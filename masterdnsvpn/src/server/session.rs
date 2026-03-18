// MasterDnsVPN Server - Session Management
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;
use std::time::Instant;

use crate::dns_utils::compression::{get_compression_name, normalize_compression_type};
use crate::dns_utils::dns_enums::PacketType;

use super::state::{ClosedSessionInfo, ServerState, SessionState};
use super::stream;

// ---------------------------------------------------------------------------
// Session cookie validation (mirrors Python _expected_session_cookie)
// ---------------------------------------------------------------------------

/// Return the expected session cookie for the given packet type and session.
/// Pre-session packets (SESSION_INIT, MTU_UP/DOWN) expect cookie 0.
/// Also checks recently_closed_sessions. Returns None if unknown session.
pub async fn expected_session_cookie(
    state: &Arc<ServerState>,
    packet_type: u8,
    session_id: u8,
) -> Option<u8> {
    if state.pre_session_packet_types.contains(&packet_type) {
        return Some(0);
    }

    // Check active sessions
    {
        let sessions = state.sessions.lock().await;
        if let Some(s) = sessions.get(&session_id) {
            return Some(s.session_cookie);
        }
    }

    // Check recently closed sessions (mirrors Python)
    {
        let closed = state.recently_closed_sessions.lock().await;
        if let Some(info) = closed.get(&session_id) {
            return Some(info.session_cookie);
        }
    }

    None
}

/// Decide whether to emit an ERROR_DROP for an invalid cookie.
/// (mirrors Python _should_emit_invalid_cookie_error)
pub fn should_emit_invalid_cookie_error(
    packet_type: u8,
    expected: Option<u8>,
    _received: u8,
) -> bool {
    if expected.is_none() {
        return false;
    }
    if packet_type == PacketType::SESSION_INIT
        || packet_type == PacketType::MTU_UP_REQ
        || packet_type == PacketType::MTU_DOWN_REQ
    {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Compression validation (mirrors Python _resolve_session_compression_types)
// ---------------------------------------------------------------------------

fn resolve_session_compression_types(
    state: &ServerState,
    requested_upload: u8,
    requested_download: u8,
) -> (u8, u8) {
    let mut upload = requested_upload;
    let mut download = requested_download;

    if !state
        .supported_upload_compression_types
        .contains(&upload)
    {
        tracing::warn!(
            "Client requested upload compression '{}' which is not allowed by server policy. Falling back to OFF.",
            get_compression_name(upload)
        );
        upload = 0; // OFF
    }

    if !state
        .supported_download_compression_types
        .contains(&download)
    {
        tracing::warn!(
            "Client requested download compression '{}' which is not allowed by server policy. Falling back to OFF.",
            get_compression_name(download)
        );
        download = 0; // OFF
    }

    (upload, download)
}

// ---------------------------------------------------------------------------
// Create new session (mirrors Python new_session)
// ---------------------------------------------------------------------------

async fn new_session(
    state: &Arc<ServerState>,
    base_encode: bool,
    client_token: Vec<u8>,
    upload_comp: u8,
    download_comp: u8,
) -> Option<u8> {
    let mut free_ids = state.free_session_ids.lock().await;
    if free_ids.is_empty() {
        tracing::error!(
            "All {} session slots are full!",
            state.max_sessions
        );
        return None;
    }

    let session_id = free_ids.pop_front().unwrap();
    drop(free_ids);

    let session_cookie: u8 = loop {
        let c: u8 = rand::random();
        if c != 0 {
            break c;
        }
    };

    let mut session = SessionState::new(session_id, session_cookie, "0.0.0.0:0".parse().unwrap());
    session.base_encode_responses = base_encode;
    session.upload_compression = upload_comp;
    session.download_compression = download_comp;
    session.init_token = client_token;

    let response_type = if base_encode {
        "Base-Encoded String"
    } else {
        "Bytes"
    };

    tracing::info!(
        "Created new session with ID: {}, Response Type: {}, Compression: Upload: {}, Download: {}",
        session_id,
        response_type,
        get_compression_name(upload_comp),
        get_compression_name(download_comp)
    );

    let mut sessions = state.sessions.lock().await;
    sessions.insert(session_id, session);

    Some(session_id)
}

// ---------------------------------------------------------------------------
// Handle SESSION_INIT (mirrors Python _handle_session_init exactly)
// ---------------------------------------------------------------------------

/// Handle SESSION_INIT: parse client payload, detect retransmits, create or
/// reuse session, and return the response bytes for SESSION_ACCEPT.
pub async fn handle_session_init(
    state: &Arc<ServerState>,
    labels: &str,
    request_domain: &str,
    question_packet: &[u8],
    extracted_header: &crate::dns_utils::dns_packet_parser::VpnHeaderData,
) -> Option<Vec<u8>> {
    // Extract and decrypt payload
    let client_payload = extract_session_payload(state, labels, extracted_header);
    if client_payload.len() < 17 {
        tracing::debug!(
            "Session init packet has insufficient payload length ({} bytes). Expected at least 17.",
            client_payload.len()
        );
        return None;
    }

    let payload_len = client_payload.len();
    let flag = client_payload[payload_len - 2];
    let compression_pref = client_payload[payload_len - 1];
    let client_token = client_payload[..payload_len - 2].to_vec();

    let (upload_comp, download_comp) = resolve_session_compression_types(
        state,
        normalize_compression_type((compression_pref >> 4) & 0x0F),
        normalize_compression_type(compression_pref & 0x0F),
    );

    let base_encode = flag == 1;

    // Check for retransmit: existing session created within 10s with same token
    let existing_session_id = {
        let sessions = state.sessions.lock().await;
        let now = Instant::now();
        sessions.iter().find_map(|(&sid, sess)| {
            if now.duration_since(sess.created_at).as_secs_f64() <= 10.0
                && sess.init_token == client_token
            {
                Some(sid)
            } else {
                None
            }
        })
    };

    let new_session_id = if let Some(sid) = existing_session_id {
        tracing::debug!("Retransmit detected. Reusing Session {}", sid);
        sid
    } else {
        match new_session(state, base_encode, client_token.clone(), upload_comp, download_comp)
            .await
        {
            Some(sid) => sid,
            None => {
                tracing::debug!("Failed to create new session");
                return None;
            }
        }
    };

    // Build response: token + ":" + session_id_str + ":" + comp_pref_byte + cookie_byte
    let session_cookie = {
        let sessions = state.sessions.lock().await;
        sessions
            .get(&new_session_id)
            .map(|s| s.session_cookie)
            .unwrap_or(0)
    };

    let compression_pref_byte = ((upload_comp & 0x0F) << 4) | (download_comp & 0x0F);
    let sid_str = new_session_id.to_string();

    let mut response_bytes = Vec::new();
    response_bytes.extend_from_slice(&client_token);
    response_bytes.push(b':');
    response_bytes.extend_from_slice(sid_str.as_bytes());
    response_bytes.push(b':');
    response_bytes.push(compression_pref_byte);
    response_bytes.push(session_cookie);

    Some(state.parser.generate_simple_vpn_response(
        request_domain,
        new_session_id,
        PacketType::SESSION_ACCEPT,
        &response_bytes,
        question_packet,
        base_encode,
        0, // session_cookie=0 for session init response
    ))
}

// ---------------------------------------------------------------------------
// Touch session (update last activity)
// ---------------------------------------------------------------------------

pub async fn touch_session(state: &Arc<ServerState>, session_id: u8) {
    let mut sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get_mut(&session_id) {
        session.last_activity = Instant::now();
    }
}

// ---------------------------------------------------------------------------
// Close session (mirrors Python _close_session)
// ---------------------------------------------------------------------------

/// Close a session: close all streams, clear queues, remove from sessions map,
/// and return the session ID to the free pool.
pub async fn close_session(state: &Arc<ServerState>, session_id: u8) {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.remove(&session_id) {
        Some(s) => s,
        None => return,
    };

    tracing::debug!(
        "Closing Session {} and all its streams...",
        session_id
    );

    let base_encode = session.base_encode_responses;
    let cookie = session.session_cookie;

    // Record in recently_closed for ERROR_DROP responses
    {
        let mut closed = state.recently_closed_sessions.lock().await;
        closed.insert(
            session_id,
            ClosedSessionInfo {
                base_encode,
                session_cookie: cookie,
                closed_at: Instant::now(),
            },
        );
    }

    // Close all streams
    let stream_ids: Vec<u16> = session.streams.keys().cloned().collect();
    drop(sessions);

    for sid in stream_ids {
        stream::close_stream(state, session_id, sid, "Session Closing", true, false).await;
    }

    // Return session ID to free pool (mirrors Python free_session_ids.appendleft)
    {
        let max = state.max_sessions.min(255) as u8;
        if session_id >= 1 && session_id <= max {
            let mut free_ids = state.free_session_ids.lock().await;
            free_ids.push_front(session_id);
        }
    }

    tracing::info!("Closed session with ID: {}", session_id);
}

// ---------------------------------------------------------------------------
// Session cleanup loop (mirrors Python _session_cleanup_loop)
// ---------------------------------------------------------------------------

/// Periodically check for idle sessions and close them.
pub async fn session_cleanup_loop(state: &Arc<ServerState>) {
    let cleanup_interval = state.session_cleanup_interval;

    while !state.is_stopping() {
        tokio::time::sleep(std::time::Duration::from_secs_f64(cleanup_interval)).await;

        if state.is_stopping() {
            break;
        }

        let now = Instant::now();

        // Find expired sessions
        let expired: Vec<u8> = {
            let sessions = state.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| {
                    now.duration_since(s.last_activity).as_secs_f64()
                        > state.session_timeout_secs
                })
                .map(|(&id, _)| id)
                .collect()
        };

        for session_id in expired {
            tracing::debug!(
                "Closed inactive session ID: {}",
                session_id
            );
            close_session(state, session_id).await;
        }

        // Clean up old recently_closed_sessions entries (600s = 10 minutes)
        {
            let mut closed = state.recently_closed_sessions.lock().await;
            let old: Vec<u8> = closed
                .iter()
                .filter(|(_, v)| now.duration_since(v.closed_at).as_secs_f64() > 600.0)
                .map(|(&k, _)| k)
                .collect();
            for k in old {
                closed.remove(&k);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: extract payload from labels
// ---------------------------------------------------------------------------

fn extract_session_payload(
    state: &ServerState,
    labels: &str,
    _extracted_header: &crate::dns_utils::dns_packet_parser::VpnHeaderData,
) -> Vec<u8> {
    let raw = state.parser.extract_vpn_data_from_labels(labels);
    if raw.is_empty() {
        return vec![];
    }
    state.parser.codec_transform(&raw, false)
}
