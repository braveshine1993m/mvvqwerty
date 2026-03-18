// MasterDnsVPN Server - Session Management
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use crate::dns_utils::compression::normalize_compression_type;
use crate::dns_utils::dns_enums::PacketType;

use super::state::{ClosedSessionInfo, ServerState, SessionState};
use super::stream;

// ---------------------------------------------------------------------------
// Session cookie validation (mirrors Python _expected_session_cookie)
// ---------------------------------------------------------------------------

/// Return the expected session cookie for the given packet type and session.
/// Pre-session packets (SESSION_INIT, MTU_UP/DOWN) expect cookie 0.
/// Returns None if the session does not exist.
pub async fn expected_session_cookie(
    state: &Arc<ServerState>,
    packet_type: u8,
    session_id: u8,
) -> Option<u8> {
    if state.pre_session_packet_types.contains(&packet_type) {
        return Some(0);
    }
    let sessions = state.sessions.lock().await;
    sessions
        .get(&session_id)
        .map(|s| s.session_cookie)
}

/// Decide whether to emit an ERROR_DROP for an invalid cookie.
/// (mirrors Python _should_emit_invalid_cookie_error)
pub fn should_emit_invalid_cookie_error(
    packet_type: u8,
    expected: Option<u8>,
    received: u8,
) -> bool {
    // Don't emit for pre-session or if session simply doesn't exist
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
// Create new session (mirrors Python _handle_session_init / new_session)
// ---------------------------------------------------------------------------

/// Handle SESSION_INIT: create or return existing session.
pub async fn handle_session_init(
    state: &Arc<ServerState>,
    session_id_hint: u8,
    client_addr: SocketAddr,
    payload: &[u8],
) -> Option<(u8, u8, bool)> {
    let mut sessions = state.sessions.lock().await;

    // Check if session already exists
    if let Some(existing) = sessions.get(&session_id_hint) {
        return Some((existing.session_id, existing.session_cookie, false));
    }

    // Check session limit
    if sessions.len() >= state.max_sessions {
        tracing::warn!(
            "Max sessions ({}) reached. Rejecting session init from {}",
            state.max_sessions,
            client_addr
        );
        return None;
    }

    // Parse payload: token(16) + flag(1) + comp_pref(1)
    let mut base_encode = false;
    let mut upload_comp: u8 = 0;
    let mut download_comp: u8 = 0;

    if payload.len() >= 18 {
        let decrypted = state.parser.codec_transform(payload, false);
        if decrypted.len() >= 18 {
            base_encode = decrypted[16] == 1;
            let comp_pref = decrypted[17];
            upload_comp = normalize_compression_type((comp_pref >> 4) & 0x0F);
            download_comp = normalize_compression_type(comp_pref & 0x0F);
        }
    }

    // Generate session cookie
    let session_cookie: u8 = rand::random();

    let mut session = SessionState::new(session_id_hint, session_cookie, client_addr);
    session.base_encode_responses = base_encode;
    session.upload_compression = upload_comp;
    session.download_compression = download_comp;

    sessions.insert(session_id_hint, session);

    tracing::info!(
        "New session {} created for {} (cookie={}, base_encode={})",
        session_id_hint,
        client_addr,
        session_cookie,
        base_encode
    );

    Some((session_id_hint, session_cookie, true))
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

/// Close a session: close all streams, clear queues, remove from sessions map.
pub async fn close_session(state: &Arc<ServerState>, session_id: u8) {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.remove(&session_id) {
        Some(s) => s,
        None => return,
    };

    let base_encode = session.base_encode_responses;

    // Record in recently_closed for ERROR_DROP responses
    {
        let mut closed = state.recently_closed_sessions.lock().await;
        closed.insert(
            session_id,
            ClosedSessionInfo {
                base_encode,
                closed_at: Instant::now(),
            },
        );
        // Limit size
        if closed.len() > 256 {
            let oldest = closed
                .iter()
                .min_by_key(|(_, v)| v.closed_at)
                .map(|(&k, _)| k);
            if let Some(k) = oldest {
                closed.remove(&k);
            }
        }
    }

    // Close all streams
    let stream_ids: Vec<u16> = session.streams.keys().cloned().collect();
    drop(sessions);

    for sid in stream_ids {
        stream::close_stream(state, session_id, sid, "Session closing", true, false).await;
    }

    tracing::info!("Session {} closed", session_id);
}

// ---------------------------------------------------------------------------
// Session cleanup loop (mirrors Python _session_cleanup_loop)
// ---------------------------------------------------------------------------

/// Periodically check for idle sessions and close them.
pub async fn session_cleanup_loop(state: &Arc<ServerState>) {
    while !state.is_stopping() {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

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
            tracing::info!(
                "Session {} expired after {:.0}s inactivity",
                session_id,
                state.session_timeout_secs
            );
            close_session(state, session_id).await;
        }

        // Clean up old recently_closed_sessions entries
        {
            let mut closed = state.recently_closed_sessions.lock().await;
            let old: Vec<u8> = closed
                .iter()
                .filter(|(_, v)| now.duration_since(v.closed_at).as_secs_f64() > 300.0)
                .map(|(&k, _)| k)
                .collect();
            for k in old {
                closed.remove(&k);
            }
        }
    }
}
