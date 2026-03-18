// MasterDnsVPN Client - Session Initialization
// Mirrors Python _init_session exactly
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dns_utils::compression::{get_compression_name, normalize_compression_type};
use crate::dns_utils::dns_enums::{DnsRecordType, PacketType};
use crate::dns_utils::dns_packet_parser::DnsPacketParser;

use super::state::ClientState;

// ---------------------------------------------------------------------------
// Helper: send DNS query and wait for response
// ---------------------------------------------------------------------------
async fn send_and_receive_dns(
    query_data: &[u8],
    resolver_addr: SocketAddr,
    timeout_secs: f64,
) -> Option<Vec<u8>> {
    let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };

    if sock.send_to(query_data, resolver_addr).await.is_err() {
        return None;
    }

    let mut buf = vec![0u8; 65535];
    let timeout = std::time::Duration::from_secs_f64(timeout_secs);
    match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Session Init (mirrors Python _init_session exactly)
// ---------------------------------------------------------------------------

pub async fn init_session(
    state: &Arc<ClientState>,
    max_attempts: u32,
) -> Result<(), String> {
    tracing::info!("Initializing session ...");

    // Python: init_token = os.urandom(8).hex().encode("ascii")
    let init_token_bytes: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
    let init_token = hex::encode(&init_token_bytes);
    let init_token_ascii = init_token.as_bytes();

    // Python: flag_byte = b"\x01" if self.base_encode_responses else b"\x00"
    let flag_byte: u8 = if state.base_encode_responses { 0x01 } else { 0x00 };

    // Python: compression_pref_byte = ((upload_comp & 0x0F) << 4) | (download_comp & 0x0F)
    let compression_pref_byte: u8 = ((state.upload_compression & 0x0F) << 4)
        | (state.download_compression & 0x0F);

    // Python: payload = init_token + flag_byte + compression_pref_byte
    let mut payload = Vec::with_capacity(init_token_ascii.len() + 2);
    payload.extend_from_slice(init_token_ascii);
    payload.push(flag_byte);
    payload.push(compression_pref_byte);

    let encrypted_token = state.parser.codec_transform(&payload, true);

    let mtu_chars = state.synced_upload_mtu_chars.load(Ordering::Relaxed);

    for overall_attempt in 0..max_attempts {
        if state.is_stopping() {
            return Err("Client shutting down".into());
        }

        // Get best server for this attempt (Python: self.balancer.get_best_server())
        let (domain, resolver_addr, resolver_label) = {
            let mut bal = state.balancer.lock().await;
            match bal.get_best_server() {
                Some(r) => {
                    let addr: SocketAddr = match r.resolver.parse() {
                        Ok(a) => a,
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            continue;
                        }
                    };
                    (r.domain.clone(), addr, r.resolver.clone())
                }
                None => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            }
        };

        let dns_queries = state.parser.build_request_dns_query(
            &domain,
            0, // session_id = 0 for init
            PacketType::SESSION_INIT,
            &encrypted_token,
            mtu_chars,
            true,
            DnsRecordType::TXT,
            0, 0, 0, 0, 0, 0, 0,
        );

        if dns_queries.is_empty() {
            tracing::error!(
                "Failed to build session init DNS query via {} for {}, Retrying...",
                resolver_label,
                domain
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }

        for inner_attempt in 0..3u32 {
            if state.is_stopping() {
                return Err("Client shutting down".into());
            }

            let response = send_and_receive_dns(
                &dns_queries[0],
                resolver_addr,
                2.0, // Python: self.timeout
            )
            .await;

            if let Some(resp) = response {
                if let Some(parsed) = DnsPacketParser::parse_dns_packet(&resp) {
                    let (hdr, data) =
                        state.parser.extract_vpn_response(&parsed, state.base_encode_responses);
                    if let Some(h) = hdr {
                        if h.packet_type == PacketType::SESSION_ACCEPT {
                            match parse_session_accept(state, &data, &init_token) {
                                Ok(()) => return Ok(()),
                                Err(e) => {
                                    tracing::error!("Session parse error: {}", e);
                                }
                            }
                        }
                    }
                }
            }

            if inner_attempt < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        tracing::warn!(
            "Session init failed via {} for {}. Retrying overall process...",
            resolver_label,
            domain
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    Err("Failed to initialize session with the server.".into())
}

// ---------------------------------------------------------------------------
// Parse SESSION_ACCEPT response (mirrors Python _init_session parsing exactly)
// ---------------------------------------------------------------------------
fn parse_session_accept(
    state: &ClientState,
    returned_data: &[u8],
    init_token: &str,
) -> Result<(), String> {
    if returned_data.is_empty() {
        return Err("Empty response data".into());
    }

    // Python: parts = bytes(returned_data).split(b":", 2)
    let parts: Vec<&[u8]> = returned_data.splitn(3, |&b| b == b':').collect();
    if parts.len() < 2 {
        return Err("Invalid response format: less than 2 parts".into());
    }

    // Python: received_token = parts[0].decode("ascii")
    let received_token = std::str::from_utf8(parts[0])
        .map_err(|e| format!("Token decode error: {}", e))?;

    if received_token != init_token {
        tracing::warn!("Token mismatch! Ignoring old session response.");
        return Err("Token mismatch".into());
    }

    // Python: raw_sid = bytes(parts[1])
    let raw_sid = parts[1];

    let mut compression_pref: u8 = 0;
    let mut session_cookie: u8 = 0;

    if parts.len() >= 3 {
        let raw_comp = parts[2];
        if !raw_comp.is_empty() {
            compression_pref = raw_comp[0];
            if raw_comp.len() >= 2 {
                session_cookie = raw_comp[1];
            }
        }
    }

    // Negotiate upload compression
    let new_upload = normalize_compression_type((compression_pref >> 4) & 0x0F);
    if new_upload != state.upload_compression {
        tracing::warn!(
            "Server requested upload compression change. New Upload Compression: {}",
            get_compression_name(new_upload)
        );
    }

    // Negotiate download compression
    let new_download = normalize_compression_type(compression_pref & 0x0F);
    if new_download != state.download_compression {
        tracing::warn!(
            "Server requested download compression change. New Download Compression: {}",
            get_compression_name(new_download)
        );
    }

    // Parse session ID
    let sid_txt = std::str::from_utf8(raw_sid)
        .unwrap_or("")
        .trim()
        .trim_matches('\x00');

    let session_id: u8 = if let Ok(id) = sid_txt.parse::<u8>() {
        id
    } else if raw_sid.len() == 1 {
        raw_sid[0]
    } else {
        return Err(format!("Invalid session id payload: {:?}", raw_sid));
    };

    state
        .session_id
        .store(session_id as u16, Ordering::SeqCst);
    state
        .session_cookie
        .store(session_cookie as u16, Ordering::SeqCst);

    tracing::info!(
        "Validated Session ID: {}, Upload Compression: {}, Download Compression: {}",
        session_id,
        get_compression_name(new_upload),
        get_compression_name(new_download)
    );

    Ok(())
}

/// Check if a received session cookie is valid for this packet type.
/// Pre-session packet types (SESSION_ACCEPT, MTU_*, ERROR_DROP) expect cookie=0.
pub fn _should_emit_invalid_cookie_error(
    _received: u8,
) -> bool {
    false
}
