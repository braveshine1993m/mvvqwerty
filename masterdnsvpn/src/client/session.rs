// MasterDnsVPN Client - Session Initialization
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dns_utils::dns_enums::{DnsRecordType, PacketType};
use crate::dns_utils::dns_packet_parser::DnsPacketParser;

use super::state::ClientState;

// ---------------------------------------------------------------------------
// Session Init (mirrors Python _session_init)
// ---------------------------------------------------------------------------

/// Perform the SESSION_INIT handshake with the server.
/// Sends a SESSION_INIT packet with a random token and compression preferences,
/// waits for SESSION_ACCEPT, and stores session_id + session_cookie.
pub async fn init_session(
    state: &Arc<ClientState>,
    sock: &Arc<tokio::net::UdpSocket>,
) -> Result<(), String> {
    // Generate a random 16-byte session token
    let session_token: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

    // Build the compression preference byte:
    //   high nibble = upload compression, low nibble = download compression
    let comp_pref: u8 = ((state.upload_compression & 0x0F) << 4)
        | (state.download_compression & 0x0F);

    // Flag byte: 0 = base32, 1 = base64 (we default to base32 = 0)
    let flag_byte: u8 = 0;

    // Payload = token + flag + compression_pref
    let mut payload = session_token.clone();
    payload.push(flag_byte);
    payload.push(comp_pref);

    let encrypted_payload = state.parser.codec_transform(&payload, true);

    let domain = &state.domains[0];
    let mtu_chars = state.upload_mtu_chars.load(Ordering::Relaxed);

    for attempt in 0..10u32 {
        if state.is_stopping() {
            return Err("Client shutting down".into());
        }

        let queries = state.parser.build_request_dns_query(
            domain,
            0, // session_id = 0 for init
            PacketType::SESSION_INIT,
            &encrypted_payload,
            mtu_chars,
            true,
            DnsRecordType::TXT,
            0, 0, 0, 0, 0, 0, 0,
        );
        if queries.is_empty() {
            return Err("Failed to build SESSION_INIT query".into());
        }

        // Get resolver
        let resolver = {
            let mut bal = state.balancer.lock().await;
            match bal.get_best_server() {
                Some(r) => r,
                None => return Err("No resolvers available".into()),
            }
        };
        let resolver_addr: SocketAddr = resolver
            .resolver
            .parse()
            .map_err(|e| format!("Invalid resolver addr: {}", e))?;

        for query in &queries {
            let _ = sock.send_to(query, resolver_addr).await;
        }

        // Wait for response
        let mut buf = vec![0u8; 65535];
        let timeout = std::time::Duration::from_secs_f64(2.0 + attempt as f64 * 0.5);
        match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Some(parsed) = DnsPacketParser::parse_dns_packet(&buf[..n]) {
                    let (hdr, data) = state.parser.extract_vpn_response(&parsed, true);
                    if let Some(h) = hdr {
                        if h.packet_type == PacketType::SESSION_ACCEPT {
                            // Parse the response: token:session_id:comp_pref:cookie
                            if let Some(result) =
                                parse_session_accept_response(&data, &session_token)
                            {
                                state
                                    .session_id
                                    .store(result.session_id as u16, Ordering::SeqCst);
                                state
                                    .session_cookie
                                    .store(result.session_cookie as u16, Ordering::SeqCst);

                                tracing::info!(
                                    "Session established: id={}, cookie={}",
                                    result.session_id,
                                    result.session_cookie
                                );

                                // Store negotiated compression types if returned
                                // (The server may override client preferences)

                                return Ok(());
                            }
                            // Fallback: use header fields directly
                            state
                                .session_id
                                .store(h.session_id as u16, Ordering::SeqCst);
                            let cookie = if !data.is_empty() {
                                data[data.len() - 1]
                            } else {
                                h.session_cookie
                            };
                            state.session_cookie.store(cookie as u16, Ordering::SeqCst);
                            return Ok(());
                        }
                    }
                }
            }
            Ok(Err(e)) => tracing::debug!("Session init recv error: {}", e),
            Err(_) => tracing::debug!("Session init attempt {} timed out", attempt + 1),
        }
    }

    Err("Session init timed out after 10 attempts".into())
}

// ---------------------------------------------------------------------------
// Parse SESSION_ACCEPT response payload
// ---------------------------------------------------------------------------

struct SessionAcceptResult {
    session_id: u8,
    session_cookie: u8,
}

fn parse_session_accept_response(
    data: &[u8],
    expected_token: &[u8],
) -> Option<SessionAcceptResult> {
    // Response format: token + ":" + session_id_str + ":" + comp_pref_byte + cookie_byte
    let decrypted = data;
    if decrypted.is_empty() {
        return None;
    }

    // Find first ":"
    let first_colon = decrypted.iter().position(|&b| b == b':')?;
    let token = &decrypted[..first_colon];

    if token != expected_token {
        return None;
    }

    let rest = &decrypted[first_colon + 1..];
    // Find second ":"
    let second_colon = rest.iter().position(|&b| b == b':')?;
    let session_id_str = std::str::from_utf8(&rest[..second_colon]).ok()?;
    let session_id: u8 = session_id_str.parse().ok()?;

    let after_second = &rest[second_colon + 1..];
    if after_second.len() < 2 {
        return None;
    }

    // comp_pref_byte (ignored for now) and cookie_byte
    let session_cookie = after_second[after_second.len() - 1];

    Some(SessionAcceptResult {
        session_id,
        session_cookie,
    })
}
