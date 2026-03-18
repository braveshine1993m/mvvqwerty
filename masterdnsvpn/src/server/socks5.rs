// MasterDnsVPN Server - SOCKS5 Target Connection
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns_utils::dns_enums::PacketType;

use super::queue;
use super::state::{CachedResponse, ServerState, ServerStreamData};
use super::stream;

// ---------------------------------------------------------------------------
// SOCKS5 error mapping (mirrors Python _map_socks5_exception_to_packet)
// ---------------------------------------------------------------------------

/// Map a connection error to the appropriate SOCKS5 error packet type.
pub fn map_socks5_exception_to_packet(err: &std::io::Error) -> u8 {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionRefused => PacketType::SOCKS5_CONNECTION_REFUSED,
        ErrorKind::ConnectionReset => PacketType::SOCKS5_CONNECTION_REFUSED,
        ErrorKind::TimedOut => PacketType::SOCKS5_TTL_EXPIRED,
        ErrorKind::AddrNotAvailable => PacketType::SOCKS5_HOST_UNREACHABLE,
        _ => {
            let msg = err.to_string().to_lowercase();
            if msg.contains("network unreachable") || msg.contains("network is unreachable") {
                PacketType::SOCKS5_NETWORK_UNREACHABLE
            } else if msg.contains("host unreachable") || msg.contains("no route to host") {
                PacketType::SOCKS5_HOST_UNREACHABLE
            } else if msg.contains("connection refused") {
                PacketType::SOCKS5_CONNECTION_REFUSED
            } else if msg.contains("timed out") || msg.contains("deadline") {
                PacketType::SOCKS5_TTL_EXPIRED
            } else {
                PacketType::SOCKS5_CONNECT_FAIL
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parse SOCKS5 target address from payload
// (mirrors Python _process_socks5_target parsing)
// ---------------------------------------------------------------------------

pub struct Socks5Target {
    pub host: String,
    pub port: u16,
    pub addr_display: String,
}

/// Parse the target address from the SOCKS5_SYN payload: [ATYP][ADDR][PORT]
pub fn parse_socks5_target(payload: &[u8]) -> Option<Socks5Target> {
    if payload.is_empty() {
        return None;
    }

    let atyp = payload[0];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            if payload.len() < 7 {
                return None;
            }
            let host = format!(
                "{}.{}.{}.{}",
                payload[1], payload[2], payload[3], payload[4]
            );
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            Some(Socks5Target {
                addr_display: format!("{}:{}", host, port),
                host,
                port,
            })
        }
        0x03 => {
            // Domain: 1 byte len + N bytes + 2 bytes port
            if payload.len() < 4 {
                return None;
            }
            let dlen = payload[1] as usize;
            if payload.len() < 2 + dlen + 2 {
                return None;
            }
            let domain = String::from_utf8_lossy(&payload[2..2 + dlen]).to_string();
            let port = u16::from_be_bytes([payload[2 + dlen], payload[3 + dlen]]);
            Some(Socks5Target {
                addr_display: format!("{}:{}", domain, port),
                host: domain,
                port,
            })
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            if payload.len() < 19 {
                return None;
            }
            let mut segments = Vec::with_capacity(8);
            for i in 0..8 {
                let seg = u16::from_be_bytes([payload[1 + i * 2], payload[2 + i * 2]]);
                segments.push(format!("{:x}", seg));
            }
            let host = segments.join(":");
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            Some(Socks5Target {
                addr_display: format!("[{}]:{}", host, port),
                host,
                port,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Process SOCKS5 target connection (mirrors Python _process_socks5_target)
// ---------------------------------------------------------------------------

/// Connect to the target host, set up ARQ, and send SOCKS5_SYN_ACK.
pub async fn process_socks5_target(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    payload: Vec<u8>,
    response_fragment_id: Option<u8>,
) {
    let target = match parse_socks5_target(&payload) {
        Some(t) => t,
        None => {
            tracing::debug!(
                "Invalid SOCKS5 target payload for stream {} in session {}",
                stream_id,
                session_id
            );
            send_socks5_error_packet(
                state,
                session_id,
                stream_id,
                PacketType::SOCKS5_CONNECT_FAIL,
                response_fragment_id,
            )
            .await;
            stream::close_stream(
                state,
                session_id,
                stream_id,
                "Invalid SOCKS5 target",
                true,
                false,
            )
            .await;
            return;
        }
    };

    tracing::debug!(
        "SOCKS5 connecting to {} for stream {} session {}",
        target.addr_display,
        stream_id,
        session_id
    );

    // Acquire connect semaphore slot
    let acquired = state.socks_connect_semaphore.try_acquire();
    if acquired.is_err() {
        tracing::debug!("SOCKS5 connect semaphore full, rejecting stream {}", stream_id);
        send_socks5_error_packet(
            state,
            session_id,
            stream_id,
            PacketType::SOCKS5_UPSTREAM_UNAVAILABLE,
            response_fragment_id,
        )
        .await;
        stream::close_stream(
            state,
            session_id,
            stream_id,
            "Connect semaphore full",
            true,
            false,
        )
        .await;
        return;
    }
    let _permit = acquired.unwrap();

    // Connect to the target
    let connect_timeout = std::time::Duration::from_secs_f64(state.socks_handshake_timeout);
    let tcp_result = tokio::time::timeout(
        connect_timeout,
        TcpStream::connect(format!("{}:{}", target.host, target.port)),
    )
    .await;

    match tcp_result {
        Ok(Ok(tcp_stream)) => {
            let (reader, writer) = tcp_stream.into_split();

            // Get download MTU from session
            let mtu = {
                let sessions = state.sessions.lock().await;
                sessions
                    .get(&session_id)
                    .map(|s| s.download_mtu)
                    .unwrap_or(50)
            };

            let arq = stream::create_server_arq_stream(
                state,
                session_id,
                stream_id,
                reader,
                writer,
                mtu,
                vec![], // no initial data for server side
            );

            // ARQ rcv_nxt starts at 0 for first STREAM_DATA
            // (SOCKS5_SYN is handled on control-plane)

            // Store ARQ and update stream status
            {
                let mut sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(sd) = session.streams.get_mut(&stream_id) {
                        sd.arq = Some(arq);
                        sd.status = "CONNECTED".to_string();
                        sd.target_addr = target.addr_display.clone();
                    }
                }
            }

            // Send SOCKS5_SYN_ACK
            queue::enqueue_packet(
                state,
                session_id,
                2,
                stream_id,
                0,
                PacketType::SOCKS5_SYN_ACK,
                vec![],
            )
            .await;

            // Cache the SYN_ACK response for retransmission
            {
                let mut sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(sd) = session.streams.get_mut(&stream_id) {
                        sd.syn_responses.insert(
                            "socks".to_string(),
                            CachedResponse {
                                packet_type: PacketType::SOCKS5_SYN_ACK,
                                payload: vec![],
                                priority: 2,
                                sequence_num: 0,
                            },
                        );
                    }
                }
            }

            tracing::debug!(
                "SOCKS5 connected to {} for stream {} session {}",
                target.addr_display,
                stream_id,
                session_id
            );
        }
        Ok(Err(e)) => {
            let err_ptype = map_socks5_exception_to_packet(&e);
            send_socks5_error_packet(
                state,
                session_id,
                stream_id,
                err_ptype,
                response_fragment_id,
            )
            .await;
            tracing::debug!(
                "SOCKS5 connection failed for stream {} session {}: {}",
                stream_id,
                session_id,
                e
            );
            stream::close_stream(
                state,
                session_id,
                stream_id,
                &format!("SOCKS target unreachable: {}", e),
                true,
                false,
            )
            .await;
        }
        Err(_) => {
            send_socks5_error_packet(
                state,
                session_id,
                stream_id,
                PacketType::SOCKS5_TTL_EXPIRED,
                response_fragment_id,
            )
            .await;
            tracing::debug!(
                "SOCKS5 connection timed out for stream {} session {}",
                stream_id,
                session_id
            );
            stream::close_stream(
                state,
                session_id,
                stream_id,
                "SOCKS connect timeout",
                true,
                false,
            )
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Send SOCKS5 error packet (mirrors Python _send_socks5_error_packet)
// ---------------------------------------------------------------------------

async fn send_socks5_error_packet(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    error_packet_type: u8,
    fragment_id: Option<u8>,
) {
    queue::enqueue_packet(
        state,
        session_id,
        0,
        stream_id,
        0,
        error_packet_type,
        vec![],
    )
    .await;
}

// ---------------------------------------------------------------------------
// Handle SOCKS5_SYN (mirrors Python _handle_socks5_syn_packet)
// ---------------------------------------------------------------------------

/// Handle a SOCKS5_SYN packet from the client. This may be a single-fragment
/// or multi-fragment SYN. When all fragments arrive, spawn the connection task.
pub async fn handle_socks5_syn(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
    payload: Vec<u8>,
    fragment_id: Option<u16>,
    total_fragments: Option<u16>,
) {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => return,
    };

    // Check if stream is in closed_streams
    if session.closed_streams.contains_key(&stream_id) {
        drop(sessions);
        queue::enqueue_packet(
            state,
            session_id,
            1,
            stream_id,
            0,
            PacketType::STREAM_RST,
            vec![],
        )
        .await;
        return;
    }

    // Get or create stream data
    if !session.streams.contains_key(&stream_id) {
        let mut sd = ServerStreamData::new(stream_id);
        sd.status = "SOCKS_HANDSHAKE".to_string();
        session.streams.insert(stream_id, sd);
    }

    let sd = session.streams.get_mut(&stream_id).unwrap();

    // Already connected? Re-send cached response
    if sd.status == "CONNECTED" || sd.arq.is_some() {
        if let Some(cached) = sd.syn_responses.get("socks") {
            let cached_clone = cached.clone();
            drop(sessions);
            queue::enqueue_packet(
                state,
                session_id,
                cached_clone.priority,
                stream_id,
                cached_clone.sequence_num,
                cached_clone.packet_type,
                cached_clone.payload,
            )
            .await;
        }
        return;
    }

    // Handle fragmented SOCKS5_SYN
    let total_frags = total_fragments.unwrap_or(1) as u8;
    let frag_id = fragment_id.unwrap_or(0) as u8;

    if total_frags > 1 {
        sd.socks_expected_frags = Some(total_frags);
        sd.socks_chunks.insert(frag_id, payload.clone());

        // Check if we have all fragments
        if sd.socks_chunks.len() < total_frags as usize {
            drop(sessions);
            return;
        }

        // Reassemble
        let mut assembled = Vec::new();
        for i in 0..total_frags {
            if let Some(chunk) = sd.socks_chunks.get(&i) {
                assembled.extend_from_slice(chunk);
            } else {
                // Missing fragment
                drop(sessions);
                return;
            }
        }
        sd.socks_chunks.clear();
        sd.status = "SOCKS_CONNECTING".to_string();
        drop(sessions);

        // Spawn connection task
        let state_clone = state.clone();
        tokio::spawn(async move {
            process_socks5_target(&state_clone, session_id, stream_id, assembled, Some(frag_id))
                .await;
        });
    } else {
        sd.status = "SOCKS_CONNECTING".to_string();
        drop(sessions);

        // Single fragment — spawn connection immediately
        let state_clone = state.clone();
        tokio::spawn(async move {
            process_socks5_target(&state_clone, session_id, stream_id, payload, None).await;
        });
    }
}
