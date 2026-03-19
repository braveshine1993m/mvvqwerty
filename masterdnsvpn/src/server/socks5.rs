// MasterDnsVPN Server - SOCKS5 Target Connection
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;

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

/// Connect to the target host (directly or via external SOCKS5), set up ARQ,
/// and send SOCKS5_SYN_ACK.
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

    let mut acquired_connect_slot = false;

    let result: Result<(), (u8, String)> = async {
        // Acquire connect semaphore slot with retry loop (mirrors Python)
        loop {
            if state.is_stopping() {
                return Err((PacketType::SOCKS5_UPSTREAM_UNAVAILABLE, "Server stopping".into()));
            }
            // Check stream status
            {
                let sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get(&session_id) {
                    if let Some(sd) = session.streams.get(&stream_id) {
                        if sd.status == "CLOSING" || sd.status == "TIME_WAIT" {
                            return Ok(());
                        }
                    }
                }
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                state.socks_connect_semaphore.acquire(),
            )
            .await
            {
                Ok(Ok(permit)) => {
                    acquired_connect_slot = true;
                    // Update last_activity
                    {
                        let mut sessions = state.sessions.lock().await;
                        if let Some(session) = sessions.get_mut(&session_id) {
                            if let Some(sd) = session.streams.get_mut(&stream_id) {
                                sd.last_activity = std::time::Instant::now();
                            }
                        }
                    }
                    // We need to forget the permit since we track it manually
                    permit.forget();
                    break;
                }
                Ok(Err(_)) => {
                    return Err((PacketType::SOCKS5_UPSTREAM_UNAVAILABLE, "Semaphore closed".into()));
                }
                Err(_) => {
                    // Timeout - update last_activity and retry
                    let mut sessions = state.sessions.lock().await;
                    if let Some(session) = sessions.get_mut(&session_id) {
                        if let Some(sd) = session.streams.get_mut(&stream_id) {
                            sd.last_activity = std::time::Instant::now();
                        }
                    }
                    continue;
                }
            }
        }

        if !acquired_connect_slot {
            return Ok(());
        }

        // Connect and handshake
        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            connect_and_handshake(state, &target, stream_id, &payload),
        )
        .await;

        // Always release semaphore after connect attempt
        state.socks_connect_semaphore.add_permits(1);
        acquired_connect_slot = false;

        let tcp_stream = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err((map_socks5_err_string(&e), format!("SOCKS target unreachable: {}", e)));
            }
            Err(_) => {
                return Err((PacketType::SOCKS5_TTL_EXPIRED, "Connection timeout".into()));
            }
        };

        // Check stream wasn't closed during connection
        {
            let sessions = state.sessions.lock().await;
            if let Some(session) = sessions.get(&session_id) {
                if let Some(sd) = session.streams.get(&stream_id) {
                    if sd.status == "CLOSING" || sd.status == "TIME_WAIT" {
                        drop(sessions);
                        drop(tcp_stream);
                        tracing::debug!(
                            "Stream {} was closed during connection phase. Aborting.",
                            stream_id
                        );
                        return Ok(());
                    }
                }
            }
        }

        let (reader, writer) = tcp_stream.into_split();

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
            vec![],
        );

        // Store ARQ, update status, cache SYN_ACK
        {
            let mut sessions = state.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                if let Some(sd) = session.streams.get_mut(&stream_id) {
                    sd.arq = Some(arq);
                    sd.status = "CONNECTED".to_string();
                    sd.target_addr = target.addr_display.clone();
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

        // Also cache fragment response if multi-fragment
        if let Some(frag_id) = response_fragment_id {
            let mut sessions = state.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                if let Some(sd) = session.streams.get_mut(&stream_id) {
                    sd.syn_responses.insert(
                        format!("socks_frag_{}", frag_id),
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

        Ok(())
    }
    .await;

    if let Err((err_ptype, reason)) = result {
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
            reason
        );
        stream::close_stream(
            state,
            session_id,
            stream_id,
            &reason,
            true,
            false,
        )
        .await;
    }

    if acquired_connect_slot {
        state.socks_connect_semaphore.add_permits(1);
    }
}

/// Connect directly or via external SOCKS5 proxy (mirrors Python _connect_and_handshake)
async fn connect_and_handshake(
    state: &Arc<ServerState>,
    target: &Socks5Target,
    stream_id: u16,
    raw_payload: &[u8],
) -> Result<TcpStream, String> {
    if state.use_external_socks5 {
        tracing::debug!(
            "Forwarding to External SOCKS5 {}:{} for target {} (Stream {})",
            state.forward_ip,
            state.forward_port,
            target.addr_display,
            stream_id
        );

        let stream = TcpStream::connect(format!("{}:{}", state.forward_ip, state.forward_port))
            .await
            .map_err(|e| format!("Failed to connect to external SOCKS5: {}", e))?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut reader, mut writer) = stream.into_split();

        // SOCKS5 greeting
        if state.socks5_auth {
            writer.write_all(&[0x05, 0x01, 0x02]).await.map_err(|e| e.to_string())?;
        } else {
            writer.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
        }

        let mut greeting_res = [0u8; 2];
        reader.read_exact(&mut greeting_res).await.map_err(|e| e.to_string())?;

        if greeting_res[0] != 0x05 {
            return Err("Upstream proxy is not a valid SOCKS5 server".into());
        }

        if state.socks5_auth && greeting_res[1] == 0x02 {
            let u_bytes = state.socks5_user.as_bytes();
            let p_bytes = state.socks5_pass.as_bytes();
            let mut auth_req = vec![0x01, u_bytes.len() as u8];
            auth_req.extend_from_slice(u_bytes);
            auth_req.push(p_bytes.len() as u8);
            auth_req.extend_from_slice(p_bytes);
            writer.write_all(&auth_req).await.map_err(|e| e.to_string())?;

            let mut auth_res = [0u8; 2];
            reader.read_exact(&mut auth_res).await.map_err(|e| e.to_string())?;
            if auth_res[1] != 0x00 {
                return Err("External SOCKS5 Authentication failed!".into());
            }
        } else if greeting_res[1] != 0x00 {
            return Err("External SOCKS5 requires unsupported authentication method".into());
        }

        // SOCKS5 connect request
        let mut conn_req = vec![0x05, 0x01, 0x00];
        conn_req.extend_from_slice(raw_payload);
        writer.write_all(&conn_req).await.map_err(|e| e.to_string())?;

        let mut resp_header = [0u8; 4];
        reader.read_exact(&mut resp_header).await.map_err(|e| e.to_string())?;

        if resp_header[0] != 0x05 || resp_header[1] != 0x00 {
            return Err(format!(
                "External SOCKS5 failed to connect to target. Code: {}",
                resp_header[1]
            ));
        }

        // Skip bound address
        let bnd_atyp = resp_header[3];
        match bnd_atyp {
            0x01 => {
                let mut skip = [0u8; 6];
                reader.read_exact(&mut skip).await.map_err(|e| e.to_string())?;
            }
            0x03 => {
                let mut dlen = [0u8; 1];
                reader.read_exact(&mut dlen).await.map_err(|e| e.to_string())?;
                let mut skip = vec![0u8; dlen[0] as usize + 2];
                reader.read_exact(&mut skip).await.map_err(|e| e.to_string())?;
            }
            0x04 => {
                let mut skip = [0u8; 18];
                reader.read_exact(&mut skip).await.map_err(|e| e.to_string())?;
            }
            _ => {}
        }

        Ok(reader.reunite(writer).expect("reunite should work"))
    } else {
        tracing::debug!(
            "SOCKS5 Fast-Connecting directly to {} for stream {}",
            target.addr_display,
            stream_id
        );
        TcpStream::connect(format!("{}:{}", target.host, target.port))
            .await
            .map_err(|e| e.to_string())
    }
}

/// Map a string error to SOCKS5 error packet type
fn map_socks5_err_string(err: &str) -> u8 {
    let lower = err.to_lowercase();
    if lower.contains("connection refused") {
        PacketType::SOCKS5_CONNECTION_REFUSED
    } else if lower.contains("network unreachable") || lower.contains("network is unreachable") {
        PacketType::SOCKS5_NETWORK_UNREACHABLE
    } else if lower.contains("host unreachable") || lower.contains("no route to host") {
        PacketType::SOCKS5_HOST_UNREACHABLE
    } else if lower.contains("timed out") || lower.contains("deadline") {
        PacketType::SOCKS5_TTL_EXPIRED
    } else if lower.contains("authentication failed") {
        PacketType::SOCKS5_AUTH_FAILED
    } else {
        PacketType::SOCKS5_CONNECT_FAIL
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
    _fragment_id: Option<u8>,
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
    _sn: u16,
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
            // Send fragment ACK for this intermediate fragment (mirrors Python)
            let fragment_payload = vec![
                b'S',
                b'F',
                b'R',
                frag_id,
                total_frags,
                sd.socks_chunks.len() as u8,
            ];
            drop(sessions);
            queue::enqueue_packet(
                state,
                session_id,
                2,
                stream_id,
                0,
                PacketType::SOCKS5_SYN_ACK,
                fragment_payload,
            )
            .await;
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
