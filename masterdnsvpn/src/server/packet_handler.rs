// MasterDnsVPN Server - Packet Dispatch & Stream Handlers
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;
use std::time::Instant;

use crate::dns_utils::compression::{compress_payload, try_decompress_payload, CompressionType};
use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::{DnsPacketParser, VpnHeaderData};

use super::config::PACKED_CONTROL_BLOCK_SIZE;
use super::mtu;
use super::queue;
use super::session;
use super::socks5;
use super::state::ServerState;
use super::stream;

// ---------------------------------------------------------------------------
// Main VPN packet handler (mirrors Python handle_vpn_packet)
// ---------------------------------------------------------------------------

/// Handle a validated VPN packet and return an optional DNS response.
pub async fn handle_vpn_packet(
    state: &Arc<ServerState>,
    packet_type: u8,
    session_id: u8,
    data: &[u8],
    labels: &str,
    request_domain: &str,
    addr: std::net::SocketAddr,
    extracted_header: &VpnHeaderData,
) -> Option<Vec<u8>> {
    // Pre-session packets
    if state.pre_session_packet_types.contains(&packet_type) {
        return handle_pre_session_packet(
            state,
            packet_type,
            session_id,
            data,
            labels,
            request_domain,
            addr,
            extracted_header,
        )
        .await;
    }

    // Touch session activity
    session::touch_session(state, session_id).await;

    // Process session packet and get piggybacked response
    process_session_packet(state, packet_type, session_id, data, labels, extracted_header, addr)
        .await;

    // Build response with piggybacked data from the session's queues
    build_piggybacked_response(state, session_id, request_domain, data, extracted_header).await
}

// ---------------------------------------------------------------------------
// Pre-session packet handling (SESSION_INIT, MTU_UP, MTU_DOWN)
// ---------------------------------------------------------------------------

async fn handle_pre_session_packet(
    state: &Arc<ServerState>,
    packet_type: u8,
    session_id: u8,
    data: &[u8],
    labels: &str,
    request_domain: &str,
    addr: std::net::SocketAddr,
    extracted_header: &VpnHeaderData,
) -> Option<Vec<u8>> {
    match packet_type {
        PacketType::SESSION_INIT => {
            // Extract payload from labels
            let payload = state.parser.extract_vpn_data_from_labels(labels);

            let result = session::handle_session_init(state, session_id, addr, &payload).await?;
            let (sid, cookie, _is_new) = result;

            // Build SESSION_ACCEPT response
            let response_data = vec![cookie];
            Some(state.parser.generate_simple_vpn_response(
                request_domain,
                sid,
                PacketType::SESSION_ACCEPT,
                &response_data,
                data,
                false,
                0,
            ))
        }
        PacketType::MTU_UP_REQ => {
            mtu::handle_mtu_up(state, session_id, labels, request_domain, data).await
        }
        PacketType::MTU_DOWN_REQ => {
            mtu::handle_mtu_down(
                state,
                session_id,
                labels,
                request_domain,
                data,
                extracted_header,
            )
            .await
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Session packet processing (mirrors Python _process_session_packet)
// ---------------------------------------------------------------------------

async fn process_session_packet(
    state: &Arc<ServerState>,
    packet_type: u8,
    session_id: u8,
    data: &[u8],
    labels: &str,
    extracted_header: &VpnHeaderData,
    addr: std::net::SocketAddr,
) {
    let stream_id = extracted_header.stream_id.unwrap_or(0);
    let sn = extracted_header.sequence_num.unwrap_or(0);
    let fragment_id = extracted_header.fragment_id;
    let total_fragments = extracted_header.total_fragments;

    // Extract and decrypt payload from DNS labels
    let raw_label_data = state.parser.extract_vpn_data_from_labels(labels);
    let payload = if !raw_label_data.is_empty() {
        let decrypted = state.parser.codec_transform(&raw_label_data, false);
        // Decompress if needed
        let comp_type = extracted_header
            .compression_type
            .unwrap_or(CompressionType::OFF);
        if !decrypted.is_empty() && comp_type != CompressionType::OFF {
            let (decompressed, ok) = try_decompress_payload(&decrypted, comp_type);
            if ok {
                decompressed
            } else {
                decrypted
            }
        } else {
            decrypted
        }
    } else {
        vec![]
    };

    match packet_type {
        PacketType::SET_MTU_REQ => {
            // Handled separately (returns direct response)
        }
        PacketType::PING => {
            handle_ping(state, session_id, sn).await;
        }
        PacketType::STREAM_SYN => {
            handle_stream_syn(state, session_id, stream_id, sn).await;
        }
        PacketType::SOCKS5_SYN => {
            socks5::handle_socks5_syn(
                state,
                session_id,
                stream_id,
                sn,
                payload,
                fragment_id.map(|f| f as u16),
                total_fragments.map(|f| f as u16),
            )
            .await;
        }
        PacketType::STREAM_DATA | PacketType::STREAM_RESEND => {
            handle_stream_data(state, session_id, stream_id, sn, payload).await;
        }
        PacketType::STREAM_DATA_ACK => {
            handle_stream_data_ack(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_FIN => {
            handle_stream_fin(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_FIN_ACK => {
            handle_stream_fin_ack(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_RST => {
            handle_stream_rst(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_RST_ACK => {
            handle_stream_rst_ack(state, session_id, stream_id, sn).await;
        }
        PacketType::PACKED_CONTROL_BLOCKS => {
            handle_packed_control_blocks(state, session_id, &payload, extracted_header).await;
        }
        _ => {
            // Control ACK types
            if state.control_ack_types.contains(&packet_type) {
                handle_control_ack(state, session_id, stream_id, sn, packet_type).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Individual packet handlers
// ---------------------------------------------------------------------------

async fn handle_ping(state: &Arc<ServerState>, session_id: u8, sn: u16) {
    queue::enqueue_packet(state, session_id, 5, 0, sn, PacketType::PONG, vec![]).await;
}

/// Handle STREAM_SYN (non-SOCKS5 direct forward mode)
async fn handle_stream_syn(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    syn_sn: u16,
) {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => return,
    };

    // Check closed_streams
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

    // Already exists? Re-send cached SYN_ACK
    if let Some(sd) = session.streams.get(&stream_id) {
        if let Some(cached) = sd.syn_responses.get("stream") {
            let c = cached.clone();
            drop(sessions);
            queue::enqueue_packet(
                state,
                session_id,
                c.priority,
                stream_id,
                syn_sn,
                c.packet_type,
                c.payload,
            )
            .await;
        }
        return;
    }

    // Create new stream and connect to forward target
    let mut sd = super::state::ServerStreamData::new(stream_id);
    sd.status = "CONNECTING".to_string();
    session.streams.insert(stream_id, sd);

    let forward_ip = state.forward_ip.clone();
    let forward_port = state.forward_port;
    let download_mtu = session.download_mtu;
    drop(sessions);

    // Connect to forward target
    match tokio::net::TcpStream::connect(format!("{}:{}", forward_ip, forward_port)).await {
        Ok(tcp_stream) => {
            let (reader, writer) = tcp_stream.into_split();

            let arq = stream::create_server_arq_stream(
                state,
                session_id,
                stream_id,
                reader,
                writer,
                download_mtu,
                vec![],
            );

            // Store ARQ and update status
            {
                let mut sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(sd) = session.streams.get_mut(&stream_id) {
                        sd.arq = Some(arq);
                        sd.status = "CONNECTED".to_string();
                        sd.syn_responses.insert(
                            "stream".to_string(),
                            super::state::CachedResponse {
                                packet_type: PacketType::STREAM_SYN_ACK,
                                payload: vec![],
                                priority: 2,
                                sequence_num: syn_sn,
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
                syn_sn,
                PacketType::STREAM_SYN_ACK,
                vec![],
            )
            .await;

            tracing::debug!(
                "Stream {} connected to {}:{} for session {}",
                stream_id,
                forward_ip,
                forward_port,
                session_id
            );
        }
        Err(e) => {
            tracing::error!(
                "Failed to connect to forward target for stream {} session {}: {}",
                stream_id,
                session_id,
                e
            );
            stream::close_stream(
                state,
                session_id,
                stream_id,
                &format!("Connection Error: {}", e),
                true,
                false,
            )
            .await;
        }
    }
}

async fn handle_stream_data(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
    payload: Vec<u8>,
) {
    if payload.is_empty() {
        return;
    }

    let sessions = state.sessions.lock().await;
    let session = match sessions.get(&session_id) {
        Some(s) => s,
        None => return,
    };

    if let Some(sd) = session.streams.get(&stream_id) {
        if let Some(arq) = &sd.arq {
            if matches!(
                sd.status.as_str(),
                "CONNECTED" | "DRAINING" | "CLOSING" | "TIME_WAIT"
            ) {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone.receive_data_only(sn, payload).await;
            }
        }
    } else {
        // Stream doesn't exist — send RST
        drop(sessions);
        handle_closed_stream_packet(state, session_id, PacketType::STREAM_DATA, stream_id, sn)
            .await;
    }
}

async fn handle_stream_data_ack(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
) {
    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        if let Some(sd) = session.streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone.receive_ack(sn).await;
                return;
            }
        }
    }
}

async fn handle_stream_fin(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
) {
    // Send FIN_ACK
    queue::enqueue_packet(
        state,
        session_id,
        0,
        stream_id,
        sn,
        PacketType::STREAM_FIN_ACK,
        vec![],
    )
    .await;

    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        if let Some(sd) = session.streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone.mark_fin_received(sn).await;
                return;
            }
        }
    }
}

async fn handle_stream_fin_ack(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
) {
    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        if let Some(sd) = session.streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone
                    .receive_control_ack(PacketType::STREAM_FIN_ACK, sn)
                    .await;
                return;
            }
        }
    }
}

async fn handle_stream_rst(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
) {
    // Send RST_ACK
    queue::enqueue_packet(
        state,
        session_id,
        0,
        stream_id,
        sn,
        PacketType::STREAM_RST_ACK,
        vec![],
    )
    .await;

    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        if let Some(sd) = session.streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone.mark_rst_received(sn).await;
            } else {
                drop(sessions);
            }
        } else {
            drop(sessions);
        }
    } else {
        drop(sessions);
    }

    stream::close_stream(state, session_id, stream_id, "Remote RST", true, true).await;
}

async fn handle_stream_rst_ack(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
) {
    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        if let Some(sd) = session.streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone
                    .receive_control_ack(PacketType::STREAM_RST_ACK, sn)
                    .await;
                return;
            }
            // Non-ARQ RST_ACK
            drop(sessions);
            {
                let mut sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(sd) = session.streams.get_mut(&stream_id) {
                        sd.rst_acked = true;
                    }
                }
            }
            return;
        }
    }
}

async fn handle_control_ack(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    sn: u16,
    packet_type: u8,
) {
    // Check if it's a SOCKS5 error ACK
    if let Some(&original_ptype) = state.socks5_error_ack_map.get(&packet_type) {
        // The client acknowledged our SOCKS5 error — no further action needed
        return;
    }

    let sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        if let Some(sd) = session.streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                let arq_clone = arq.clone();
                drop(sessions);
                arq_clone.receive_control_ack(packet_type, sn).await;
                return;
            }
        }
    }
}

async fn handle_packed_control_blocks(
    state: &Arc<ServerState>,
    session_id: u8,
    payload: &[u8],
    original_header: &VpnHeaderData,
) {
    let mut offset = 0;
    while offset + PACKED_CONTROL_BLOCK_SIZE <= payload.len() {
        if let Some((b_ptype, b_sid, b_sn)) =
            DnsPacketParser::unpack_control_block(&payload[offset..])
        {
            if PacketType::is_valid(b_ptype) && b_ptype != PacketType::PACKED_CONTROL_BLOCKS {
                dispatch_unpacked_block(state, session_id, b_ptype, b_sid, b_sn).await;
            }
        }
        offset += PACKED_CONTROL_BLOCK_SIZE;
    }
}

/// Dispatch a single unpacked control block.
async fn dispatch_unpacked_block(
    state: &Arc<ServerState>,
    session_id: u8,
    ptype: u8,
    stream_id: u16,
    sn: u16,
) {
    match ptype {
        PacketType::STREAM_DATA_ACK => {
            handle_stream_data_ack(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_FIN => {
            handle_stream_fin(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_FIN_ACK => {
            handle_stream_fin_ack(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_RST => {
            handle_stream_rst(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_RST_ACK => {
            handle_stream_rst_ack(state, session_id, stream_id, sn).await;
        }
        PacketType::STREAM_SYN => {
            handle_stream_syn(state, session_id, stream_id, sn).await;
        }
        _ => {
            if state.control_ack_types.contains(&ptype) {
                handle_control_ack(state, session_id, stream_id, sn, ptype).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handle packets for closed streams (mirrors Python _handle_closed_stream_packet)
// ---------------------------------------------------------------------------

async fn handle_closed_stream_packet(
    state: &Arc<ServerState>,
    session_id: u8,
    ptype: u8,
    stream_id: u16,
    sn: u16,
) {
    match ptype {
        PacketType::STREAM_FIN => {
            queue::enqueue_packet(
                state,
                session_id,
                0,
                stream_id,
                sn,
                PacketType::STREAM_FIN_ACK,
                vec![],
            )
            .await;
        }
        PacketType::STREAM_RST => {
            queue::enqueue_packet(
                state,
                session_id,
                0,
                stream_id,
                sn,
                PacketType::STREAM_RST_ACK,
                vec![],
            )
            .await;
        }
        PacketType::STREAM_DATA | PacketType::STREAM_RESEND => {
            queue::enqueue_packet(
                state,
                session_id,
                0,
                stream_id,
                0,
                PacketType::STREAM_RST,
                vec![],
            )
            .await;
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Build piggybacked response (mirrors Python _dequeue_response_packet in handle_vpn_packet)
// ---------------------------------------------------------------------------

async fn build_piggybacked_response(
    state: &Arc<ServerState>,
    session_id: u8,
    request_domain: &str,
    question_packet: &[u8],
    extracted_header: &VpnHeaderData,
) -> Option<Vec<u8>> {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => return None,
    };

    let item = match queue::dequeue_response_packet(state, session) {
        Some(i) => i,
        None => return None,
    };

    // Pack control blocks if applicable
    let final_item = queue::maybe_pack_control_blocks(state, session, item);

    let ptype = final_item.packet_type;
    let stream_id = final_item.stream_id;
    let sn = final_item.sequence_num;
    let mut data = final_item.data;
    let base_encode = session.base_encode_responses;
    let cookie = session.session_cookie;
    let download_comp = session.download_compression;
    let comp_min = state.compression_min_size;

    drop(sessions);

    // Compress response data
    let mut actual_comp: u8 = CompressionType::OFF;
    if !data.is_empty() && download_comp != CompressionType::OFF {
        let (compressed, ct) = compress_payload(&data, download_comp, comp_min);
        data = compressed;
        actual_comp = ct;
    }

    // Encrypt response data
    let encrypted = if !data.is_empty() {
        state.parser.codec_transform(&data, true)
    } else {
        vec![]
    };

    Some(state.parser.generate_full_vpn_response(
        request_domain,
        session_id,
        ptype,
        &encrypted,
        question_packet,
        stream_id,
        sn,
        base_encode,
        actual_comp,
        cookie,
    ))
}
