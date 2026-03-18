// MasterDnsVPN Client - RX Worker & Response Dispatch
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;

use crate::dns_utils::compression::{try_decompress_payload, CompressionType};
use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::{DnsPacketParser, VpnHeaderData};

use super::config::PACKED_CONTROL_BLOCK_SIZE;
use super::queue;
use super::state::ClientState;
use super::stream;

// ---------------------------------------------------------------------------
// RX Worker (mirrors Python _rx_worker)
// ---------------------------------------------------------------------------

/// Receives DNS responses from the tunnel socket, parses them, and dispatches.
pub async fn rx_worker(state: &Arc<ClientState>, sock: &Arc<UdpSocket>) {
    let mut buf = vec![0u8; 65535];

    while !state.is_stopping() {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sock.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, _addr))) => {
                if n < 12 {
                    continue;
                }
                let data = buf[..n].to_vec();
                let s = state.clone();
                let permit = state.rx_semaphore.clone().try_acquire_owned();
                if let Ok(permit) = permit {
                    tokio::spawn(async move {
                        process_received_packet(&s, &data).await;
                        drop(permit);
                    });
                }
            }
            Ok(Err(e)) => {
                if !state.is_stopping() {
                    tracing::debug!("RX recv error: {}", e);
                }
            }
            Err(_) => {} // timeout — loop to re-check running
        }
    }
}

// ---------------------------------------------------------------------------
// Process a single received DNS response
// (mirrors Python _process_and_route_incoming)
// ---------------------------------------------------------------------------

async fn process_received_packet(state: &Arc<ClientState>, raw_data: &[u8]) {
    let parsed = match DnsPacketParser::parse_dns_packet(raw_data) {
        Some(p) => p,
        None => return,
    };

    let (hdr_opt, data) = state.parser.extract_vpn_response(&parsed, true);
    let hdr = match hdr_opt {
        Some(h) => h,
        None => return,
    };

    // Validate session cookie
    let expected_cookie = state.expected_inbound_session_cookie(hdr.packet_type);
    if expected_cookie != 0 && hdr.session_cookie != expected_cookie as u8 {
        tracing::debug!(
            "Cookie mismatch: expected={} got={} ptype={}",
            expected_cookie,
            hdr.session_cookie,
            hdr.packet_type
        );
        return;
    }

    // Decrypt data if present
    let decrypted = if !data.is_empty() {
        state.parser.codec_transform(&data, false)
    } else {
        vec![]
    };

    // Track download bytes
    state
        .total_download
        .fetch_add(raw_data.len() as u64, Ordering::Relaxed);

    handle_server_response(state, &hdr, decrypted).await;
}

// ---------------------------------------------------------------------------
// Server Response Handler (mirrors Python _handle_server_response)
// ---------------------------------------------------------------------------

async fn handle_server_response(
    state: &Arc<ClientState>,
    hdr: &VpnHeaderData,
    mut data: Vec<u8>,
) {
    let ptype = hdr.packet_type;
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;

    // Verify session_id for all post-session packets
    if hdr.session_id != session_id
        && ptype != PacketType::SESSION_ACCEPT
        && ptype != PacketType::MTU_UP_RES
        && ptype != PacketType::MTU_DOWN_RES
        && ptype != PacketType::ERROR_DROP
    {
        return;
    }

    // Decompress if needed
    let comp_type = hdr.compression_type.unwrap_or(CompressionType::OFF);
    if !data.is_empty() && comp_type != CompressionType::OFF {
        let (decompressed, ok) = try_decompress_payload(&data, comp_type);
        if !ok {
            tracing::debug!("Decompression failed for ptype={}", ptype);
            return;
        }
        data = decompressed;
    }

    let stream_id = hdr.stream_id.unwrap_or(0);
    let sn = hdr.sequence_num.unwrap_or(0);

    // Handle packets for closed streams
    if stream_id > 0 {
        let closed = state.closed_streams.lock().await;
        if closed.contains_key(&stream_id) {
            drop(closed);
            handle_closed_stream_packet(state, ptype, stream_id, sn).await;
            return;
        }
    }

    // Update stream activity timestamp
    if stream_id > 0 {
        let mut streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get_mut(&stream_id) {
            sd.last_activity_time = Instant::now();
        }
    }

    // -----------------------------------------------------------------------
    // PACKED_CONTROL_BLOCKS — unpack and recursively handle each block
    // -----------------------------------------------------------------------
    if ptype == PacketType::PACKED_CONTROL_BLOCKS && !data.is_empty() {
        let mut offset = 0;
        while offset + PACKED_CONTROL_BLOCK_SIZE <= data.len() {
            if let Some((b_ptype, b_sid, b_sn)) =
                DnsPacketParser::unpack_control_block(&data[offset..])
            {
                if PacketType::is_valid(b_ptype)
                    && b_ptype != PacketType::PACKED_CONTROL_BLOCKS
                {
                    let fake_hdr = VpnHeaderData {
                        session_id,
                        packet_type: b_ptype,
                        stream_id: Some(b_sid),
                        sequence_num: Some(b_sn),
                        fragment_id: None,
                        total_fragments: None,
                        total_data_length: None,
                        compression_type: None,
                        session_cookie: hdr.session_cookie,
                    };
                    Box::pin(handle_server_response(state, &fake_hdr, vec![])).await;
                }
            }
            offset += PACKED_CONTROL_BLOCK_SIZE;
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_SYN_ACK — stream accepted by server (non-SOCKS5 path)
    // -----------------------------------------------------------------------
    if ptype == PacketType::STREAM_SYN_ACK && stream_id > 0 {
        let mut streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get_mut(&stream_id) {
            if sd.arq.is_some() || sd.status == "ACTIVE" {
                return;
            }
            sd.status = "ACTIVE".to_string();
            if let Some(evt) = &sd.handshake_event {
                evt.notify_one();
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // SOCKS5_SYN_ACK — SOCKS5 target connected
    // -----------------------------------------------------------------------
    if ptype == PacketType::SOCKS5_SYN_ACK && stream_id > 0 {
        let is_fragment_ack = !data.is_empty();
        if !is_fragment_ack {
            let mut streams = state.active_streams.lock().await;
            if let Some(sd) = streams.get_mut(&stream_id) {
                if let Some(arq) = &sd.arq {
                    arq.receive_control_ack(PacketType::SOCKS5_SYN_ACK, sn).await;
                }
                sd.status = "ACTIVE".to_string();
                if let Some(evt) = &sd.handshake_event {
                    evt.notify_one();
                }
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // Control request packets → send ACK back
    // -----------------------------------------------------------------------
    if let Some(&ack_ptype) = state.control_request_ack_map.get(&ptype) {
        queue::enqueue_packet(state, 0, stream_id, sn, ack_ptype, vec![]).await;
        // Check if it's a SOCKS5 error
        if state.socks5_error_types.contains(&ptype) && stream_id > 0 {
            let mut streams = state.active_streams.lock().await;
            if let Some(sd) = streams.get_mut(&stream_id) {
                sd.socks_error_packet = Some(ptype);
                if let Some(evt) = &sd.handshake_event {
                    evt.notify_one();
                }
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // Control ACK types (from ARQ reliable control plane)
    // -----------------------------------------------------------------------
    if state.control_ack_types.contains(&ptype) && stream_id > 0 {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                arq.receive_control_ack(ptype, sn).await;
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_DATA / STREAM_RESEND — data from server
    // -----------------------------------------------------------------------
    if (ptype == PacketType::STREAM_DATA || ptype == PacketType::STREAM_RESEND)
        && stream_id > 0
        && !data.is_empty()
    {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                if matches!(
                    sd.status.as_str(),
                    "ACTIVE" | "DRAINING" | "CLOSING" | "TIME_WAIT"
                ) {
                    let arq_clone = arq.clone();
                    drop(streams);
                    // ARQ handles writing to its internal writer
                    arq_clone.receive_data_only(sn, data).await;
                }
            } else if sd.status == "PENDING" {
                // Buffer data for later delivery after ARQ is set up
                drop(streams);
                let mut streams_mut = state.active_streams.lock().await;
                if let Some(sd) = streams_mut.get_mut(&stream_id) {
                    sd.pending_inbound_data.entry(sn).or_insert(data);
                }
            } else {
                drop(streams);
                queue::enqueue_packet(state, 0, stream_id, 0, PacketType::STREAM_RST, vec![])
                    .await;
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_DATA_ACK — ACK from server for data we sent
    // -----------------------------------------------------------------------
    if ptype == PacketType::STREAM_DATA_ACK && stream_id > 0 {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                arq.receive_ack(sn).await;
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_FIN — server closing stream
    // -----------------------------------------------------------------------
    if ptype == PacketType::STREAM_FIN && stream_id > 0 {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                arq.mark_fin_received(sn).await;
            }
        }
        drop(streams);
        queue::enqueue_packet(state, 0, stream_id, sn, PacketType::STREAM_FIN_ACK, vec![]).await;
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_FIN_ACK — server acknowledges our FIN
    // -----------------------------------------------------------------------
    if ptype == PacketType::STREAM_FIN_ACK && stream_id > 0 {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                arq.receive_control_ack(PacketType::STREAM_FIN_ACK, sn).await;
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_RST — server forcibly resetting stream
    // -----------------------------------------------------------------------
    if ptype == PacketType::STREAM_RST && stream_id > 0 {
        queue::enqueue_packet(state, 0, stream_id, sn, PacketType::STREAM_RST_ACK, vec![]).await;
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                arq.mark_rst_received(sn).await;
            }
        }
        drop(streams);
        stream::close_stream(state, stream_id, "Remote stream reset", true, true).await;
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // STREAM_RST_ACK — server acknowledges our RST
    // -----------------------------------------------------------------------
    if ptype == PacketType::STREAM_RST_ACK && stream_id > 0 {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if let Some(arq) = &sd.arq {
                arq.receive_control_ack(PacketType::STREAM_RST_ACK, sn).await;
            }
        }
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // PONG — server pong reply
    // -----------------------------------------------------------------------
    if ptype == PacketType::PONG {
        // Update balancer RTT if possible
        queue::send_ping_packet(state);
        return;
    }

    // -----------------------------------------------------------------------
    // ERROR_DROP — session invalidated by server
    // -----------------------------------------------------------------------
    if ptype == PacketType::ERROR_DROP {
        if !state.session_restart.load(Ordering::Relaxed) {
            tracing::error!("Session dropped by server. Reconnecting...");
            state.session_restart.store(true, Ordering::SeqCst);
        }
        return;
    }
}

// ---------------------------------------------------------------------------
// Handle packets arriving for already-closed streams
// (mirrors Python _handle_closed_stream_packet)
// ---------------------------------------------------------------------------

async fn handle_closed_stream_packet(
    state: &Arc<ClientState>,
    ptype: u8,
    stream_id: u16,
    sn: u16,
) {
    match ptype {
        PacketType::STREAM_FIN => {
            queue::enqueue_packet(state, 0, stream_id, sn, PacketType::STREAM_FIN_ACK, vec![])
                .await;
        }
        PacketType::STREAM_RST => {
            queue::enqueue_packet(state, 0, stream_id, sn, PacketType::STREAM_RST_ACK, vec![])
                .await;
        }
        PacketType::STREAM_DATA | PacketType::STREAM_RESEND | PacketType::STREAM_DATA_ACK => {
            queue::enqueue_packet(state, 0, stream_id, 0, PacketType::STREAM_RST, vec![]).await;
        }
        _ => {}
    }
}
