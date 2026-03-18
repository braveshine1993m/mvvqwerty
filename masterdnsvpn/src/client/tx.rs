// MasterDnsVPN Client - TX Worker
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::dns_utils::compression::{compress_payload, CompressionType};
use crate::dns_utils::dns_enums::DnsRecordType;
use crate::dns_utils::packet_queue::QueueItem;

use super::connection;
use super::queue;
use super::state::ClientState;

// ---------------------------------------------------------------------------
// TX Worker (mirrors Python _tx_worker)
// ---------------------------------------------------------------------------

/// Continuously dequeues packets and sends them as DNS queries to resolvers.
pub async fn tx_worker(state: &Arc<ClientState>, sock: &Arc<UdpSocket>) {
    while !state.is_stopping() {
        // Wait until something is enqueued
        state.tx_notify.notified().await;

        // Drain all available items
        loop {
            if state.is_stopping() {
                break;
            }

            let item = match queue::dequeue_response_packet(state).await {
                Some(i) => i,
                None => break,
            };

            if let Err(e) = send_single_packet(state, sock, &item).await {
                tracing::debug!("TX send error: {}", e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Send a single packet (mirrors Python _send_single_packet)
// ---------------------------------------------------------------------------

/// Build DNS queries for a single VPN packet and send to selected resolvers.
async fn send_single_packet(
    state: &Arc<ClientState>,
    sock: &Arc<UdpSocket>,
    item: &QueueItem,
) -> Result<(), String> {
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;
    let cookie = state.session_cookie.load(Ordering::Relaxed) as u8;
    let mtu_chars = state.synced_upload_mtu_chars.load(Ordering::Relaxed);
    let ptype = item.packet_type;
    let stream_id = item.stream_id;
    let sn = item.sequence_num;
    let mut data = item.data.clone();

    // Compress data if applicable
    let mut actual_comp: u8 = CompressionType::OFF;
    if !data.is_empty() && state.upload_compression != CompressionType::OFF {
        let (compressed, ct) =
            compress_payload(&data, state.upload_compression, state.compression_min_size);
        data = compressed;
        actual_comp = ct;
    }

    // Encrypt
    let data_encrypted = if !data.is_empty() {
        state.parser.codec_transform(&data, true)
    } else {
        vec![]
    };

    // Select target connections
    let targets =
        connection::select_target_connections(state, ptype, stream_id).await;

    if targets.is_empty() {
        // Fallback: use balancer directly
        let resolvers = {
            let mut bal = state.balancer.lock().await;
            bal.get_unique_servers(state.packet_duplication_count)
        };

        let domain = &state.domains[0];

        for resolver in &resolvers {
            send_to_resolver(
                state,
                sock,
                domain,
                &resolver.resolver,
                session_id,
                ptype,
                &data_encrypted,
                mtu_chars,
                stream_id,
                sn,
                actual_comp,
                cookie,
            )
            .await;

            // Report send
            let mut bal = state.balancer.lock().await;
            bal.report_send(&resolver.key);
        }
    } else {
        for entry in &targets {
            send_to_resolver(
                state,
                sock,
                &entry.domain,
                &entry.resolver,
                session_id,
                ptype,
                &data_encrypted,
                mtu_chars,
                stream_id,
                sn,
                actual_comp,
                cookie,
            )
            .await;

            // Report send
            let mut bal = state.balancer.lock().await;
            bal.report_send(&entry.key);
            drop(bal);

            connection::track_server_send(state, &entry.key).await;
        }
    }

    // Track upload bytes
    state
        .total_upload
        .fetch_add(data_encrypted.len() as u64, Ordering::Relaxed);

    Ok(())
}

/// Build and send DNS queries for a single packet to one resolver.
async fn send_to_resolver(
    state: &Arc<ClientState>,
    sock: &Arc<UdpSocket>,
    domain: &str,
    resolver: &str,
    session_id: u8,
    ptype: u8,
    data_encrypted: &[u8],
    mtu_chars: usize,
    stream_id: u16,
    sn: u16,
    comp: u8,
    cookie: u8,
) {
    let queries = state.parser.build_request_dns_query(
        domain,
        session_id,
        ptype,
        data_encrypted,
        mtu_chars,
        true,
        DnsRecordType::TXT,
        stream_id,
        sn,
        0, // fragment_id
        0, // total_fragments
        0, // total_data_length
        comp,
        cookie,
    );

    let resolver_addr: SocketAddr = match resolver.parse() {
        Ok(a) => a,
        Err(_) => return,
    };

    for query in &queries {
        let _ = sock.send_to(query, resolver_addr).await;
    }
}
