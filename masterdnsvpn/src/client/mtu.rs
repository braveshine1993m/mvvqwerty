// MasterDnsVPN Client - MTU Testing & Synchronization
// Mirrors Python client: test_mtu_sizes, _binary_search_mtu,
// send_upload_mtu_test, send_download_mtu_test, _sync_mtu_with_server
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::Mutex as TokioMutex;

use crate::dns_utils::dns_enums::{DnsRecordType, PacketType};
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::utils::generate_random_hex_text;

use super::state::{ClientState, ConnectionEntry};

// ---------------------------------------------------------------------------
// Helper: send DNS query and wait for response (mirrors Python _send_and_receive_dns)
// ---------------------------------------------------------------------------
async fn send_and_receive_dns(
    parser: &Arc<DnsPacketParser>,
    query_data: &[u8],
    resolver_addr: SocketAddr,
    timeout_secs: f64,
    buffer_size: usize,
) -> Option<Vec<u8>> {
    let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };

    if sock.send_to(query_data, resolver_addr).await.is_err() {
        return None;
    }

    let mut buf = vec![0u8; buffer_size];
    let timeout = std::time::Duration::from_secs_f64(timeout_secs);
    match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Process received packet (mirrors Python _process_received_packet, simplified)
// ---------------------------------------------------------------------------
fn process_received_packet(
    parser: &Arc<DnsPacketParser>,
    response_bytes: &[u8],
    base_encode_responses: bool,
) -> (Option<crate::dns_utils::dns_packet_parser::VpnHeaderData>, Vec<u8>) {
    if response_bytes.is_empty() {
        return (None, vec![]);
    }

    let parsed = match DnsPacketParser::parse_dns_packet(response_bytes) {
        Some(p) => p,
        None => return (None, vec![]),
    };

    let (hdr, data) = parser.extract_vpn_response(&parsed, base_encode_responses);
    match hdr {
        Some(h) => (Some(h), data),
        None => (None, vec![]),
    }
}

// ---------------------------------------------------------------------------
// Upload MTU test for a specific connection (mirrors Python send_upload_mtu_test)
// ---------------------------------------------------------------------------
async fn send_upload_mtu_test(
    state: &Arc<ClientState>,
    domain: &str,
    resolver_addr: SocketAddr,
    mtu_size: usize,
) -> bool {
    let (mtu_char_len, mtu_bytes) = state.parser.calculate_upload_mtu(domain, mtu_size);
    if mtu_size > mtu_bytes || mtu_char_len < 29 {
        return false;
    }

    let flag_str = if state.base_encode_responses { "1" } else { "0" };
    let random_hex = format!("{}{}", flag_str, generate_random_hex_text(mtu_char_len.saturating_sub(1)));

    let dns_queries = state.parser.build_request_dns_query(
        domain,
        rand::random::<u8>(),
        PacketType::MTU_UP_REQ,
        random_hex.as_bytes(),
        mtu_char_len,
        false, // encode_data = false (already hex text)
        DnsRecordType::TXT,
        0, 0, 0, 0, 0, 0, 0,
    );

    if dns_queries.is_empty() {
        return false;
    }

    let response = send_and_receive_dns(
        &state.parser,
        &dns_queries[0],
        resolver_addr,
        state.mtu_test_timeout,
        65535,
    )
    .await;

    match response {
        Some(resp) => {
            let (hdr, _) = process_received_packet(&state.parser, &resp, state.base_encode_responses);
            if let Some(h) = hdr {
                if h.packet_type == PacketType::MTU_UP_RES {
                    return true;
                }
            }
            false
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Download MTU test for a specific connection (mirrors Python send_download_mtu_test)
// ---------------------------------------------------------------------------
async fn send_download_mtu_test(
    state: &Arc<ClientState>,
    domain: &str,
    resolver_addr: SocketAddr,
    mtu_size: usize,
    up_mtu_bytes: usize,
) -> bool {
    let worst_header = state.parser.get_max_vpn_header_raw_size();
    let test_header = state.parser.get_vpn_header_raw_size(PacketType::MTU_DOWN_RES);
    let header_reserve = worst_header.saturating_sub(test_header);
    let effective_download_size = mtu_size + header_reserve;

    let target_length = up_mtu_bytes.max(5);
    let flag_byte: u8 = if state.base_encode_responses { 0x01 } else { 0x00 };
    let mut data_bytes = vec![flag_byte];
    data_bytes.extend_from_slice(&(effective_download_size as u32).to_be_bytes());

    if target_length > 5 {
        let pad: Vec<u8> = (0..(target_length - 5)).map(|_| rand::random::<u8>()).collect();
        data_bytes.extend_from_slice(&pad);
    }

    let encrypted_data = state.parser.codec_transform(&data_bytes, true);

    let (mtu_char_len, _) = state.parser.calculate_upload_mtu(domain, target_length);

    let dns_queries = state.parser.build_request_dns_query(
        domain,
        rand::random::<u8>(),
        PacketType::MTU_DOWN_REQ,
        &encrypted_data,
        mtu_char_len,
        true,
        DnsRecordType::TXT,
        0, 0, 0, 0, 0, 0, 0,
    );

    if dns_queries.is_empty() {
        return false;
    }

    let response = send_and_receive_dns(
        &state.parser,
        &dns_queries[0],
        resolver_addr,
        state.mtu_test_timeout,
        65535,
    )
    .await;

    match response {
        Some(resp) => {
            let (hdr, returned_data) =
                process_received_packet(&state.parser, &resp, state.base_encode_responses);
            if let Some(h) = hdr {
                if h.packet_type == PacketType::MTU_DOWN_RES {
                    return !returned_data.is_empty()
                        && returned_data.len() == effective_download_size;
                }
            }
            false
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Binary search MTU (mirrors Python _binary_search_mtu)
// ---------------------------------------------------------------------------
async fn binary_search_mtu<F, Fut>(
    state: &Arc<ClientState>,
    test_fn: F,
    min_mtu: usize,
    max_mtu: usize,
    min_threshold: usize,
    allowed_min_mtu: usize,
) -> usize
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if max_mtu == 0 {
        return 0;
    }

    let min_allowed = min_threshold.max(allowed_min_mtu);
    if max_mtu < min_allowed {
        return 0;
    }

    let low = min_mtu.max(min_allowed);
    let high = max_mtu;
    if low > high {
        return 0;
    }

    // Test high first
    let mut ok = false;
    for _ in 0..state.mtu_test_retries {
        if state.is_stopping() {
            return 0;
        }
        if test_fn(high).await {
            ok = true;
            break;
        }
    }
    if ok {
        return high;
    }

    if low == high {
        return 0;
    }

    // Test low
    ok = false;
    for _ in 0..state.mtu_test_retries {
        if state.is_stopping() {
            return 0;
        }
        if test_fn(low).await {
            ok = true;
            break;
        }
    }
    if !ok {
        return 0;
    }

    let mut optimal = low;
    let mut left = low + 1;
    let mut right = high - 1;

    while left <= right {
        if state.is_stopping() {
            return 0;
        }

        let mid = (left + right) / 2;
        let mut mid_ok = false;
        for _ in 0..state.mtu_test_retries {
            if state.is_stopping() {
                return 0;
            }
            if test_fn(mid).await {
                mid_ok = true;
                break;
            }
        }

        if mid_ok {
            optimal = mid;
            left = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            right = mid - 1;
        }
    }

    optimal
}

// ---------------------------------------------------------------------------
// Test upload MTU size for a connection (mirrors Python test_upload_mtu_size)
// ---------------------------------------------------------------------------
async fn test_upload_mtu_size(
    state: &Arc<ClientState>,
    domain: &str,
    resolver_addr: SocketAddr,
    default_mtu: usize,
) -> (bool, usize, usize) {
    let (mtu_char_len, mtu_bytes) = state.parser.calculate_upload_mtu(domain, 0);
    let default_mtu = if default_mtu > 512 || default_mtu == 0 {
        512
    } else {
        default_mtu
    };
    let actual_max = default_mtu.min(mtu_bytes);

    let s = state.clone();
    let d = domain.to_string();
    let optimal = binary_search_mtu(
        state,
        |m| {
            let s2 = s.clone();
            let d2 = d.clone();
            async move { send_upload_mtu_test(&s2, &d2, resolver_addr, m).await }
        },
        0,
        actual_max,
        30,
        state.min_upload_mtu,
    )
    .await;

    if optimal > 29 {
        let (chars, bytes) = state.parser.calculate_upload_mtu(domain, optimal);
        return (true, bytes, chars);
    }
    (false, 0, 0)
}

// ---------------------------------------------------------------------------
// Test download MTU size for a connection (mirrors Python test_download_mtu_size)
// ---------------------------------------------------------------------------
async fn test_download_mtu_size(
    state: &Arc<ClientState>,
    domain: &str,
    resolver_addr: SocketAddr,
    default_mtu: usize,
    up_mtu_bytes: usize,
) -> (bool, usize) {
    let s = state.clone();
    let d = domain.to_string();
    let optimal = binary_search_mtu(
        state,
        |m| {
            let s2 = s.clone();
            let d2 = d.clone();
            async move { send_download_mtu_test(&s2, &d2, resolver_addr, m, up_mtu_bytes).await }
        },
        0,
        default_mtu,
        30,
        state.min_download_mtu,
    )
    .await;

    if optimal >= state.min_download_mtu.max(30) {
        return (true, optimal);
    }
    (false, 0)
}

// ---------------------------------------------------------------------------
// Test MTU sizes for all connections (mirrors Python test_mtu_sizes)
// ---------------------------------------------------------------------------

/// Result of per-connection MTU testing
pub struct MtuTestResults {
    pub valid_count: usize,
    pub total_count: usize,
}

pub async fn test_mtu_sizes(state: &Arc<ClientState>) -> Option<MtuTestResults> {
    let total_conns = {
        let conn_map = state.connection_map.lock().await;
        conn_map.len()
    };

    if total_conns == 0 {
        tracing::error!("No connections to test MTU against!");
        return None;
    }

    tracing::info!("{}", "=".repeat(80));
    tracing::info!(
        "Testing MTU sizes for all resolver-domain pairs (parallel={})...",
        state.mtu_test_parallelism
    );

    // Reset all connections
    {
        let mut conn_map = state.connection_map.lock().await;
        for conn in conn_map.iter_mut() {
            conn.is_valid = false;
            conn.upload_mtu_bytes = 0;
            conn.upload_mtu_chars = 0;
            conn.download_mtu_bytes = 0;
            conn.packet_loss = 100;
            conn.recheck_fail_count = 0;
            conn.was_valid_once = false;
            conn.recheck_next_at = 0.0;
        }
    }

    // Shared counters
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let valid = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reject_upload = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reject_download = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Build work items
    let work_items: Vec<(usize, ConnectionEntry)> = {
        let conn_map = state.connection_map.lock().await;
        conn_map
            .iter()
            .enumerate()
            .map(|(i, c)| (i + 1, c.clone()))
            .collect()
    };

    let work_queue = Arc::new(TokioMutex::new(std::collections::VecDeque::from(work_items)));
    let results: Arc<TokioMutex<Vec<(usize, ConnectionEntry)>>> =
        Arc::new(TokioMutex::new(Vec::new()));

    let worker_count = state.mtu_test_parallelism.min(total_conns).max(1);
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let s = state.clone();
        let wq = work_queue.clone();
        let res = results.clone();
        let comp = completed.clone();
        let val = valid.clone();
        let rej_up = reject_upload.clone();
        let rej_down = reject_download.clone();
        let tc = total_conns;

        handles.push(tokio::spawn(async move {
            loop {
                if s.is_stopping() {
                    break;
                }

                let item = {
                    let mut q = wq.lock().await;
                    q.pop_front()
                };
                let (server_id, conn) = match item {
                    Some(i) => i,
                    None => break,
                };

                let domain = conn.domain.clone();
                let resolver_addr = conn.resolver_addr;
                let resolver_label = conn.resolver.clone();

                tracing::debug!(
                    "Testing connection {} via {} ({} / {})...",
                    domain,
                    resolver_label,
                    server_id,
                    tc
                );

                // Upload MTU test
                let (up_valid, up_mtu_bytes, up_mtu_chars) =
                    test_upload_mtu_size(&s, &domain, resolver_addr, s.max_upload_mtu).await;

                if !up_valid || (s.min_upload_mtu > 0 && up_mtu_bytes < s.min_upload_mtu) {
                    let c = comp.fetch_add(1, Ordering::SeqCst) + 1;
                    rej_up.fetch_add(1, Ordering::SeqCst);
                    let v = val.load(Ordering::SeqCst);
                    let r = rej_up.load(Ordering::SeqCst) + rej_down.load(Ordering::SeqCst);
                    tracing::warn!(
                        "Rejected ({}/{}): {} via {} | reason=UPLOAD_MTU | value={} | totals: valid={}, rejected={}",
                        c, tc, domain, resolver_label, up_mtu_bytes, v, r
                    );
                    continue;
                }

                // Download MTU test
                let (down_valid, down_mtu_bytes) =
                    test_download_mtu_size(&s, &domain, resolver_addr, s.max_download_mtu, up_mtu_bytes)
                        .await;

                if !down_valid || (s.min_download_mtu > 0 && down_mtu_bytes < s.min_download_mtu) {
                    let c = comp.fetch_add(1, Ordering::SeqCst) + 1;
                    rej_down.fetch_add(1, Ordering::SeqCst);
                    let v = val.load(Ordering::SeqCst);
                    let r = rej_up.load(Ordering::SeqCst) + rej_down.load(Ordering::SeqCst);
                    tracing::warn!(
                        "Rejected ({}/{}): {} via {} | reason=DOWNLOAD_MTU | value={} | totals: valid={}, rejected={}",
                        c, tc, domain, resolver_label, down_mtu_bytes, v, r
                    );
                    continue;
                }

                // Connection passed
                let c = comp.fetch_add(1, Ordering::SeqCst) + 1;
                val.fetch_add(1, Ordering::SeqCst);
                let v = val.load(Ordering::SeqCst);
                let r = rej_up.load(Ordering::SeqCst) + rej_down.load(Ordering::SeqCst);
                tracing::info!(
                    "Accepted ({}/{}): {} via {} | upload={} | download={} | totals: valid={}, rejected={}",
                    c, tc, domain, resolver_label, up_mtu_bytes, down_mtu_bytes, v, r
                );

                let mut updated_conn = conn.clone();
                updated_conn.is_valid = true;
                updated_conn.upload_mtu_bytes = up_mtu_bytes;
                updated_conn.upload_mtu_chars = up_mtu_chars;
                updated_conn.download_mtu_bytes = down_mtu_bytes;
                updated_conn.packet_loss = 0;
                updated_conn.was_valid_once = true;

                res.lock().await.push((server_id - 1, updated_conn));
            }
        }));
    }

    // Wait for all workers
    for h in handles {
        let _ = h.await;
    }

    // Apply results back to connection map
    let valid_results = results.lock().await;
    {
        let mut conn_map = state.connection_map.lock().await;
        for (idx, updated) in valid_results.iter() {
            if *idx < conn_map.len() {
                conn_map[*idx] = updated.clone();
            }
        }
    }

    let valid_count = valid.load(Ordering::SeqCst);
    if valid_count == 0 {
        tracing::error!("No valid connections found after MTU testing!");
        return None;
    }

    Some(MtuTestResults {
        valid_count,
        total_count: total_conns,
    })
}

// ---------------------------------------------------------------------------
// MTU Sync with server (mirrors Python _sync_mtu_with_server)
// ---------------------------------------------------------------------------
pub async fn sync_mtu_with_server(state: &Arc<ClientState>) -> Result<(), String> {
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;
    let cookie = state.session_cookie.load(Ordering::Relaxed) as u8;
    let mtu_chars = state.synced_upload_mtu_chars.load(Ordering::Relaxed);
    let up_mtu = state.upload_mtu_bytes.load(Ordering::Relaxed) as u32;
    let down_mtu = state.download_mtu_bytes.load(Ordering::Relaxed) as u32;

    tracing::info!(
        "Syncing MTU with server for session {}...",
        state.session_id.load(Ordering::Relaxed)
    );

    for overall_attempt in 0..10u32 {
        if state.is_stopping() {
            return Err("Client shutting down".into());
        }

        let (domain, resolver_addr, resolver_label) = {
            let mut bal = state.balancer.lock().await;
            match bal.get_best_server() {
                Some(r) => {
                    let addr: SocketAddr = r
                        .resolver
                        .parse()
                        .map_err(|e| format!("Invalid resolver: {}", e))?;
                    (r.domain.clone(), addr, r.resolver.clone())
                }
                None => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            }
        };

        let sync_token: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
        let mut mtu_data = Vec::with_capacity(16);
        mtu_data.extend_from_slice(&up_mtu.to_be_bytes());
        mtu_data.extend_from_slice(&down_mtu.to_be_bytes());
        mtu_data.extend_from_slice(&sync_token);

        let encrypted = state.parser.codec_transform(&mtu_data, true);

        let queries = state.parser.build_request_dns_query(
            &domain,
            session_id,
            PacketType::SET_MTU_REQ,
            &encrypted,
            mtu_chars,
            true,
            DnsRecordType::TXT,
            0, 0, 0, 0, 0, 0, cookie,
        );

        if queries.is_empty() {
            tracing::error!(
                "Failed to build MTU sync via {} for {}, Retrying...",
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
                &state.parser,
                &queries[0],
                resolver_addr,
                2.0,
                65535,
            )
            .await;

            if let Some(resp) = response {
                let (hdr, returned_data) =
                    process_received_packet(&state.parser, &resp, state.base_encode_responses);
                if let Some(h) = hdr {
                    if h.packet_type == PacketType::SET_MTU_RES {
                        if returned_data == sync_token {
                            tracing::info!("MTU values successfully synced with the server!");
                            return Ok(());
                        } else {
                            tracing::warn!("MTU Sync token mismatch! Ignoring response.");
                        }
                    }
                }
            }

            if inner_attempt < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        tracing::warn!(
            "MTU sync failed via {} for {}. Retrying overall process...",
            resolver_label,
            domain
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    Err("Failed to sync MTU with server after retries".into())
}
