// MasterDnsVPN Client - MTU Testing & Synchronization
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
// MTU Sync with server (mirrors Python _mtu_sync)
// ---------------------------------------------------------------------------

/// Sync the negotiated MTU values with the server via SET_MTU_REQ / SET_MTU_RES.
pub async fn sync_mtu_with_server(
    state: &Arc<ClientState>,
    sock: &Arc<tokio::net::UdpSocket>,
) -> Result<(), String> {
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;
    let cookie = state.session_cookie.load(Ordering::Relaxed) as u8;
    let domain = &state.domains[0];
    let mtu_chars = state.upload_mtu_chars.load(Ordering::Relaxed);
    let up_mtu = state.upload_mtu_bytes.load(Ordering::Relaxed) as u32;
    let down_mtu = state.download_mtu_bytes.load(Ordering::Relaxed) as u32;

    // Payload: 4 bytes upload_mtu (big-endian) + 4 bytes download_mtu (big-endian) + sync_token
    let sync_token: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
    let mut mtu_data = Vec::with_capacity(8 + sync_token.len());
    mtu_data.extend_from_slice(&up_mtu.to_be_bytes());
    mtu_data.extend_from_slice(&down_mtu.to_be_bytes());
    mtu_data.extend_from_slice(&sync_token);

    let encrypted = state.parser.codec_transform(&mtu_data, true);

    for attempt in 0..5u32 {
        if state.is_stopping() {
            return Err("Client shutting down".into());
        }

        let queries = state.parser.build_request_dns_query(
            domain,
            session_id,
            PacketType::SET_MTU_REQ,
            &encrypted,
            mtu_chars,
            true,
            DnsRecordType::TXT,
            0, 0, 0, 0, 0, 0, cookie,
        );

        let resolver = {
            let mut bal = state.balancer.lock().await;
            bal.get_best_server()
        };
        let resolver_addr: SocketAddr = match resolver {
            Some(r) => r.resolver.parse().map_err(|e| format!("{}", e))?,
            None => return Err("No resolvers".into()),
        };

        for q in &queries {
            let _ = sock.send_to(q, resolver_addr).await;
        }

        let mut buf = vec![0u8; 65535];
        let timeout = std::time::Duration::from_secs_f64(2.0 + attempt as f64 * 0.5);
        match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Some(parsed) = DnsPacketParser::parse_dns_packet(&buf[..n]) {
                    let (hdr, response_data) = state.parser.extract_vpn_response(&parsed, true);
                    if let Some(h) = hdr {
                        if h.packet_type == PacketType::SET_MTU_RES {
                            // Verify sync token if present
                            if !response_data.is_empty() {
                                let decrypted = state.parser.codec_transform(&response_data, false);
                                if decrypted.len() >= sync_token.len()
                                    && decrypted[..sync_token.len()] == sync_token[..]
                                {
                                    tracing::debug!("MTU sync token verified");
                                }
                            }

                            state
                                .synced_upload_mtu_chars
                                .store(mtu_chars, Ordering::SeqCst);
                            tracing::info!(
                                "MTU synced: upload={} bytes, download={} bytes",
                                up_mtu,
                                down_mtu
                            );
                            return Ok(());
                        }
                    }
                }
            }
            Ok(Err(e)) => tracing::debug!("MTU sync recv error: {}", e),
            Err(_) => tracing::debug!("MTU sync attempt {} timed out", attempt + 1),
        }
    }

    tracing::warn!("MTU sync failed after retries, using defaults");
    state
        .synced_upload_mtu_chars
        .store(mtu_chars, Ordering::SeqCst);
    Ok(())
}

// ---------------------------------------------------------------------------
// Upload MTU binary search (mirrors Python _mtu_upload_binary_search)
// ---------------------------------------------------------------------------

/// Test the maximum upload MTU via binary search using MTU_UP_REQ/RES.
pub async fn mtu_upload_test(
    state: &Arc<ClientState>,
    sock: &Arc<tokio::net::UdpSocket>,
    min_chars: usize,
    max_chars: usize,
) -> Result<usize, String> {
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;
    let domain = &state.domains[0];
    let mut lo = min_chars;
    let mut hi = max_chars;
    let mut best = min_chars;

    while lo <= hi {
        if state.is_stopping() {
            return Err("Client shutting down".into());
        }

        let mid = (lo + hi) / 2;
        if test_upload_mtu_size(state, sock, domain, session_id, mid).await {
            best = mid;
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    Ok(best)
}

/// Send a single MTU_UP_REQ of the given size and check if we get MTU_UP_RES back.
async fn test_upload_mtu_size(
    state: &Arc<ClientState>,
    sock: &Arc<tokio::net::UdpSocket>,
    domain: &str,
    session_id: u8,
    test_chars: usize,
) -> bool {
    // Build padding data to fill exactly test_chars worth of encoded labels
    let padding: Vec<u8> = (0..test_chars).map(|i| (i & 0xFF) as u8).collect();

    // Flag byte: 0 = base32 labels
    let mut payload = vec![0u8];
    payload.extend_from_slice(&padding);

    let queries = state.parser.build_request_dns_query(
        domain,
        session_id,
        PacketType::MTU_UP_REQ,
        &payload,
        test_chars + 64, // allow extra room for header
        true,
        DnsRecordType::TXT,
        0, 0, 0, 0, 0, 0, 0,
    );

    if queries.is_empty() {
        return false;
    }

    let resolver = {
        let mut bal = state.balancer.lock().await;
        bal.get_best_server()
    };
    let resolver_addr: SocketAddr = match resolver {
        Some(r) => match r.resolver.parse() {
            Ok(a) => a,
            Err(_) => return false,
        },
        None => return false,
    };

    for query in &queries {
        let _ = sock.send_to(query, resolver_addr).await;
    }

    let mut buf = vec![0u8; 65535];
    let timeout = std::time::Duration::from_secs(3);
    match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            if let Some(parsed) = DnsPacketParser::parse_dns_packet(&buf[..n]) {
                let (hdr, _) = state.parser.extract_vpn_response(&parsed, true);
                if let Some(h) = hdr {
                    return h.packet_type == PacketType::MTU_UP_RES;
                }
            }
            false
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Download MTU binary search (mirrors Python _mtu_download_binary_search)
// ---------------------------------------------------------------------------

/// Test the maximum download MTU via binary search using MTU_DOWN_REQ/RES.
pub async fn mtu_download_test(
    state: &Arc<ClientState>,
    sock: &Arc<tokio::net::UdpSocket>,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<usize, String> {
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;
    let domain = &state.domains[0];
    let mtu_chars = state.upload_mtu_chars.load(Ordering::Relaxed);
    let mut lo = min_bytes;
    let mut hi = max_bytes;
    let mut best = min_bytes;

    while lo <= hi {
        if state.is_stopping() {
            return Err("Client shutting down".into());
        }

        let mid = (lo + hi) / 2;
        if test_download_mtu_size(state, sock, domain, session_id, mtu_chars, mid).await {
            best = mid;
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    Ok(best)
}

/// Send MTU_DOWN_REQ asking for `test_bytes` of download data and verify response.
async fn test_download_mtu_size(
    state: &Arc<ClientState>,
    sock: &Arc<tokio::net::UdpSocket>,
    domain: &str,
    session_id: u8,
    mtu_chars: usize,
    test_bytes: usize,
) -> bool {
    // Payload: flag(1) + size(4 bytes big-endian) + random_seed(4)
    let flag_byte: u8 = 0; // base32
    let mut payload = vec![flag_byte];
    payload.extend_from_slice(&(test_bytes as u32).to_be_bytes());
    payload.extend_from_slice(&rand::random::<[u8; 4]>());

    let encrypted = state.parser.codec_transform(&payload, true);

    let queries = state.parser.build_request_dns_query(
        domain,
        session_id,
        PacketType::MTU_DOWN_REQ,
        &encrypted,
        mtu_chars,
        true,
        DnsRecordType::TXT,
        0, 0, 0, 0, 0, 0, 0,
    );

    if queries.is_empty() {
        return false;
    }

    let resolver = {
        let mut bal = state.balancer.lock().await;
        bal.get_best_server()
    };
    let resolver_addr: SocketAddr = match resolver {
        Some(r) => match r.resolver.parse() {
            Ok(a) => a,
            Err(_) => return false,
        },
        None => return false,
    };

    for query in &queries {
        let _ = sock.send_to(query, resolver_addr).await;
    }

    let mut buf = vec![0u8; 65535];
    let timeout = std::time::Duration::from_secs(3);
    match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            if let Some(parsed) = DnsPacketParser::parse_dns_packet(&buf[..n]) {
                let (hdr, data) = state.parser.extract_vpn_response(&parsed, true);
                if let Some(h) = hdr {
                    if h.packet_type == PacketType::MTU_DOWN_RES {
                        // Verify we got at least close to the requested amount
                        return data.len() >= test_bytes.saturating_sub(32);
                    }
                }
            }
            false
        }
        _ => false,
    }
}
