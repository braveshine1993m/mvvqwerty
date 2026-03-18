// MasterDnsVPN Server - MTU Handlers
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;

use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::DnsPacketParser;

use super::config::PACKED_CONTROL_BLOCK_SIZE;
use super::session;
use super::state::ServerState;

// ---------------------------------------------------------------------------
// SET_MTU handler (mirrors Python _handle_set_mtu)
// ---------------------------------------------------------------------------

/// Handle SET_MTU_REQ: save upload/download MTU to the session and reply.
pub async fn handle_set_mtu(
    state: &Arc<ServerState>,
    session_id: u8,
    data: &[u8],
    labels: &str,
    request_domain: &str,
    question_packet: &[u8],
    extracted_header: &crate::dns_utils::dns_packet_parser::VpnHeaderData,
) -> Option<Vec<u8>> {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => {
            tracing::debug!(
                "SET_MTU_REQ for invalid session_id: {}",
                session_id
            );
            return None;
        }
    };

    let extracted_data = extract_packet_payload(state, labels, extracted_header);
    if extracted_data.len() < 8 {
        tracing::debug!("Invalid or missing SET_MTU_REQ data");
        return None;
    }

    let upload_mtu = u32::from_be_bytes([
        extracted_data[0],
        extracted_data[1],
        extracted_data[2],
        extracted_data[3],
    ]) as usize;
    let download_mtu = u32::from_be_bytes([
        extracted_data[4],
        extracted_data[5],
        extracted_data[6],
        extracted_data[7],
    ]) as usize;
    let sync_token = if extracted_data.len() > 8 {
        extracted_data[8..].to_vec()
    } else {
        b"OK".to_vec()
    };

    let safe_upload_mtu = upload_mtu.min(4096);
    let safe_download_mtu = download_mtu.min(4096);

    let safe_downlink_mtu = safe_download_mtu.saturating_sub(state.crypto_overhead);
    session.upload_mtu = safe_upload_mtu.saturating_sub(state.crypto_overhead);
    session.download_mtu = safe_downlink_mtu;

    // Compute max packed blocks based on download MTU
    let download_pack_limit = compute_mtu_based_pack_limit(
        safe_download_mtu,
        80.0,
        PACKED_CONTROL_BLOCK_SIZE,
    );
    session.max_packed_blocks = download_pack_limit
        .max(1)
        .min(state.max_packets_per_batch);

    session.last_activity = std::time::Instant::now();

    let base_encode = session.base_encode_responses;
    let cookie = session.session_cookie;

    tracing::info!(
        "Session {} MTU synced - Upload: {}, Download: {}",
        session_id,
        safe_upload_mtu,
        safe_download_mtu
    );

    drop(sessions);

    Some(state.parser.generate_simple_vpn_response(
        request_domain,
        session_id,
        PacketType::SET_MTU_RES,
        &sync_token,
        question_packet,
        base_encode,
        cookie,
    ))
}

// ---------------------------------------------------------------------------
// MTU_DOWN handler (mirrors Python _handle_mtu_down)
// ---------------------------------------------------------------------------

/// Handle MTU_DOWN_REQ: respond with requested bytes of padding data.
pub async fn handle_mtu_down(
    state: &Arc<ServerState>,
    session_id: u8,
    labels: &str,
    request_domain: &str,
    question_packet: &[u8],
    extracted_header: &crate::dns_utils::dns_packet_parser::VpnHeaderData,
) -> Option<Vec<u8>> {
    let download_size_bytes = extract_packet_payload(state, labels, extracted_header);
    if download_size_bytes.len() < 5 {
        tracing::debug!("Invalid MTU_DOWN_REQ data");
        return None;
    }

    let flag = download_size_bytes[0];
    let base_encode = flag == 1;
    let download_size = u32::from_be_bytes([
        download_size_bytes[1],
        download_size_bytes[2],
        download_size_bytes[3],
        download_size_bytes[4],
    ]) as usize;

    if download_size < 29 {
        tracing::debug!("Download size too small: {}", download_size);
        return None;
    }

    // Build response data of the requested size
    let raw_plaintext = if download_size > download_size_bytes.len() - 1 {
        let padding_len = download_size - (download_size_bytes.len() - 1);
        let mut data = download_size_bytes[1..].to_vec();
        let padding: Vec<u8> = (0..padding_len).map(|_| rand::random::<u8>()).collect();
        data.extend_from_slice(&padding);
        data
    } else {
        download_size_bytes[1..1 + download_size].to_vec()
    };

    let effective_session_id = if session_id != 0 { session_id } else { 255 };

    Some(state.parser.generate_simple_vpn_response(
        request_domain,
        effective_session_id,
        PacketType::MTU_DOWN_RES,
        &raw_plaintext,
        question_packet,
        base_encode,
        0,
    ))
}

// ---------------------------------------------------------------------------
// MTU_UP handler (mirrors Python _handle_mtu_up)
// ---------------------------------------------------------------------------

/// Handle MTU_UP_REQ: just echo back a success indicator.
pub async fn handle_mtu_up(
    state: &Arc<ServerState>,
    session_id: u8,
    labels: &str,
    request_domain: &str,
    question_packet: &[u8],
) -> Option<Vec<u8>> {
    let raw_label = if labels.contains('.') {
        labels.split('.').next().unwrap_or(labels)
    } else {
        labels
    };
    let base_encode = raw_label.starts_with('1');

    let effective_session_id = if session_id != 0 { session_id } else { 255 };

    Some(state.parser.generate_simple_vpn_response(
        request_domain,
        effective_session_id,
        PacketType::MTU_UP_RES,
        b"1",
        question_packet,
        base_encode,
        0,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract and decrypt the payload portion from DNS labels.
fn extract_packet_payload(
    state: &Arc<ServerState>,
    labels: &str,
    _extracted_header: &crate::dns_utils::dns_packet_parser::VpnHeaderData,
) -> Vec<u8> {
    let raw = state.parser.extract_vpn_data_from_labels(labels);
    if raw.is_empty() {
        return vec![];
    }
    state.parser.codec_transform(&raw, false)
}

/// Compute max packed control blocks that fit within the given MTU.
fn compute_mtu_based_pack_limit(
    download_mtu: usize,
    overhead_pct: f64,
    block_size: usize,
) -> usize {
    if block_size == 0 || download_mtu == 0 {
        return 1;
    }
    let usable = (download_mtu as f64 * (overhead_pct / 100.0)) as usize;
    (usable / block_size).max(1)
}
