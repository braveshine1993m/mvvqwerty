// MasterDnsVPN Server - DNS Request Handling
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::Arc;

use crate::dns_utils::dns_enums::{DnsRecordType, PacketType};
use crate::dns_utils::dns_packet_parser::DnsPacketParser;

use super::packet_handler;
use super::session;
use super::state::ServerState;

// ---------------------------------------------------------------------------
// DNS Request Worker (mirrors Python _dns_request_worker / handle_single_request)
// ---------------------------------------------------------------------------

/// Process one incoming DNS request: parse, validate domain, extract VPN header,
/// dispatch to packet handler, and send the response.
pub async fn handle_single_request(
    state: &Arc<ServerState>,
    raw_data: &[u8],
    addr: SocketAddr,
) {
    // Parse DNS packet
    let dns_packet = match DnsPacketParser::parse_dns_packet(raw_data) {
        Some(p) => p,
        None => {
            send_servfail(state, raw_data, addr).await;
            return;
        }
    };

    // Validate domain
    let qname = match dns_packet.questions.first() {
        Some(q) => q.qname.to_lowercase(),
        None => {
            send_servfail(state, raw_data, addr).await;
            return;
        }
    };
    if !is_allowed_domain(state, &qname) {
        tracing::debug!(
            "Received DNS request for unauthorized domain '{}' from {}. Ignoring.",
            qname, addr
        );
        send_refused(state, raw_data, addr).await;
        return;
    }

    // Validate qType is TXT (mirrors Python q0.get("qType") != DNS_Record_Type.TXT)
    if let Some(q) = dns_packet.questions.first() {
        if q.qtype != DnsRecordType::TXT {
            send_empty_noerror(state, raw_data, addr).await;
            return;
        }
    }

    // Extract the request domain (the allowed domain suffix)
    let request_domain = match find_request_domain(state, &qname) {
        Some(d) => d,
        None => {
            send_servfail(state, raw_data, addr).await;
            return;
        }
    };

    // Extract labels (subdomain part before the domain)
    let labels = extract_labels(&qname, &request_domain);
    if labels.is_empty() {
        send_servfail(state, raw_data, addr).await;
        return;
    }

    // Extract VPN header from DNS labels
    let hdr = match state.parser.extract_vpn_header_from_labels(&labels) {
        Some(h) => h,
        None => {
            send_servfail(state, raw_data, addr).await;
            return;
        }
    };
    // Extract encrypted payload data from the labels
    let _label_payload = state.parser.extract_vpn_data_from_labels(&labels);

    let packet_type = hdr.packet_type;
    let session_id = hdr.session_id;

    // Validate packet type
    if !state.valid_packet_types.contains(&packet_type) {
        tracing::debug!(
            "Invalid packet type {} from {}",
            packet_type,
            addr
        );
        send_servfail(state, raw_data, addr).await;
        return;
    }

    // Validate session cookie for all packet types (mirrors Python)
    let expected_cookie = session::expected_session_cookie(state, packet_type, session_id).await;
    let packet_cookie = hdr.session_cookie;

    if expected_cookie.is_none() || packet_cookie != expected_cookie.unwrap_or(0) {
        tracing::debug!(
            "Invalid session cookie for packet type '{}' session '{}' from {}. Dropping.",
            packet_type, session_id, addr
        );
        if session::should_emit_invalid_cookie_error(
            packet_type,
            expected_cookie,
            packet_cookie,
        ) {
            let response = build_invalid_session_error_response(
                state,
                session_id,
                &request_domain,
                raw_data,
            );
            if let Some(resp) = response {
                send_response(state, &resp, addr).await;
            }
        }
        return;
    }

    // Dispatch to main packet handler
    let vpn_response = packet_handler::handle_vpn_packet(
        state,
        packet_type,
        session_id,
        raw_data,
        &labels,
        &request_domain,
        addr,
        &hdr,
    )
    .await;

    if let Some(resp) = vpn_response {
        send_response(state, &resp, addr).await;
        return;
    }

    // Fallback: send empty NOERROR DNS response (mirrors Python)
    send_empty_noerror(state, raw_data, addr).await;
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

fn is_allowed_domain(state: &ServerState, qname: &str) -> bool {
    let qname_lower = qname.to_lowercase();
    for domain in &state.allowed_domains_lower {
        if qname_lower.ends_with(domain) || qname_lower.ends_with(&format!("{}.", domain)) {
            return true;
        }
    }
    false
}

fn find_request_domain(state: &ServerState, qname: &str) -> Option<String> {
    let qname_lower = qname.to_lowercase();
    for (i, domain) in state.allowed_domains_lower.iter().enumerate() {
        let dot_domain = format!(".{}", domain);
        let dot_domain_trailing = format!(".{}.", domain);
        if qname_lower.ends_with(&dot_domain) || qname_lower.ends_with(&dot_domain_trailing) {
            return Some(state.allowed_domains[i].clone());
        }
        if qname_lower == *domain || qname_lower == format!("{}.", domain) {
            return Some(state.allowed_domains[i].clone());
        }
    }
    None
}

fn extract_labels(qname: &str, request_domain: &str) -> String {
    let qname_lower = qname.to_lowercase();
    let domain_lower = request_domain.to_lowercase();

    // Remove trailing dot
    let qname_clean = qname_lower.trim_end_matches('.');

    if let Some(prefix) = qname_clean.strip_suffix(&domain_lower) {
        let prefix = prefix.trim_end_matches('.');
        prefix.to_string()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

async fn send_response(state: &ServerState, data: &[u8], addr: SocketAddr) {
    let sock = state.udp_sock.lock().await;
    if let Some(ref s) = *sock {
        let _ = s.send_to(data, addr).await;
    }
}

async fn send_servfail(state: &ServerState, request: &[u8], addr: SocketAddr) {
    let response = DnsPacketParser::server_fail_response(request);
    send_response(state, &response, addr).await;
}

async fn send_refused(state: &ServerState, request: &[u8], addr: SocketAddr) {
    let response = DnsPacketParser::refused_response(request);
    send_response(state, &response, addr).await;
}

async fn send_empty_noerror(state: &ServerState, request: &[u8], addr: SocketAddr) {
    let response = DnsPacketParser::empty_noerror_response(request);
    send_response(state, &response, addr).await;
}

fn build_invalid_session_error_response(
    state: &ServerState,
    session_id: u8,
    request_domain: &str,
    question_packet: &[u8],
) -> Option<Vec<u8>> {
    // Check recently_closed for base_encode preference, else random
    let base_encode = {
        // Check active sessions first
        let sess = state.sessions.try_lock();
        if let Ok(sessions) = sess {
            if let Some(s) = sessions.get(&session_id) {
                Some(s.base_encode_responses)
            } else {
                None
            }
        } else {
            None
        }
    }
    .or_else(|| {
        let closed = state.recently_closed_sessions.try_lock();
        match closed {
            Ok(c) => c.get(&session_id).map(|i| i.base_encode),
            Err(_) => None,
        }
    })
    .unwrap_or(rand::random::<bool>());

    // Python: invalid_response_data = b"INV" + os.urandom(5)
    let mut inv_data = vec![b'I', b'N', b'V'];
    for _ in 0..5 {
        inv_data.push(rand::random::<u8>());
    }

    Some(state.parser.generate_simple_vpn_response(
        request_domain,
        session_id,
        PacketType::ERROR_DROP,
        &inv_data,
        question_packet,
        base_encode,
        0,
    ))
}
