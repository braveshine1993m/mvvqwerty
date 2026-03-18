// MasterDnsVPN Server - DNS Request Handling
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::net::SocketAddr;
use std::sync::Arc;

use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::{DnsPacketParser, VpnHeaderData};

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
    let qname = dns_packet.qname.to_lowercase();
    if !is_allowed_domain(state, &qname) {
        send_servfail(state, raw_data, addr).await;
        return;
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
    let label_payload = state.parser.extract_vpn_data_from_labels(&labels);

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

    // Validate session cookie for post-session packets
    if !state.pre_session_packet_types.contains(&packet_type) {
        let expected = session::expected_session_cookie(state, packet_type, session_id).await;
        match expected {
            Some(expected_cookie) => {
                if expected_cookie != 0 && hdr.session_cookie != expected_cookie {
                    tracing::debug!(
                        "Cookie mismatch for session {}: expected={}, got={}",
                        session_id,
                        expected_cookie,
                        hdr.session_cookie
                    );
                    // Send ERROR_DROP
                    let response =
                        build_invalid_session_error_response(state, session_id, &request_domain, raw_data);
                    if let Some(resp) = response {
                        send_response(state, &resp, addr).await;
                    }
                    return;
                }
            }
            None => {
                // Session doesn't exist — send ERROR_DROP
                if session::should_emit_invalid_cookie_error(
                    packet_type,
                    None,
                    hdr.session_cookie,
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
        }
    }

    // Handle SET_MTU_REQ directly (returns a response)
    if packet_type == PacketType::SET_MTU_REQ {
        let response = super::mtu::handle_set_mtu(
            state,
            session_id,
            raw_data,
            &labels,
            &request_domain,
            raw_data,
            &hdr,
        )
        .await;
        if let Some(resp) = response {
            send_response(state, &resp, addr).await;
        }
        return;
    }

    // Dispatch to main packet handler
    let response = packet_handler::handle_vpn_packet(
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

    if let Some(resp) = response {
        send_response(state, &resp, addr).await;
    } else {
        // No piggybacked data available — send empty DNS response
        // (The server always responds to DNS queries)
        let cookie = {
            let sessions = state.sessions.lock().await;
            sessions
                .get(&session_id)
                .map(|s| s.session_cookie)
                .unwrap_or(0)
        };
        let empty_response = state.parser.generate_simple_vpn_response(
            &request_domain,
            session_id,
            PacketType::PONG,
            &[],
            raw_data,
            false,
            cookie,
        );
        send_response(state, &empty_response, addr).await;
    }
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

fn build_invalid_session_error_response(
    state: &ServerState,
    session_id: u8,
    request_domain: &str,
    question_packet: &[u8],
) -> Option<Vec<u8>> {
    // Check recently_closed for base_encode preference
    let base_encode = {
        let closed = state.recently_closed_sessions.try_lock();
        match closed {
            Ok(c) => c.get(&session_id).map(|i| i.base_encode).unwrap_or(false),
            Err(_) => false,
        }
    };

    Some(state.parser.generate_simple_vpn_response(
        request_domain,
        session_id,
        PacketType::ERROR_DROP,
        &[],
        question_packet,
        base_encode,
        0,
    ))
}
