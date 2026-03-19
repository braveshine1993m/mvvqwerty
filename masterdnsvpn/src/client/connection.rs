// MasterDnsVPN Client - Connection & Resolver Management
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::dns_utils::config_loader::{get_config_path, TomlValueExt};
use crate::dns_utils::dns_balancer::ResolverInfo;
use crate::dns_utils::utils;

use super::state::{ClientState, ConnectionEntry};

// ---------------------------------------------------------------------------
// Resolver loading from config + file
// ---------------------------------------------------------------------------

/// Parse a resolver line into (ip_str, port).
/// Accepts: "1.2.3.4", "1.2.3.4:5353"
fn parse_resolver_entry(line: &str) -> Option<(String, u16)> {
    if line.contains(':') {
        // Could be ip:port
        let parts: Vec<&str> = line.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[0].parse::<u16>() {
                let ip = parts[1].to_string();
                // Validate it looks like an IP
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    return Some((ip, port));
                }
            }
        }
        // Try as bare IPv6 (rare) — fall through
        None
    } else {
        // bare IP, default port 53
        if line.parse::<std::net::IpAddr>().is_ok() {
            Some((line.to_string(), 53))
        } else {
            None
        }
    }
}

/// Expand CIDR notation to individual IPs (max 65536 hosts like Python).
/// Returns None if not CIDR, or Err if too large.
fn expand_cidr(line: &str) -> Option<Vec<String>> {
    if !line.contains('/') {
        return None;
    }
    // Parse as IPv4 CIDR only (common case)
    let (cidr_part, port_opt) = if let Some(idx) = line.find(':') {
        // cidr:port not standard, but handle gracefully
        (&line[..idx], Some(&line[idx+1..]))
    } else {
        (line, None)
    };
    let _ = port_opt; // port from CIDR line not used; caller uses default 53
    let network: std::net::Ipv4Addr;
    let prefix_len: u8;
    let parts: Vec<&str> = cidr_part.splitn(2, '/').collect();
    if parts.len() != 2 { return None; }
    network = parts[0].parse().ok()?;
    prefix_len = parts[1].parse().ok()?;
    if prefix_len > 32 { return None; }
    let num_hosts = 1u64 << (32 - prefix_len);
    if num_hosts > 65536 { return None; } // mirrors Python max_cidr_hosts
    let base = u32::from(network);
    let mask = if prefix_len == 0 { 0u32 } else { !((1u32 << (32 - prefix_len)) - 1) };
    let network_addr = base & mask;
    let broadcast = network_addr | ((1u32 << (32 - prefix_len)) - 1);
    // usable hosts: skip network and broadcast for /0.../30
    let (start, end) = if prefix_len < 31 {
        (network_addr + 1, broadcast.saturating_sub(1))
    } else {
        (network_addr, broadcast)
    };
    let mut ips = Vec::new();
    let mut ip = start;
    while ip <= end {
        ips.push(std::net::Ipv4Addr::from(ip).to_string());
        if ip == u32::MAX { break; }
        ip += 1;
    }
    Some(ips)
}

/// Load resolver addresses from the resolvers file specified in config.
/// Deduplicates by (ip, port) like Python _load_resolvers_from_file.
/// Supports CIDR ranges.
pub fn load_resolvers(
    config: &HashMap<String, toml::Value>,
    domains: &[String],
) -> Vec<ResolverInfo> {
    let mut resolvers: Vec<ResolverInfo> = Vec::new();
    let mut seen: HashSet<(String, u16)> = HashSet::new();

    let resolvers_file = config.get_str_or("CLIENT_RESOLVERS_FILE", "client_resolvers.txt");
    let file_path = get_config_path(&resolvers_file);

    if let Some(content) = utils::load_text(&file_path.to_string_lossy()) {
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Try CIDR expansion first
            if let Some(ips) = expand_cidr(line) {
                let expanded = ips.len();
                let mut count = 0usize;
                for ip in ips {
                    let entry = (ip.clone(), 53u16);
                    if seen.contains(&entry) { continue; }
                    seen.insert(entry);
                    for domain in domains {
                        resolvers.push(ResolverInfo::new(&format!("{}:53", ip), domain, true));
                    }
                    count += 1;
                }
                tracing::debug!("Expanded CIDR '{}' to {} IPs ({} new)", line, expanded, count);
                continue;
            }

            // Parse single IP or IP:port
            match parse_resolver_entry(line) {
                Some((ip, port)) => {
                    let entry = (ip.clone(), port);
                    if seen.contains(&entry) {
                        continue;
                    }
                    seen.insert(entry);
                    let addr_str = format!("{}:{}", ip, port);
                    for domain in domains {
                        resolvers.push(ResolverInfo::new(&addr_str, domain, true));
                    }
                }
                None => {
                    tracing::warn!("Invalid resolver entry '{}' ignored.", line);
                }
            }
        }
    }

    if resolvers.is_empty() {
        tracing::warn!("No resolvers in file, using fallback public DNS (8.8.8.8, 1.1.1.1)");
        for domain in domains {
            resolvers.push(ResolverInfo::new("8.8.8.8:53", domain, true));
            resolvers.push(ResolverInfo::new("1.1.1.1:53", domain, true));
        }
    }

    resolvers
}

// ---------------------------------------------------------------------------
// Connection map creation (mirrors Python _create_connection_map)
// ---------------------------------------------------------------------------

/// Build the connection map from the balancer's resolver list.
/// Each entry maps a unique key to a (domain, resolver_addr) pair.
pub async fn create_connection_map(state: &Arc<ClientState>) {
    let bal = state.balancer.lock().await;
    let resolvers = bal.get_all_servers();
    let mut entries = Vec::new();

    for info in &resolvers {
        if let Ok(addr) = info.resolver.parse::<SocketAddr>() {
            entries.push(ConnectionEntry {
                key: info.key.clone(),
                domain: info.domain.clone(),
                resolver: info.resolver.clone(),
                resolver_addr: addr,
                is_valid: false,
                upload_mtu_bytes: 0,
                upload_mtu_chars: 0,
                download_mtu_bytes: 0,
                packet_loss: 100,
                recheck_fail_count: 0,
                recheck_next_at: 0.0,
                was_valid_once: false,
            });
        }
    }

    let mut conn_map = state.connection_map.lock().await;
    *conn_map = entries;
}

// ---------------------------------------------------------------------------
// Server selection for TX packets (mirrors Python _select_target_connections_for_packet)
// ---------------------------------------------------------------------------

/// Select which connection entries to use when sending a packet.
/// Uses the balancer for best-server selection and respects packet_duplication_count.
pub async fn select_target_connections(
    state: &Arc<ClientState>,
    _packet_type: u8,
    stream_id: u16,
) -> Vec<ConnectionEntry> {
    let conn_map = state.connection_map.lock().await;
    if conn_map.is_empty() {
        return Vec::new();
    }

    let dup_count = state.packet_duplication_count.min(conn_map.len()).max(1);

    // For stream-bound packets, try to use the stream's preferred connection first
    if stream_id > 0 {
        let streams = state.active_streams.lock().await;
        if let Some(sd) = streams.get(&stream_id) {
            if !sd.preferred_server_key.is_empty() {
                if let Some(entry) = conn_map.iter().find(|e| e.key == sd.preferred_server_key) {
                    let mut result = vec![entry.clone()];
                    // Fill remaining slots with other connections
                    for e in conn_map.iter() {
                        if result.len() >= dup_count {
                            break;
                        }
                        if e.key != sd.preferred_server_key {
                            result.push(e.clone());
                        }
                    }
                    return result;
                }
            }
        }
    }

    // Use balancer to pick best servers
    let mut bal = state.balancer.lock().await;
    let best = bal.get_unique_servers(dup_count);
    drop(bal);

    let mut result = Vec::with_capacity(dup_count);
    for info in &best {
        if let Some(entry) = conn_map.iter().find(|e| e.key == info.key) {
            result.push(entry.clone());
        }
    }

    // Fallback: if balancer didn't return enough, fill from connection map
    if result.is_empty() {
        result.push(conn_map[0].clone());
    }

    result
}

// ---------------------------------------------------------------------------
// Stream preferred connection management
// (mirrors Python _ensure_stream_preferred_connection)
// ---------------------------------------------------------------------------

/// Assign a preferred server connection key to a stream for sticky routing.
pub async fn ensure_stream_preferred_connection(
    state: &Arc<ClientState>,
    stream_id: u16,
) {
    let conn_map = state.connection_map.lock().await;
    if conn_map.is_empty() {
        return;
    }

    let mut bal = state.balancer.lock().await;
    let best = match bal.get_best_server() {
        Some(r) => r,
        None => return,
    };
    drop(bal);

    let mut streams = state.active_streams.lock().await;
    if let Some(sd) = streams.get_mut(&stream_id) {
        sd.preferred_server_key = best.key.clone();
    }
}

// ---------------------------------------------------------------------------
// Server health tracking (mirrors Python _track_server_send / _note_stream_progress)
// ---------------------------------------------------------------------------

/// Record a send event for a connection key.
pub async fn track_server_send(state: &Arc<ClientState>, key: &str) {
    let mut counts = state.server_send_counts.lock().await;
    *counts.entry(key.to_string()).or_insert(0) += 1;
}

/// Note that a stream made progress (received a valid response) and reset
/// any resolver failover streak.
pub async fn note_stream_progress(state: &Arc<ClientState>, stream_id: u16) {
    let mut streams = state.active_streams.lock().await;
    if let Some(sd) = streams.get_mut(&stream_id) {
        sd.resolver_resend_streak = 0;
    }
}
