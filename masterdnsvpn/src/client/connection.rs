// MasterDnsVPN Client - Connection & Resolver Management
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::dns_utils::config_loader::{get_config_path, TomlValueExt};
use crate::dns_utils::dns_balancer::ResolverInfo;
use crate::dns_utils::utils;

use super::state::{ClientState, ConnectionEntry};

// ---------------------------------------------------------------------------
// Resolver loading from config + file
// ---------------------------------------------------------------------------

/// Load resolver addresses from the resolvers file specified in config.
/// Falls back to public DNS (8.8.8.8, 1.1.1.1) if no resolvers are found.
pub fn load_resolvers(
    config: &HashMap<String, toml::Value>,
    domains: &[String],
) -> Vec<ResolverInfo> {
    let mut resolvers = Vec::new();

    let resolvers_file = config.get_str_or("CLIENT_RESOLVERS_FILE", "client_resolvers.txt");
    let file_path = get_config_path(&resolvers_file);

    if let Some(content) = utils::load_text(&file_path.to_string_lossy()) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let resolver = if line.contains(':') {
                line.to_string()
            } else {
                format!("{}:53", line)
            };
            for domain in domains {
                resolvers.push(ResolverInfo::new(&resolver, domain, true));
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
