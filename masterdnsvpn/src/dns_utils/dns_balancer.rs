// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashMap;
use rand::seq::SliceRandom;

/// Per-resolver quality statistics.
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    pub sent: u64,
    pub acked: u64,
    pub rtt_sum: f64,
    pub rtt_count: u64,
}

/// Resolver information used by the balancer.
#[derive(Debug, Clone)]
pub struct ResolverInfo {
    pub resolver: String,
    pub domain: String,
    pub is_valid: bool,
    pub key: String,
    /// Extra fields the caller may attach (resolver IP, port, etc.)
    pub extra: HashMap<String, String>,
}

impl ResolverInfo {
    pub fn new(resolver: &str, domain: &str, is_valid: bool) -> Self {
        let key = format!("{}:{}", resolver, domain);
        ResolverInfo {
            resolver: resolver.to_string(),
            domain: domain.to_string(),
            is_valid,
            key,
            extra: HashMap::new(),
        }
    }
}

/// Load-balancing strategy identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalancerStrategy {
    RoundRobin = 0,
    Random = 1,
    LeastLoss = 3,
    LowestLatency = 4,
}

impl From<i64> for BalancerStrategy {
    fn from(v: i64) -> Self {
        match v {
            1 => BalancerStrategy::Random,
            3 => BalancerStrategy::LeastLoss,
            4 => BalancerStrategy::LowestLatency,
            _ => BalancerStrategy::RoundRobin,
        }
    }
}

pub struct DNSBalancer {
    pub strategy: BalancerStrategy,
    rr_index: usize,
    pub server_stats: HashMap<String, ServerStats>,
    pub resolvers: Vec<ResolverInfo>,
    pub valid_servers: Vec<ResolverInfo>,
}

impl DNSBalancer {
    pub fn new(resolvers: Vec<ResolverInfo>, strategy: BalancerStrategy) -> Self {
        let mut b = DNSBalancer {
            strategy,
            rr_index: 0,
            server_stats: HashMap::new(),
            resolvers: Vec::new(),
            valid_servers: Vec::new(),
        };
        b.set_balancers(resolvers);
        b
    }

    pub fn set_balancers(&mut self, balancers: Vec<ResolverInfo>) {
        let valid: Vec<ResolverInfo> = balancers.iter().filter(|s| s.is_valid).cloned().collect();
        self.resolvers = balancers;
        self.valid_servers = valid;
        self.rr_index = 0;
    }

    fn normalize_required_count(&self, required_count: usize, default_if_invalid: usize) -> usize {
        let total = self.valid_servers.len();
        if total == 0 {
            return 0;
        }
        let count = if required_count == 0 { default_if_invalid } else { required_count };
        count.min(total)
    }

    pub fn report_success(&mut self, server_key: &str, rtt: f64) {
        let stats = self.server_stats.entry(server_key.to_string()).or_default();
        stats.acked += 1;
        if rtt > 0.0 {
            stats.rtt_sum += rtt;
            stats.rtt_count += 1;
        }
        // Decay to prevent unbounded growth
        if stats.sent > 1000 {
            stats.sent = (stats.sent as f64 * 0.5) as u64;
            stats.acked = (stats.acked as f64 * 0.5) as u64;
            stats.rtt_sum *= 0.5;
            stats.rtt_count = (stats.rtt_count as f64 * 0.5) as u64;
        }
    }

    pub fn report_send(&mut self, server_key: &str) {
        self.server_stats.entry(server_key.to_string()).or_default().sent += 1;
    }

    pub fn reset_server_stats(&mut self, server_key: &str) {
        self.server_stats.remove(server_key);
    }

    pub fn get_loss_rate(&self, server_key: &str) -> f64 {
        match self.server_stats.get(server_key) {
            Some(stats) => {
                if stats.sent < 5 {
                    return 0.5;
                }
                let loss = 1.0 - (stats.acked as f64 / stats.sent as f64);
                loss.clamp(0.0, 1.0)
            }
            None => 0.5,
        }
    }

    pub fn get_avg_rtt(&self, server_key: &str) -> f64 {
        match self.server_stats.get(server_key) {
            Some(stats) => {
                if stats.rtt_count < 5 {
                    return 999.0;
                }
                stats.rtt_sum / stats.rtt_count as f64
            }
            None => 999.0,
        }
    }

    /// Return a clone of all resolvers (valid and invalid).
    pub fn get_all_servers(&self) -> Vec<ResolverInfo> {
        self.resolvers.clone()
    }

    /// Return a clone of all valid (enabled) resolvers.
    pub fn get_valid_servers(&self) -> Vec<ResolverInfo> {
        self.valid_servers.clone()
    }

    pub fn get_best_server(&mut self) -> Option<ResolverInfo> {
        if self.valid_servers.is_empty() {
            return None;
        }
        let servers = self.get_unique_servers(1);
        servers.into_iter().next()
    }

    pub fn get_unique_servers(&mut self, required_count: usize) -> Vec<ResolverInfo> {
        let actual_count = self.normalize_required_count(required_count, 1);
        if actual_count == 0 {
            return Vec::new();
        }
        self.get_servers(actual_count)
    }

    pub fn get_servers_for_stream(&mut self, _stream_id: u16, required_count: usize) -> Vec<ResolverInfo> {
        let actual_count = self.normalize_required_count(required_count, 1);
        if actual_count == 0 {
            return Vec::new();
        }
        self.get_servers(actual_count)
    }

    fn get_servers(&mut self, count: usize) -> Vec<ResolverInfo> {
        match self.strategy {
            BalancerStrategy::Random => self.get_servers_random(count),
            BalancerStrategy::LeastLoss => self.get_servers_least_loss(count),
            BalancerStrategy::LowestLatency => self.get_servers_lowest_latency(count),
            BalancerStrategy::RoundRobin => self.get_servers_round_robin(count),
        }
    }

    fn get_servers_random(&self, count: usize) -> Vec<ResolverInfo> {
        let mut rng = rand::thread_rng();
        let mut servers = self.valid_servers.clone();
        servers.shuffle(&mut rng);
        servers.truncate(count);
        servers
    }

    fn get_servers_least_loss(&self, count: usize) -> Vec<ResolverInfo> {
        let mut scored: Vec<_> = self.valid_servers.clone();
        scored.sort_by(|a, b| {
            let la = self.get_loss_rate(&a.key);
            let lb = self.get_loss_rate(&b.key);
            la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(count);
        scored
    }

    fn get_servers_lowest_latency(&self, count: usize) -> Vec<ResolverInfo> {
        let mut scored: Vec<_> = self.valid_servers.clone();
        scored.sort_by(|a, b| {
            let ra = self.get_avg_rtt(&a.key);
            let rb = self.get_avg_rtt(&b.key);
            ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(count);
        scored
    }

    fn get_servers_round_robin(&mut self, count: usize) -> Vec<ResolverInfo> {
        let total = self.valid_servers.len();
        let idx = self.rr_index;
        self.rr_index = (idx + count) % total;

        if count == 1 {
            return vec![self.valid_servers[idx].clone()];
        }

        let end = idx + count;
        if end <= total {
            self.valid_servers[idx..end].to_vec()
        } else {
            let mut result = self.valid_servers[idx..].to_vec();
            result.extend_from_slice(&self.valid_servers[..end % total]);
            result
        }
    }
}
