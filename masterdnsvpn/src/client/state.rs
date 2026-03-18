// MasterDnsVPN Client - Shared State
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, Semaphore};

use crate::dns_utils::arq::{Arq, ArqConfig};
use crate::dns_utils::dns_balancer::DNSBalancer;
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueItem, QueueOwner};


// ---------------------------------------------------------------------------
// Per-stream data stored on the client
// ---------------------------------------------------------------------------
pub struct StreamData {
    pub stream_id: u16,
    pub arq: Option<Arc<Arq>>,
    pub writer: Option<tokio::net::tcp::OwnedWriteHalf>,
    pub status: String,
    pub create_time: Instant,
    pub last_activity_time: Instant,
    pub tx_queue: BinaryHeap<QueueItem>,
    pub queue_owner: QueueOwner,
    pub handshake_event: Option<Arc<Notify>>,
    pub socks_error_packet: Option<u8>,
    pub initial_payload: Vec<u8>,
    pub pending_inbound_data: HashMap<u16, Vec<u8>>,
    pub close_time: Option<Instant>,
    pub fin_retries: u32,
    pub rst_retries: u32,
    pub stream_creating: bool,
    pub preferred_server_key: String,
    pub resolver_resend_streak: u32,
    pub last_resolver_failover_at: f64,
}

impl StreamData {
    pub fn new(stream_id: u16) -> Self {
        let now = Instant::now();
        let mut owner = QueueOwner::default();
        owner.stream_id = Some(stream_id);
        Self {
            stream_id,
            arq: None,
            writer: None,
            status: "PENDING".to_string(),
            create_time: now,
            last_activity_time: now,
            tx_queue: BinaryHeap::new(),
            queue_owner: owner,
            handshake_event: None,
            socks_error_packet: None,
            initial_payload: Vec::new(),
            pending_inbound_data: HashMap::new(),
            close_time: None,
            fin_retries: 0,
            rst_retries: 0,
            stream_creating: false,
            preferred_server_key: String::new(),
            resolver_resend_streak: 0,
            last_resolver_failover_at: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Connection map entry (mirrors Python connection_map)
// ---------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct ConnectionEntry {
    pub key: String,
    pub domain: String,
    pub resolver: String,
    pub resolver_addr: SocketAddr,
}

// ---------------------------------------------------------------------------
// Shared client state
// ---------------------------------------------------------------------------
pub struct ClientState {
    // Session
    pub session_id: AtomicU16,
    pub session_cookie: AtomicU16,
    pub session_established: AtomicBool,
    pub session_restart: AtomicBool,

    // MTU
    pub upload_mtu_chars: AtomicUsize,
    pub upload_mtu_bytes: AtomicUsize,
    pub download_mtu_bytes: AtomicUsize,
    pub synced_upload_mtu_chars: AtomicUsize,
    pub safe_uplink_mtu: AtomicUsize,
    pub success_mtu_checks: AtomicBool,

    // Streams
    pub active_streams: Mutex<HashMap<u16, StreamData>>,
    pub closed_streams: Mutex<HashMap<u16, Instant>>,
    pub last_stream_id: AtomicU16,

    // Lifecycle
    pub running: AtomicBool,

    // Stats
    pub total_upload: AtomicU64,
    pub total_download: AtomicU64,

    // Core components
    pub parser: Arc<DnsPacketParser>,
    pub balancer: Mutex<DNSBalancer>,
    pub tunnel_sock: Mutex<Option<Arc<UdpSocket>>>,

    // Connection map
    pub connection_map: Mutex<Vec<ConnectionEntry>>,
    pub domains: Vec<String>,

    // Config values
    pub protocol_type: String,
    pub socks5_auth: bool,
    pub socks5_user: String,
    pub socks5_pass: String,
    pub upload_compression: u8,
    pub download_compression: u8,
    pub compression_min_size: usize,
    pub packet_duplication_count: usize,
    pub socks_handshake_timeout: f64,
    pub arq_config: ArqConfig,
    pub num_rx_workers: usize,
    pub rx_semaphore: Arc<Semaphore>,
    pub listen_ip: String,
    pub listen_port: u16,

    // Queue management
    pub queue_manager: Mutex<PacketQueueManager>,
    pub main_queue: Mutex<BinaryHeap<QueueItem>>,
    pub main_queue_owner: Mutex<QueueOwner>,
    pub tx_notify: Arc<Notify>,
    pub enqueue_seq: AtomicU32,
    pub active_response_ids: Mutex<Vec<u16>>,
    pub active_response_set: Mutex<HashSet<u16>>,
    pub round_robin_stream_id: AtomicU16,
    pub count_ping: AtomicU32,
    pub max_packed_blocks: usize,
    pub max_closed_stream_records: usize,

    // Packet type lookup tables (built once at startup)
    pub control_request_ack_map: HashMap<u8, u8>,
    pub control_ack_types: HashSet<u8>,
    pub socks5_error_types: HashSet<u8>,
    pub socks5_error_reply_map: HashMap<u8, u8>,
    pub packable_control_types: HashSet<u8>,
    pub pre_session_packet_types: HashSet<u8>,

    // Server health tracking per connection key
    pub server_send_counts: Mutex<HashMap<String, u64>>,
    pub disabled_servers: Mutex<HashMap<String, Instant>>,
}

impl ClientState {
    pub fn is_stopping(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
            || self.session_restart.load(Ordering::Relaxed)
    }

    pub fn new_stream_id(&self) -> Option<u16> {
        if self.is_stopping() {
            return None;
        }
        let start = self.last_stream_id.load(Ordering::Relaxed).wrapping_add(1);
        let id = if start == 0 || start > 65535 { 1 } else { start };
        // We cannot check active_streams synchronously here because it's behind
        // an async Mutex. The caller must validate after acquiring the lock.
        self.last_stream_id.store(id, Ordering::Relaxed);
        Some(id)
    }

    pub fn expected_inbound_session_cookie(&self, packet_type: u8) -> u16 {
        use crate::dns_utils::dns_enums::PacketType;
        if packet_type == PacketType::SESSION_ACCEPT
            || packet_type == PacketType::MTU_UP_RES
            || packet_type == PacketType::MTU_DOWN_RES
            || packet_type == PacketType::ERROR_DROP
        {
            return 0;
        }
        self.session_cookie.load(Ordering::Relaxed)
    }
}
