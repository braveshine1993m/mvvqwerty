// MasterDnsVPN Server - Shared State
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, Semaphore};

use crate::dns_utils::arq::{Arq, ArqConfig};
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueItem, QueueOwner};

// ---------------------------------------------------------------------------
// Per-stream data on the server
// ---------------------------------------------------------------------------
pub struct ServerStreamData {
    pub stream_id: u16,
    pub arq: Option<Arc<Arq>>,
    pub writer: Option<tokio::net::tcp::OwnedWriteHalf>,
    pub status: String,
    pub create_time: Instant,
    pub last_activity: Instant,
    pub tx_queue: BinaryHeap<QueueItem>,
    pub queue_owner: QueueOwner,
    pub close_time: Option<Instant>,
    pub target_addr: String,
    pub priority_counts: HashMap<i32, usize>,
    pub syn_responses: HashMap<String, CachedResponse>,
    pub socks_chunks: HashMap<u8, Vec<u8>>,
    pub socks_expected_frags: Option<u8>,
    pub rst_sent: bool,
    pub rst_acked: bool,
    pub rst_seq_sent: u16,
    pub rst_retries: u32,
    pub fin_retries: u32,
}

impl ServerStreamData {
    pub fn new(stream_id: u16) -> Self {
        let now = Instant::now();
        let mut owner = QueueOwner::default();
        owner.stream_id = Some(stream_id);
        Self {
            stream_id,
            arq: None,
            writer: None,
            status: "CONNECTING".to_string(),
            create_time: now,
            last_activity: now,
            tx_queue: BinaryHeap::new(),
            queue_owner: owner,
            close_time: None,
            target_addr: String::new(),
            priority_counts: HashMap::new(),
            syn_responses: HashMap::new(),
            socks_chunks: HashMap::new(),
            socks_expected_frags: None,
            rst_sent: false,
            rst_acked: false,
            rst_seq_sent: 0,
            rst_retries: 0,
            fin_retries: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Cached response (for SYN_ACK / SOCKS5_SYN_ACK retransmission)
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct CachedResponse {
    pub packet_type: u8,
    pub payload: Vec<u8>,
    pub priority: i32,
    pub sequence_num: u16,
}

// ---------------------------------------------------------------------------
// Per-session state on the server
// ---------------------------------------------------------------------------
pub struct SessionState {
    pub session_id: u8,
    pub session_cookie: u8,
    pub client_addr: SocketAddr,
    pub last_activity: Instant,
    pub created_at: Instant,
    pub init_token: Vec<u8>,
    pub streams: HashMap<u16, ServerStreamData>,
    pub closed_streams: HashMap<u16, Instant>,
    pub main_queue: BinaryHeap<QueueItem>,
    pub main_queue_owner: QueueOwner,
    pub enqueue_seq: u32,
    pub active_response_ids: Vec<u16>,
    pub active_response_set: HashSet<u16>,
    pub round_robin_idx: u16,
    pub upload_mtu: usize,
    pub download_mtu: usize,
    pub max_packed_blocks: usize,
    pub base_encode_responses: bool,
    pub upload_compression: u8,
    pub download_compression: u8,
}

impl SessionState {
    pub fn new(session_id: u8, session_cookie: u8, client_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            session_cookie,
            client_addr,
            last_activity: now,
            created_at: now,
            init_token: Vec::new(),
            streams: HashMap::new(),
            closed_streams: HashMap::new(),
            main_queue: BinaryHeap::new(),
            main_queue_owner: QueueOwner::default(),
            enqueue_seq: 0,
            active_response_ids: Vec::new(),
            active_response_set: HashSet::new(),
            round_robin_idx: 0,
            upload_mtu: 200,
            download_mtu: 200,
            max_packed_blocks: 4,
            base_encode_responses: false,
            upload_compression: 0,
            download_compression: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------
pub struct ServerState {
    // Sessions
    pub sessions: Mutex<HashMap<u8, SessionState>>,
    pub recently_closed_sessions: Mutex<HashMap<u8, ClosedSessionInfo>>,
    pub free_session_ids: Mutex<VecDeque<u8>>,
    pub max_sessions: usize,

    // Core components
    pub parser: Arc<DnsPacketParser>,
    pub queue_manager: Mutex<PacketQueueManager>,

    // Network
    pub udp_sock: Mutex<Option<Arc<tokio::net::UdpSocket>>>,

    // Lifecycle
    pub should_stop: AtomicBool,

    // Config values
    pub allowed_domains: Vec<String>,
    pub allowed_domains_lower: Vec<String>,
    pub protocol_type: String,
    pub forward_ip: String,
    pub forward_port: u16,
    pub socks5_auth: bool,
    pub socks5_user: String,
    pub socks5_pass: String,
    pub use_external_socks5: bool,
    pub upload_compression: u8,
    pub download_compression: u8,
    pub compression_min_size: usize,
    pub supported_upload_compression_types: Vec<u8>,
    pub supported_download_compression_types: Vec<u8>,
    pub arq_config: ArqConfig,
    pub session_timeout_secs: f64,
    pub session_cleanup_interval: f64,
    pub stream_idle_timeout_secs: f64,
    pub socks_handshake_timeout: f64,
    pub socks_connect_semaphore: Arc<Semaphore>,
    pub max_packets_per_batch: usize,
    pub dns_request_worker_count: usize,
    pub max_concurrent_requests: usize,
    pub crypto_overhead: usize,
    pub listen_ip: String,
    pub listen_port: u16,

    // Packet type lookup tables (built once)
    pub valid_packet_types: HashSet<u8>,
    pub pre_session_packet_types: HashSet<u8>,
    pub control_ack_types: HashSet<u8>,
    pub socks5_error_ack_map: HashMap<u8, u8>,
    pub packable_control_types: HashSet<u8>,
    pub socks5_error_types: HashSet<u8>,
    pub terminal_fallback_types: HashSet<u8>,

    // Config diagnostics
    pub encrypt_key: String,
    pub encryption_method: u8,
    pub config_version: f64,
    pub min_config_version: f64,

    // Background task tracking
    pub background_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct ClosedSessionInfo {
    pub base_encode: bool,
    pub session_cookie: u8,
    pub closed_at: Instant,
}

impl ServerState {
    pub fn is_stopping(&self) -> bool {
        self.should_stop.load(Ordering::Relaxed)
    }
}
