// MasterDnsVPN Client - Application Lifecycle
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, Semaphore};

use crate::dns_utils::arq::ArqConfig;
use crate::dns_utils::compression::normalize_compression_type;
use crate::dns_utils::config_loader::{load_config, TomlValueExt};
use crate::dns_utils::dns_balancer::{BalancerStrategy, DNSBalancer};
use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueOwner};
use crate::dns_utils::ping_manager::PingManager;
use crate::dns_utils::utils;

use super::config;
use super::connection;
use super::health;
use super::mtu;
use super::queue;
use super::recommendations;
use super::retransmit;
use super::rx;
use super::session;
use super::socks5;
use super::state::{ClientState, StreamData};
use super::stream;
use super::tx;

// ---------------------------------------------------------------------------
// Client entry point
// ---------------------------------------------------------------------------

pub async fn run() {
    let cfg = load_config(config::DEFAULT_CONFIG_FILE);
    if cfg.is_empty() {
        eprintln!(
            "Error: Configuration file '{}' not found or empty.",
            config::DEFAULT_CONFIG_FILE
        );
        eprintln!(
            "Hint: Copy 'client_config.toml.simple' to '{}' and edit it.",
            config::DEFAULT_CONFIG_FILE
        );
        std::process::exit(1);
    }

    let state = build_client_state(&cfg);

    // Handle Ctrl+C (mirrors Python _signal_handler)
    let state_ctrlc = state.clone();
    ctrlc::set_handler(move || {
        if !state_ctrlc.running.load(Ordering::Relaxed) {
            tracing::warn!("Force quitting immediately due to repeated signal.");
            std::process::exit(0);
        }
        tracing::warn!("Stopping operations... (Press CTRL+C again to force quit)");
        state_ctrlc.running.store(false, Ordering::SeqCst);
        state_ctrlc.session_restart.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // --- Welcome Banner (mirrors Python start()) ---
    tracing::info!("{}", "=".repeat(60));
    tracing::info!("Starting MasterDnsVPN Client...");
    tracing::info!("Build Version: {}", config::BUILD_VERSION);
    tracing::info!("GitHub: https://github.com/masterking32/MasterDnsVPN");
    tracing::info!("Telegram: @MasterDnsVPN");
    tracing::info!("{}", "=".repeat(60));

    if state.domains.is_empty() {
        tracing::error!("Domains or Resolvers are missing in config.");
        return;
    }

    // --- Main reconnect loop (mirrors Python start() while loop) ---
    state.success_mtu_checks.store(false, Ordering::SeqCst);

    while state.running.load(Ordering::Relaxed) {
        tracing::info!("{}", "=".repeat(60));
        state.session_restart.store(false, Ordering::SeqCst);
        state.session_established.store(false, Ordering::SeqCst);
        state.session_id.store(0, Ordering::SeqCst);

        // --- run_client() logic (mirrors Python run_client) ---
        // Reset tunnel runtime state (mirrors Python _reset_tunnel_runtime_state)
        state.count_ping.store(0, Ordering::Relaxed);
        state.enqueue_seq.store(0, Ordering::Relaxed);
        state.round_robin_stream_id.store(0, Ordering::Relaxed);
        state.last_stream_id.store(0, Ordering::Relaxed);
        state.session_cookie.store(0, Ordering::SeqCst);
        {
            let mut mq = state.main_queue.lock().await;
            mq.clear();
        }
        {
            let mut ids = state.active_response_ids.lock().await;
            ids.clear();
        }
        {
            let mut rset = state.active_response_set.lock().await;
            rset.clear();
        }
        {
            let mut streams = state.active_streams.lock().await;
            streams.clear();
        }
        {
            let mut closed = state.closed_streams.lock().await;
            closed.clear();
        }
        {
            let mut sc = state.server_send_counts.lock().await;
            sc.clear();
        }

        tracing::info!("Setting up connections...");

        if !state.success_mtu_checks.load(Ordering::Relaxed) {
            // Build connection map
            connection::create_connection_map(&state).await;
            let all_resolvers = {
                let conn_map = state.connection_map.lock().await;
                conn_map.len()
            };

            // Config recommendations (mirrors Python: called at start of test_mtu_sizes)
            recommendations::config_recommendations(&state).await;

            // MTU testing for all connections
            match mtu::test_mtu_sizes(&state).await {
                Some(_r) => {},
                None => {
                    tracing::error!("No valid servers found to connect.");
                    if !state.running.load(Ordering::Relaxed) {
                        break;
                    }
                    tracing::warn!("Restarting Client workflow in 2 seconds...");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            // Collect valid connections and compute synced MTU
            let (valid_conns, synced_up_mtu, synced_up_chars, synced_down_mtu) = {
                let conn_map = state.connection_map.lock().await;
                let valid: Vec<_> = conn_map.iter().filter(|c| c.is_valid).cloned().collect();
                if valid.is_empty() {
                    (vec![], 0usize, 0usize, 0usize)
                } else {
                let min_up = valid.iter().map(|c| c.upload_mtu_bytes).min().unwrap_or(0);
                let min_up_chars = valid.iter().map(|c| c.upload_mtu_chars).min().unwrap_or(0);
                let min_down = valid.iter().map(|c| c.download_mtu_bytes).min().unwrap_or(0);
                (valid, min_up, min_up_chars, min_down)
                }
            };

            if valid_conns.is_empty() {
                tracing::error!("No valid connections found after MTU testing!");
                if !state.running.load(Ordering::Relaxed) {
                    break;
                }
                tracing::warn!("Restarting Client workflow in 2 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }

            // Update balancer with valid connections
            {
                let mut bal = state.balancer.lock().await;
                let valid_keys: Vec<String> = valid_conns.iter().map(|c| c.key.clone()).collect();
                bal.set_valid_servers(&valid_keys);
            }

            // Store synced MTU values
            state.upload_mtu_bytes.store(synced_up_mtu, Ordering::SeqCst);
            state.upload_mtu_chars.store(synced_up_chars, Ordering::SeqCst);
            state.synced_upload_mtu_chars.store(synced_up_chars, Ordering::SeqCst);
            state.download_mtu_bytes.store(synced_down_mtu, Ordering::SeqCst);

            let safe_uplink = synced_up_mtu.saturating_sub(state.crypto_overhead).max(64);
            state.safe_uplink_mtu.store(safe_uplink, Ordering::SeqCst);

            let max_up = valid_conns.iter().map(|c| c.upload_mtu_bytes).max().unwrap_or(0);
            let max_down = valid_conns.iter().map(|c| c.download_mtu_bytes).max().unwrap_or(0);

            // --- MTU results table (mirrors Python run_client logging) ---
            tracing::info!("MTU Testing Completed!");
            tracing::info!("{}", "=".repeat(80));
            tracing::info!("Valid Connections After MTU Testing:");
            tracing::info!("{}", "=".repeat(80));
            tracing::info!(
                "{:<20} {:<15} {:<15} {:<30}",
                "Resolver", "Upload MTU", "Download MTU", "Domain"
            );
            tracing::info!("{}", "-".repeat(80));
            for conn in &valid_conns {
                tracing::info!(
                    "{:<20} {:<15} {:<15} {:<30}",
                    conn.resolver, conn.upload_mtu_bytes, conn.download_mtu_bytes, conn.domain
                );
            }
            tracing::info!("{}", "=".repeat(80));
            tracing::info!(
                "Total valid resolvers after MTU testing: {} of {}",
                valid_conns.len(),
                all_resolvers
            );
            tracing::info!(
                "Note: Each packet will be sent {} times to improve reliability.",
                state.packet_duplication_count
            );
            tracing::info!("{}", "=".repeat(80));
            tracing::info!(
                "[MTU RESULTS] Max Upload MTU found: {} | Max Download MTU found: {}",
                max_up, max_down
            );
            tracing::info!(
                "[MTU RESULTS] Selected Synced Upload MTU: {} | Selected Synced Download MTU: {}",
                synced_up_mtu, synced_down_mtu
            );
            tracing::info!("{}", "=".repeat(80));
            tracing::info!(
                "Global MTU Configuration -> Upload: {}, Download: {}",
                synced_up_mtu, synced_down_mtu
            );

            state.success_mtu_checks.store(true, Ordering::SeqCst);
        }

        // Get best server to confirm availability
        {
            let mut bal = state.balancer.lock().await;
            if bal.get_best_server().is_none() {
                tracing::error!("No active servers available from Balancer.");
                drop(bal);
                if !state.running.load(Ordering::Relaxed) {
                    break;
                }
                tracing::warn!("Restarting Client workflow in 2 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        }

        // Apply session compression policy (mirrors Python _apply_session_compression_policy)
        recommendations::apply_session_compression_policy(&state);

        // Session init (mirrors Python _init_session)
        let max_attempts = cfg.get_i64_or("MAX_CONNECTION_ATTEMPTS", 10) as u32;
        match session::init_session(&state, max_attempts).await {
            Ok(()) => {
                tracing::info!(
                    "Session Established! Session ID: {}",
                    state.session_id.load(Ordering::Relaxed)
                );
                state.session_established.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                tracing::error!("Failed to initialize session with the server: {}", e);
                if !state.running.load(Ordering::Relaxed) {
                    break;
                }
                tracing::warn!("Restarting Client workflow in 2 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        }

        // Sync MTU with server (mirrors Python _sync_mtu_with_server)
        if let Err(e) = mtu::sync_mtu_with_server(&state).await {
            tracing::error!("Failed to sync MTU with the server: {}", e);
            if !state.running.load(Ordering::Relaxed) {
                break;
            }
            tracing::warn!("Restarting Client workflow in 2 seconds...");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        }

        // Enter tunnel main loop
        run_tunnel_loop(&state).await;

        // Cleanup after disconnect
        stream::clear_runtime_state(&state).await;

        if !state.running.load(Ordering::Relaxed) {
            break;
        }
        tracing::warn!("Restarting Client workflow in 2 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// ---------------------------------------------------------------------------
// Build ClientState from config
// ---------------------------------------------------------------------------

fn build_client_state(cfg: &HashMap<String, toml::Value>) -> Arc<ClientState> {
    let protocol_type = cfg.get_str_or("PROTOCOL_TYPE", "SOCKS5");
    let domains = cfg.get_string_array("DOMAINS");
    if domains.is_empty() {
        eprintln!("Error: DOMAINS must be set in config.");
        std::process::exit(1);
    }

    let encryption_method = cfg.get_i64_or("DATA_ENCRYPTION_METHOD", 1) as u8;
    let encryption_key_cfg = cfg.get_str_or("ENCRYPTION_KEY", "");
    let encryption_key = if encryption_key_cfg.is_empty() {
        utils::get_encrypt_key(encryption_method)
    } else {
        encryption_key_cfg
    };

    let listen_ip = cfg.get_str_or("LISTEN_IP", "0.0.0.0");
    let listen_port = cfg.get_i64_or("LISTEN_PORT", 1080) as u16;
    let socks5_auth = cfg.get_bool_or("SOCKS5_AUTH", false);
    let socks5_user = cfg.get_str_or("SOCKS5_USER", "");
    let socks5_pass = cfg.get_str_or("SOCKS5_PASS", "");

    let upload_comp = normalize_compression_type(
        cfg.get_i64_or("UPLOAD_COMPRESSION_TYPE", 0) as u8,
    );
    let download_comp = normalize_compression_type(
        cfg.get_i64_or("DOWNLOAD_COMPRESSION_TYPE", 0) as u8,
    );
    let compression_min_size = cfg.get_i64_or("COMPRESSION_MIN_SIZE", 64) as usize;

    let packet_dup = (cfg.get_i64_or("PACKET_DUPLICATION_COUNT", 2) as usize).max(1);
    let socks_handshake_timeout = cfg.get_f64_or("SOCKS_HANDSHAKE_TIMEOUT", 300.0);

    let arq_window = cfg.get_i64_or("ARQ_WINDOW_SIZE", 1000) as usize;
    let arq_rto = cfg.get_f64_or("ARQ_INITIAL_RTO", 0.5);
    let arq_max_rto = cfg.get_f64_or("ARQ_MAX_RTO", 3.0);
    let arq_ctrl_rto = cfg.get_f64_or("ARQ_CONTROL_INITIAL_RTO", 0.5);
    let arq_ctrl_max_rto = cfg.get_f64_or("ARQ_CONTROL_MAX_RTO", 3.0);
    let arq_ctrl_retries = cfg.get_i64_or("ARQ_CONTROL_MAX_RETRIES", 80) as u32;

    let num_rx_workers = cfg.get_i64_or("NUM_RX_WORKERS", 2) as usize;
    let rx_sem_limit = cfg.get_i64_or("RX_SEMAPHORE_LIMIT", 500) as usize;
    let max_packed_blocks = cfg.get_i64_or("MAX_PACKETS_PER_BATCH", 100) as usize;
    let log_level = cfg.get_str_or("LOG_LEVEL", "INFO");

    let min_upload_mtu = cfg.get_i64_or("MIN_UPLOAD_MTU", 0) as usize;
    let max_upload_mtu = cfg.get_i64_or("MAX_UPLOAD_MTU", 512) as usize;
    let min_download_mtu = cfg.get_i64_or("MIN_DOWNLOAD_MTU", 0) as usize;
    let max_download_mtu = cfg.get_i64_or("MAX_DOWNLOAD_MTU", 1200) as usize;
    let mtu_test_retries = cfg.get_i64_or("MTU_TEST_RETRIES", 3) as usize;
    let mtu_test_timeout = cfg.get_f64_or("MTU_TEST_TIMEOUT", 3.0);
    let mtu_test_parallelism = cfg.get_i64_or("MTU_TEST_PARALLELISM", 5) as usize;
    let base_encode_responses = cfg.get_bool_or("BASE_ENCODE_RESPONSES", false);
    let crypto_overhead = cfg.get_i64_or("CRYPTO_OVERHEAD", 32) as usize;
    let resolver_balancing_strategy = cfg.get_i64_or("RESOLVER_BALANCING_STRATEGY", 2) as u32;

    utils::init_logger(&log_level, None, 0, 0, false);

    tracing::info!("Protocol: {}", protocol_type);
    tracing::info!("Domains: {:?}", domains);
    tracing::info!("Encryption: method={}", encryption_method);
    tracing::info!("Listen: {}:{}", listen_ip, listen_port);
    tracing::info!("Compression: up={}, down={}", upload_comp, download_comp);

    let parser = Arc::new(DnsPacketParser::new(&encryption_key, encryption_method));

    let (mtu_chars, mtu_bytes) = parser.calculate_upload_mtu(&domains[0], 0);
    tracing::info!("Upload MTU: {} chars, {} bytes", mtu_chars, mtu_bytes);

    let resolvers = connection::load_resolvers(cfg, &domains);
    if resolvers.is_empty() {
        eprintln!("Error: No valid resolvers found.");
        std::process::exit(1);
    }
    tracing::info!("Loaded {} resolver(s)", resolvers.len());

    let strategy = BalancerStrategy::from(resolver_balancing_strategy as i64);
    let balancer = DNSBalancer::new(resolvers, strategy);

    let arq_config = ArqConfig {
        window_size: arq_window,
        rto: arq_rto,
        max_rto: arq_max_rto,
        is_socks: protocol_type == "SOCKS5",
        enable_control_reliability: true,
        control_rto: arq_ctrl_rto,
        control_max_rto: arq_ctrl_max_rto,
        control_max_retries: arq_ctrl_retries,
        ..ArqConfig::default()
    };

    Arc::new(ClientState {
        session_id: AtomicU16::new(0),
        session_cookie: AtomicU16::new(0),
        session_established: AtomicBool::new(false),
        session_restart: AtomicBool::new(false),
        upload_mtu_chars: AtomicUsize::new(mtu_chars),
        upload_mtu_bytes: AtomicUsize::new(mtu_bytes),
        download_mtu_bytes: AtomicUsize::new(200),
        synced_upload_mtu_chars: AtomicUsize::new(mtu_chars),
        safe_uplink_mtu: AtomicUsize::new(mtu_bytes),
        success_mtu_checks: AtomicBool::new(false),
        active_streams: Mutex::new(HashMap::new()),
        closed_streams: Mutex::new(HashMap::new()),
        last_stream_id: AtomicU16::new(0),
        running: AtomicBool::new(true),
        total_upload: AtomicU64::new(0),
        total_download: AtomicU64::new(0),
        parser,
        balancer: Mutex::new(balancer),
        tunnel_sock: Mutex::new(None),
        connection_map: Mutex::new(Vec::new()),
        domains,
        protocol_type,
        socks5_auth,
        socks5_user,
        socks5_pass,
        upload_compression: upload_comp,
        download_compression: download_comp,
        compression_min_size,
        packet_duplication_count: packet_dup,
        socks_handshake_timeout,
        arq_config,
        num_rx_workers,
        rx_semaphore: Arc::new(Semaphore::new(rx_sem_limit)),
        listen_ip,
        listen_port,
        queue_manager: Mutex::new(PacketQueueManager::new()),
        main_queue: Mutex::new(BinaryHeap::new()),
        main_queue_owner: Mutex::new(QueueOwner::default()),
        tx_notify: Arc::new(Notify::new()),
        enqueue_seq: AtomicU32::new(0),
        active_response_ids: Mutex::new(Vec::new()),
        active_response_set: Mutex::new(HashSet::new()),
        round_robin_stream_id: AtomicU16::new(0),
        count_ping: AtomicU32::new(0),
        max_packed_blocks,
        max_closed_stream_records: 500,
        control_request_ack_map: config::control_request_ack_map(),
        control_ack_types: config::control_ack_types(),
        socks5_error_types: config::socks5_error_packet_types(),
        socks5_error_reply_map: config::socks5_error_reply_map(),
        packable_control_types: config::packable_control_types(),
        pre_session_packet_types: config::pre_session_packet_types(),
        server_send_counts: Mutex::new(HashMap::new()),
        disabled_servers: Mutex::new(HashMap::new()),
        min_upload_mtu,
        max_upload_mtu,
        min_download_mtu,
        max_download_mtu,
        mtu_test_retries,
        mtu_test_timeout,
        mtu_test_parallelism,
        base_encode_responses,
        crypto_overhead,
        recheck_batch_size: AtomicUsize::new(5),
        recheck_inactive_interval_seconds: std::sync::atomic::AtomicU64::new(30),
        recheck_server_interval_seconds: std::sync::atomic::AtomicU64::new(60),
        config_version: cfg.get_i64_or("CONFIG_VERSION", 0) as u32,
        min_config_version: 3,
        resolver_balancing_strategy,
    })
}

// ---------------------------------------------------------------------------
// Tunnel loop — spawns all workers and waits for session restart or shutdown
// (mirrors Python _run_tunnel_loop / start)
// ---------------------------------------------------------------------------

async fn run_tunnel_loop(state: &Arc<ClientState>) {
    tracing::info!("Entering VPN Tunnel Main Loop...");

    // Bind UDP tunnel socket (mirrors Python _main_tunnel_loop socket setup)
    let tunnel_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!("Failed to bind tunnel UDP socket: {}", e);
            return;
        }
    };

    // Set socket buffer sizes
    let buffer_size: usize = 8_388_608;
    utils::set_socket_buffer_size(&tunnel_sock, buffer_size);

    *state.tunnel_sock.lock().await = Some(tunnel_sock.clone());

    // Bind TCP listener
    let bind_addr = format!("{}:{}", state.listen_ip, state.listen_port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind listener on {}: {}", bind_addr, e);
            return;
        }
    };

    // Log listener info
    tracing::info!("Local listener sockets: {}", bind_addr);

    // Protocol startup message (mirrors Python _main_tunnel_loop)
    if state.protocol_type == "SOCKS5" {
        if state.socks5_auth && !state.socks5_user.is_empty() && !state.socks5_pass.is_empty() {
            tracing::info!(
                "SOCKS5 Proxy started on {} with Authentication. Username: {}",
                state.listen_port, state.socks5_user
            );
        } else {
            tracing::info!(
                "SOCKS5 Proxy started on {} without Authentication.",
                state.listen_port
            );
        }
    } else {
        tracing::info!(
            "TCP Proxy started on {} (Protocol: {})",
            state.listen_port, state.protocol_type
        );
    }

    let cpu_count = num_cpus::get();
    let num_rx = state.num_rx_workers;
    let num_tx = 4; // default
    tracing::info!(
        "Runtime CPU cores detected: {} | RX workers: {} | TX workers: {}",
        cpu_count, num_rx, num_tx
    );
    tracing::info!("Build Version: {}", config::BUILD_VERSION);
    tracing::info!("{}", "=".repeat(80));
    tracing::info!("Join our Telegram channel: @MasterDNSVPN for support and updates!");
    tracing::info!("{}", "=".repeat(80));
    tracing::info!("GitHub: https://github.com/masterking32/MasterDnsVPN");
    tracing::info!("{}", "=".repeat(80));

    // Spawn all workers
    let mut tasks = Vec::new();

    // RX workers
    for _ in 0..num_rx {
        let s = state.clone();
        let sk = tunnel_sock.clone();
        tasks.push(tokio::spawn(async move {
            rx::rx_worker(&s, &sk).await;
        }));
    }

    // TX workers
    for _ in 0..num_tx {
        let s = state.clone();
        let sk = tunnel_sock.clone();
        tasks.push(tokio::spawn(async move {
            tx::tx_worker(&s, &sk).await;
        }));
    }

    // Retransmit worker
    {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            retransmit::retransmit_worker(&s).await;
        }));
    }

    // Ping manager
    {
        let s = state.clone();
        let send_fn = {
            let s2 = s.clone();
            Arc::new(move || {
                queue::send_ping_packet(&s2);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let pm = PingManager::new(send_fn);
        tasks.push(tokio::spawn(async move {
            pm.ping_loop().await;
        }));
    }

    // Timeout guard
    {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            health::timeout_guard_worker(&s, 120.0).await;
        }));
    }

    // Inactive server recheck
    {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            health::inactive_server_recheck_worker(&s, 30.0).await;
        }));
    }

    // TCP listener — accept connections
    let s = state.clone();
    tasks.push(tokio::spawn(async move {
        accept_loop(&s, listener).await;
    }));

    // Wait for session restart or shutdown
    loop {
        if state.is_stopping() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // Cleanup (mirrors Python _main_tunnel_loop finally block)
    tracing::info!("Cleaning up tunnel resources...");
    for t in &tasks {
        t.abort();
    }
    for t in tasks {
        let _ = t.await;
    }

    // Close all active streams
    let stream_ids: Vec<u16> = {
        let streams = state.active_streams.lock().await;
        streams.keys().cloned().collect()
    };
    let is_restart = state.session_restart.load(Ordering::Relaxed);
    let close_reason = if is_restart {
        "Client Restarting"
    } else {
        "Client App Closing"
    };
    for sid in stream_ids {
        stream::close_stream(state, sid, close_reason, is_restart, false).await;
    }

    // Close tunnel socket
    *state.tunnel_sock.lock().await = None;

    tracing::info!("Cleaning up old connections before reconnecting...");
}

// ---------------------------------------------------------------------------
// TCP Accept loop
// ---------------------------------------------------------------------------

async fn accept_loop(state: &Arc<ClientState>, listener: TcpListener) {
    loop {
        if state.is_stopping() {
            break;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept()).await {
            Ok(Ok((tcp_stream, addr))) => {
                if state.session_established.load(Ordering::Relaxed) {
                    let sc = state.clone();
                    tokio::spawn(async move {
                        handle_client_connection(sc, tcp_stream, addr).await;
                    });
                }
            }
            Ok(Err(e)) => tracing::debug!("Accept error: {}", e),
            Err(_) => {} // timeout — loop to recheck
        }
    }
}

// ---------------------------------------------------------------------------
// Handle new local TCP connection (mirrors Python _handle_local_tcp_connection)
// ---------------------------------------------------------------------------

async fn handle_client_connection(
    state: Arc<ClientState>,
    mut tcp_stream: TcpStream,
    addr: std::net::SocketAddr,
) {
    let is_socks5 = state.protocol_type == "SOCKS5";
    let mut socks5_result = None;

    if is_socks5 {
        match socks5::handle_socks5_handshake(&state, &mut tcp_stream).await {
            Ok(result) => {
                socks5_result = Some(result);
            }
            Err(e) => {
                tracing::debug!("SOCKS5 handshake failed for {}: {}", addr, e);
                return;
            }
        }
    }

    let stream_id = match stream::allocate_stream_id(&state).await {
        Some(id) => id,
        None => {
            tracing::warn!("Stream ID exhausted, rejecting connection from {}", addr);
            return;
        }
    };

    tracing::info!("New local connection, assigning Stream ID: {}", stream_id);

    let handshake_event = Arc::new(Notify::new());

    // Create the stream data
    let mut sd = StreamData::new(stream_id);
    sd.handshake_event = Some(handshake_event.clone());

    if let Some(ref result) = socks5_result {
        sd.initial_payload = result.target_payload.clone();
    }

    if is_socks5 {
        // ---------------------------------------------------------------
        // SOCKS5 path (mirrors Python _stream_syn_handler)
        // Create ARQ *before* sending SYN so the SYN goes via ARQ control
        // reliability with retransmit tracking.
        // ---------------------------------------------------------------
        sd.status = "ACTIVE".to_string();

        {
            let mut streams = state.active_streams.lock().await;
            streams.insert(stream_id, sd);
        }

        // Assign preferred server connection for sticky routing
        connection::ensure_stream_preferred_connection(&state, stream_id).await;

        // Split TCP and create ARQ stream immediately (mirrors Python _stream_syn_handler)
        let (reader, writer) = tcp_stream.into_split();
        let arq = stream::create_client_arq_stream(
            &state,
            stream_id,
            reader,
            writer,
            vec![], // initial_data is empty; payload goes via SYN
            true,   // is_socks: ARQ read loop waits for socks_connected
        );

        // Store ARQ in stream data
        {
            let mut streams = state.active_streams.lock().await;
            if let Some(sd) = streams.get_mut(&stream_id) {
                sd.arq = Some(arq.clone());
            }
        }

        // Send SOCKS5_SYN via ARQ control reliability (with retransmit tracking)
        let target_payload = socks5_result
            .as_ref()
            .map(|r| r.target_payload.clone())
            .unwrap_or_default();

        arq.send_control_packet(
            PacketType::SOCKS5_SYN,
            0,
            &target_payload,
            0,
            true,
            Some(PacketType::SOCKS5_SYN_ACK),
        )
        .await;

        tracing::debug!(
            "SOCKS5 Stream {} created and queued SOCKS5_SYN chunks.",
            stream_id
        );

        // Wait for server response (SYN_ACK or error)
        let timeout = std::time::Duration::from_secs_f64(state.socks_handshake_timeout);
        match tokio::time::timeout(timeout, handshake_event.notified()).await {
            Ok(()) => {
                let streams = state.active_streams.lock().await;
                let sd_check = match streams.get(&stream_id) {
                    Some(s) => s,
                    None => {
                        tracing::debug!("Stream {} closed before handshake completion", stream_id);
                        return;
                    }
                };

                if let Some(err_ptype) = sd_check.socks_error_packet {
                    drop(streams);
                    tracing::debug!("SOCKS target rejected by server: ptype={}", err_ptype);
                    let fail_reply = socks5::build_socks5_fail_reply(
                        &state.socks5_error_reply_map,
                        err_ptype,
                    );
                    let _ = arq.write_to_local(&fail_reply).await;
                    arq.abort("SOCKS handshake failed", true).await;
                    stream::close_stream(&state, stream_id, "SOCKS5 error", true, false).await;
                    return;
                }

                if sd_check.status != "ACTIVE" {
                    drop(streams);
                    let fail_reply = socks5::build_socks5_fail_reply(
                        &state.socks5_error_reply_map,
                        PacketType::SOCKS5_CONNECT_FAIL,
                    );
                    let _ = arq.write_to_local(&fail_reply).await;
                    arq.abort("Stream not active", true).await;
                    stream::close_stream(&state, stream_id, "Stream not active", true, false)
                        .await;
                    return;
                }
                drop(streams);

                // Send SOCKS5 success reply to local app via ARQ-owned writer
                if let Some(ref result) = socks5_result {
                    let reply = socks5::build_socks5_success_reply(
                        result.atyp,
                        &result.target_addr_bytes,
                        &result.target_port_bytes,
                    );
                    if let Err(e) = arq.write_to_local(&reply).await {
                        tracing::debug!("Failed to write SOCKS5 reply: {}", e);
                        arq.abort("Failed to write SOCKS5 reply", true).await;
                        stream::close_stream(
                            &state,
                            stream_id,
                            "Local app closed before SOCKS5 reply",
                            true,
                            false,
                        )
                        .await;
                        return;
                    }
                }

                // Notify ARQ that SOCKS5 connection is established
                // (unblocks the ARQ read loop to start forwarding data)
                arq.notify_socks_connected();
            }
            Err(_) => {
                tracing::debug!(
                    "SOCKS handshake timed out for stream {} after {:.1}s",
                    stream_id,
                    state.socks_handshake_timeout
                );
                let fail_reply = socks5::build_socks5_fail_reply(
                    &state.socks5_error_reply_map,
                    PacketType::SOCKS5_UPSTREAM_UNAVAILABLE,
                );
                let _ = arq.write_to_local(&fail_reply).await;
                arq.abort("SOCKS handshake timeout", true).await;
                stream::close_stream(&state, stream_id, "SOCKS5 handshake timeout", true, false)
                    .await;
                return;
            }
        }
    } else {
        // ---------------------------------------------------------------
        // Non-SOCKS5 (TCP forward): send STREAM_SYN and wait for SYN_ACK,
        // then create ARQ after handshake completes.
        // ---------------------------------------------------------------
        {
            let mut streams = state.active_streams.lock().await;
            streams.insert(stream_id, sd);
        }

        queue::enqueue_packet(&state, 0, stream_id, 0, PacketType::STREAM_SYN, vec![]).await;

        let timeout = std::time::Duration::from_secs_f64(state.socks_handshake_timeout);
        match tokio::time::timeout(timeout, handshake_event.notified()).await {
            Ok(()) => {
                let streams = state.active_streams.lock().await;
                if let Some(sd) = streams.get(&stream_id) {
                    if sd.status != "ACTIVE" {
                        drop(streams);
                        stream::close_stream(
                            &state,
                            stream_id,
                            "Stream SYN not ACKed",
                            true,
                            false,
                        )
                        .await;
                        return;
                    }
                } else {
                    return;
                }
            }
            Err(_) => {
                stream::close_stream(&state, stream_id, "SYN timeout", true, false).await;
                return;
            }
        }

        // Setup ARQ stream on the TCP connection (non-SOCKS5 path)
        setup_arq_stream(state, tcp_stream, stream_id).await;
    }
}

// ---------------------------------------------------------------------------
// ARQ Stream Setup (mirrors Python _create_client_arq_stream wiring)
// ---------------------------------------------------------------------------

async fn setup_arq_stream(state: Arc<ClientState>, tcp_stream: TcpStream, stream_id: u16) {
    let (reader, writer) = tcp_stream.into_split();

    let initial_data = {
        let streams = state.active_streams.lock().await;
        streams
            .get(&stream_id)
            .map(|sd| sd.initial_payload.clone())
            .unwrap_or_default()
    };

    let arq = stream::create_client_arq_stream(&state, stream_id, reader, writer, initial_data, false);

    // Store ARQ in stream data
    let mut streams = state.active_streams.lock().await;
    if let Some(sd) = streams.get_mut(&stream_id) {
        sd.arq = Some(arq);
        if sd.status == "PENDING" {
            sd.status = "ACTIVE".to_string();
        }
    }

    tracing::debug!("Stream {} ARQ established", stream_id);
}
