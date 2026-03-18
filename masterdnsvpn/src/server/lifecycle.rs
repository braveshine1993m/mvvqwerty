// MasterDnsVPN Server - Application Lifecycle
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};

use crate::dns_utils::arq::ArqConfig;
use crate::dns_utils::compression::normalize_compression_type;
use crate::dns_utils::config_loader::{load_config, TomlValueExt};
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::packet_queue::PacketQueueManager;
use crate::dns_utils::utils;

use super::config;
use super::dns_handler;
use super::retransmit;
use super::session;
use super::state::ServerState;

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub async fn run() {
    println!("MasterDnsVPN Server v{}", config::BUILD_VERSION);
    println!("Loading configuration...");

    let cfg = load_config(config::DEFAULT_CONFIG_FILE);
    if cfg.is_empty() {
        eprintln!(
            "Error: Configuration file '{}' not found or empty.",
            config::DEFAULT_CONFIG_FILE
        );
        eprintln!(
            "Hint: Copy 'server_config.toml.simple' to '{}' and edit it.",
            config::DEFAULT_CONFIG_FILE
        );
        std::process::exit(1);
    }

    let state = build_server_state(&cfg);

    // Handle Ctrl+C
    let state_ctrlc = state.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Shutting down...");
        state_ctrlc.should_stop.store(true, Ordering::SeqCst);
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // Bind UDP socket
    let bind_addr = format!("{}:{}", state.listen_ip, state.listen_port);
    let udp_sock = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!("Failed to bind UDP socket on {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };

    // Set socket buffer sizes
    utils::set_socket_buffer_sizes(&udp_sock, 4 * 1024 * 1024, 4 * 1024 * 1024);

    *state.udp_sock.lock().await = Some(udp_sock.clone());
    tracing::info!("Listening on {} (UDP)", bind_addr);

    // Start background workers
    let mut tasks = Vec::new();

    // Session cleanup loop
    {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            session::session_cleanup_loop(&s).await;
        }));
    }

    // Retransmit loop
    {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            retransmit::server_retransmit_loop(&s).await;
        }));
    }

    // DNS request workers
    let worker_count = state.dns_request_worker_count.max(1);
    let request_semaphore = Arc::new(Semaphore::new(state.max_concurrent_requests));

    for _ in 0..worker_count {
        let s = state.clone();
        let sock = udp_sock.clone();
        let sem = request_semaphore.clone();
        tasks.push(tokio::spawn(async move {
            dns_receive_loop(&s, &sock, &sem).await;
        }));
    }

    tracing::info!(
        "Server started with {} DNS worker(s), max {} concurrent requests",
        worker_count,
        state.max_concurrent_requests
    );

    // Wait for shutdown
    loop {
        if state.is_stopping() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Cancel all background tasks
    for t in tasks {
        t.abort();
    }

    // Close all sessions
    stop_server(&state).await;
}

// ---------------------------------------------------------------------------
// DNS Receive Loop (mirrors Python handle_dns_requests)
// ---------------------------------------------------------------------------

async fn dns_receive_loop(
    state: &Arc<ServerState>,
    sock: &Arc<UdpSocket>,
    semaphore: &Arc<Semaphore>,
) {
    let mut buf = vec![0u8; 65535];

    while !state.is_stopping() {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sock.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, addr))) => {
                if n < 12 {
                    continue;
                }

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // At capacity — drop the request
                        continue;
                    }
                };

                let data = buf[..n].to_vec();
                let s = state.clone();
                tokio::spawn(async move {
                    dns_handler::handle_single_request(&s, &data, addr).await;
                    drop(permit);
                });
            }
            Ok(Err(e)) => {
                if !state.is_stopping() {
                    tracing::debug!("UDP recv error: {}", e);
                }
            }
            Err(_) => {} // timeout — loop to recheck
        }
    }
}

// ---------------------------------------------------------------------------
// Build ServerState from config
// ---------------------------------------------------------------------------

fn build_server_state(cfg: &HashMap<String, toml::Value>) -> Arc<ServerState> {
    let allowed_domains = {
        let d = cfg.get_string_array("DOMAIN");
        if d.is_empty() { cfg.get_string_array("DOMAINS") } else { d }
    };
    if allowed_domains.is_empty() {
        eprintln!("Error: DOMAINS must be set in config.");
        std::process::exit(1);
    }
    let allowed_domains_lower: Vec<String> =
        allowed_domains.iter().map(|d| d.to_lowercase()).collect();

    let encryption_method = cfg.get_i64_or("DATA_ENCRYPTION_METHOD", 1) as u8;
    let encryption_key_cfg = cfg.get_str_or("ENCRYPTION_KEY", "");
    let encryption_key = if encryption_key_cfg.is_empty() {
        utils::get_encrypt_key(encryption_method)
    } else {
        encryption_key_cfg
    };

    let listen_ip = cfg.get_str_or("UDP_HOST", "0.0.0.0");
    let listen_port = cfg.get_i64_or("UDP_PORT", 53) as u16;

    let protocol_type = cfg.get_str_or("PROTOCOL_TYPE", "SOCKS5");
    let forward_ip = cfg.get_str_or("FORWARD_IP", "127.0.0.1");
    let forward_port = cfg.get_i64_or("FORWARD_PORT", 1080) as u16;

    let socks5_auth = cfg.get_bool_or("SOCKS5_AUTH", false);
    let socks5_user = cfg.get_str_or("SOCKS5_USER", "");
    let socks5_pass = cfg.get_str_or("SOCKS5_PASS", "");
    let use_external_socks5 = cfg.get_bool_or("USE_EXTERNAL_SOCKS5", false);

    let upload_comp = normalize_compression_type(
        cfg.get_i64_or("UPLOAD_COMPRESSION_TYPE", 0) as u8,
    );
    let download_comp = normalize_compression_type(
        cfg.get_i64_or("DOWNLOAD_COMPRESSION_TYPE", 0) as u8,
    );
    let compression_min_size = cfg.get_i64_or("COMPRESSION_MIN_SIZE", 64) as usize;

    let supported_upload_comp: Vec<u8> = {
        let arr = cfg.get_i64_array("SUPPORTED_UPLOAD_COMPRESSION_TYPES");
        if arr.is_empty() { vec![0, 1, 2, 3] } else { arr.iter().map(|&v| v as u8).collect() }
    };
    let supported_download_comp: Vec<u8> = {
        let arr = cfg.get_i64_array("SUPPORTED_DOWNLOAD_COMPRESSION_TYPES");
        if arr.is_empty() { vec![0, 1, 2, 3] } else { arr.iter().map(|&v| v as u8).collect() }
    };

    let max_sessions = cfg.get_i64_or("MAX_SESSIONS", 255) as usize;
    let session_timeout = cfg.get_f64_or("SESSION_TIMEOUT", 300.0);
    let stream_idle_timeout = cfg.get_f64_or("STREAM_IDLE_TIMEOUT", 120.0);
    let socks_handshake_timeout = cfg.get_f64_or("SOCKS_HANDSHAKE_TIMEOUT", 180.0);

    let arq_window = cfg.get_i64_or("ARQ_WINDOW_SIZE", 1000) as usize;
    let arq_rto = cfg.get_f64_or("ARQ_INITIAL_RTO", 0.5);
    let arq_max_rto = cfg.get_f64_or("ARQ_MAX_RTO", 3.0);
    let arq_ctrl_rto = cfg.get_f64_or("ARQ_CONTROL_INITIAL_RTO", 0.5);
    let arq_ctrl_max_rto = cfg.get_f64_or("ARQ_CONTROL_MAX_RTO", 3.0);
    let arq_ctrl_retries = cfg.get_i64_or("ARQ_CONTROL_MAX_RETRIES", 80) as u32;

    let dns_worker_count = cfg.get_i64_or("DNS_REQUEST_WORKERS", 4) as usize;
    let max_concurrent = cfg.get_i64_or("MAX_CONCURRENT_REQUESTS", 1000) as usize;
    let max_packets_per_batch = cfg.get_i64_or("MAX_PACKETS_PER_BATCH", 1000) as usize;
    let socks_concurrency = cfg.get_i64_or("MAX_CONCURRENT_SOCKS_CONNECTS", 16) as usize;

    let log_level = cfg.get_str_or("LOG_LEVEL", "INFO");
    utils::init_logger(&log_level, None, 0, 0, false);

    tracing::info!("Protocol: {}", protocol_type);
    tracing::info!("Domains: {:?}", allowed_domains);
    tracing::info!("Encryption: method={}", encryption_method);
    tracing::info!("Listen: {}:{}", listen_ip, listen_port);

    let parser = Arc::new(DnsPacketParser::new(&encryption_key, encryption_method));
    let crypto_overhead = parser.get_max_vpn_header_raw_size() + 32;

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

    Arc::new(ServerState {
        sessions: Mutex::new(HashMap::new()),
        recently_closed_sessions: Mutex::new(HashMap::new()),
        max_sessions,
        parser,
        queue_manager: Mutex::new(PacketQueueManager::new()),
        udp_sock: Mutex::new(None),
        should_stop: AtomicBool::new(false),
        allowed_domains,
        allowed_domains_lower,
        protocol_type,
        forward_ip,
        forward_port,
        socks5_auth,
        socks5_user,
        socks5_pass,
        use_external_socks5,
        upload_compression: upload_comp,
        download_compression: download_comp,
        compression_min_size,
        supported_upload_compression_types: supported_upload_comp,
        supported_download_compression_types: supported_download_comp,
        arq_config,
        session_timeout_secs: session_timeout,
        stream_idle_timeout_secs: stream_idle_timeout,
        socks_handshake_timeout,
        socks_connect_semaphore: Arc::new(Semaphore::new(socks_concurrency)),
        max_packets_per_batch,
        dns_request_worker_count: dns_worker_count,
        max_concurrent_requests: max_concurrent,
        crypto_overhead,
        listen_ip,
        listen_port,
        valid_packet_types: config::valid_packet_types(),
        pre_session_packet_types: config::pre_session_packet_types(),
        control_ack_types: config::control_ack_types(),
        socks5_error_ack_map: config::socks5_error_ack_map(),
        packable_control_types: config::packable_control_types(),
        socks5_error_types: config::socks5_error_packet_types(),
        terminal_fallback_types: config::terminal_fallback_packet_types(),
        background_tasks: Mutex::new(Vec::new()),
    })
}

// ---------------------------------------------------------------------------
// Stop server (mirrors Python stop)
// ---------------------------------------------------------------------------

async fn stop_server(state: &Arc<ServerState>) {
    tracing::info!("Stopping server...");
    state.should_stop.store(true, Ordering::SeqCst);

    // Close all sessions
    let session_ids: Vec<u8> = {
        let sessions = state.sessions.lock().await;
        sessions.keys().cloned().collect()
    };

    for sid in session_ids {
        session::close_session(state, sid).await;
    }

    tracing::info!("Server stopped.");
}
