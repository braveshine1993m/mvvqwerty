// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

use super::dns_enums::{PacketType, StreamState};

/// Pending control packet awaiting ACK.
#[derive(Debug, Clone)]
struct PendingControlPacket {
    packet_type: u8,
    sequence_num: u16,
    ack_type: u8,
    payload: Vec<u8>,
    priority: i32,
    retries: u32,
    current_rto: f64,
    time: Instant,
    create_time: Instant,
}

/// Pending data packet awaiting ACK.
#[derive(Debug)]
struct PendingDataPacket {
    data: Vec<u8>,
    time: Instant,
    create_time: Instant,
    retries: u32,
    current_rto: f64,
}

/// Callback type for enqueuing data-plane TX packets.
pub type EnqueueTxCb = Arc<
    dyn Fn(i32, u16, u16, Vec<u8>, bool, bool) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Callback type for enqueuing control-plane TX packets.
pub type EnqueueControlTxCb = Arc<
    dyn Fn(i32, u16, u16, u8, Vec<u8>, bool) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Control ACK pairs mapping.
fn control_ack_pairs() -> HashMap<u8, u8> {
    [
        (PacketType::STREAM_SYN, PacketType::STREAM_SYN_ACK),
        (PacketType::STREAM_FIN, PacketType::STREAM_FIN_ACK),
        (PacketType::STREAM_RST, PacketType::STREAM_RST_ACK),
        (PacketType::SOCKS5_SYN, PacketType::SOCKS5_SYN_ACK),
        (PacketType::STREAM_KEEPALIVE, PacketType::STREAM_KEEPALIVE_ACK),
        (PacketType::STREAM_WINDOW_UPDATE, PacketType::STREAM_WINDOW_UPDATE_ACK),
        (PacketType::STREAM_PROBE, PacketType::STREAM_PROBE_ACK),
        (PacketType::SOCKS5_CONNECT_FAIL, PacketType::SOCKS5_CONNECT_FAIL_ACK),
        (PacketType::SOCKS5_RULESET_DENIED, PacketType::SOCKS5_RULESET_DENIED_ACK),
        (PacketType::SOCKS5_NETWORK_UNREACHABLE, PacketType::SOCKS5_NETWORK_UNREACHABLE_ACK),
        (PacketType::SOCKS5_HOST_UNREACHABLE, PacketType::SOCKS5_HOST_UNREACHABLE_ACK),
        (PacketType::SOCKS5_CONNECTION_REFUSED, PacketType::SOCKS5_CONNECTION_REFUSED_ACK),
        (PacketType::SOCKS5_TTL_EXPIRED, PacketType::SOCKS5_TTL_EXPIRED_ACK),
        (PacketType::SOCKS5_COMMAND_UNSUPPORTED, PacketType::SOCKS5_COMMAND_UNSUPPORTED_ACK),
        (PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED, PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK),
        (PacketType::SOCKS5_AUTH_FAILED, PacketType::SOCKS5_AUTH_FAILED_ACK),
        (PacketType::SOCKS5_UPSTREAM_UNAVAILABLE, PacketType::SOCKS5_UPSTREAM_UNAVAILABLE_ACK),
    ]
    .into_iter()
    .collect()
}

/// ARQ configuration parameters.
#[derive(Debug, Clone)]
pub struct ArqConfig {
    pub window_size: usize,
    pub rto: f64,
    pub max_rto: f64,
    pub is_socks: bool,
    pub enable_control_reliability: bool,
    pub control_rto: f64,
    pub control_max_rto: f64,
    pub control_max_retries: u32,
    pub inactivity_timeout: f64,
    pub data_packet_ttl: f64,
    pub max_data_retries: u32,
    pub control_packet_ttl: f64,
    pub fin_drain_timeout: f64,
    pub graceful_drain_timeout: f64,
}

impl Default for ArqConfig {
    fn default() -> Self {
        ArqConfig {
            window_size: 600,
            rto: 0.8,
            max_rto: 1.5,
            is_socks: false,
            enable_control_reliability: false,
            control_rto: 0.8,
            control_max_rto: 2.5,
            control_max_retries: 15,
            inactivity_timeout: 1200.0,
            data_packet_ttl: 600.0,
            max_data_retries: 400,
            control_packet_ttl: 600.0,
            fin_drain_timeout: 300.0,
            graceful_drain_timeout: 600.0,
        }
    }
}

/// Inner mutable state of an ARQ stream.
struct ArqInner {
    // Sequence and buffers
    snd_nxt: u16,
    rcv_nxt: u16,
    snd_buf: HashMap<u16, PendingDataPacket>,
    rcv_buf: HashMap<u16, Vec<u8>>,
    control_snd_buf: HashMap<(u8, u16), PendingControlPacket>,

    // Stream lifecycle
    state: StreamState,
    closed: bool,
    close_reason: String,
    last_activity: Instant,

    // FIN tracking
    fin_sent: bool,
    fin_received: bool,
    fin_acked: bool,
    fin_seq_sent: Option<u16>,
    fin_seq_received: Option<u16>,

    // RST tracking
    rst_received: bool,
    rst_sent: bool,
    rst_acked: bool,
    rst_seq_sent: Option<u16>,
    rst_seq_received: Option<u16>,

    // Half-close tracking
    local_write_closed: bool,
    remote_write_closed: bool,
    stop_local_read: bool,

    // Dup ACK throttle
    last_dup_ack_sn: Option<u16>,
    last_dup_ack_time: Instant,

    // Writer for delivering received data to local TCP stream
    writer: Option<OwnedWriteHalf>,
}

/// Automatic Repeat Request for reliable data transfer over DNS.
pub struct Arq {
    pub stream_id: u16,
    pub session_id: u8,
    enqueue_tx: EnqueueTxCb,
    enqueue_control_tx: EnqueueControlTxCb,
    mtu: usize,
    config: ArqConfig,
    limit: usize,

    inner: Arc<Mutex<ArqInner>>,
    window_not_full: Arc<Notify>,
    socks_connected: Arc<Notify>,

    control_ack_map: HashMap<u8, u8>,
    control_reverse_ack_map: HashMap<u8, u8>,

    io_task: Option<JoinHandle<()>>,
    rtx_task: Option<JoinHandle<()>>,
}

impl Arq {
    pub fn new(
        stream_id: u16,
        session_id: u8,
        enqueue_tx_cb: EnqueueTxCb,
        enqueue_control_tx_cb: EnqueueControlTxCb,
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        mtu: usize,
        config: ArqConfig,
        initial_data: Vec<u8>,
    ) -> Arc<Self> {
        let window_size = config.window_size.max(1);
        let limit = (window_size as f64 * 0.8) as usize;
        let limit = limit.max(50);

        let rto = config.rto.max(0.05).min(config.max_rto.max(0.05));
        let max_rto = config.max_rto.max(0.05);
        let control_rto = config.control_rto.max(0.05).min(config.control_max_rto.max(0.05));
        let control_max_rto = config.control_max_rto.max(0.05);

        let ack_map = control_ack_pairs();
        let reverse_map: HashMap<u8, u8> = ack_map.iter().map(|(&k, &v)| (v, k)).collect();

        let now = Instant::now();
        let inner = Arc::new(Mutex::new(ArqInner {
            snd_nxt: 0,
            rcv_nxt: 0,
            snd_buf: HashMap::new(),
            rcv_buf: HashMap::new(),
            control_snd_buf: HashMap::new(),
            state: StreamState::Open,
            closed: false,
            close_reason: "Unknown".to_string(),
            last_activity: now,
            fin_sent: false,
            fin_received: false,
            fin_acked: false,
            fin_seq_sent: None,
            fin_seq_received: None,
            rst_received: false,
            rst_sent: false,
            rst_acked: false,
            rst_seq_sent: None,
            rst_seq_received: None,
            local_write_closed: false,
            remote_write_closed: false,
            stop_local_read: false,
            last_dup_ack_sn: None,
            last_dup_ack_time: now,
            writer: Some(writer),
        }));

        let window_not_full = Arc::new(Notify::new());
        let socks_connected = Arc::new(Notify::new());

        let mut effective_config = config.clone();
        effective_config.rto = rto;
        effective_config.max_rto = max_rto;
        effective_config.control_rto = control_rto;
        effective_config.control_max_rto = control_max_rto;
        effective_config.inactivity_timeout = config.inactivity_timeout.max(120.0);
        effective_config.data_packet_ttl = config.data_packet_ttl.max(120.0);
        effective_config.max_data_retries = config.max_data_retries.max(20);
        effective_config.fin_drain_timeout = config.fin_drain_timeout.max(30.0);
        effective_config.graceful_drain_timeout = config.graceful_drain_timeout.max(60.0);
        effective_config.control_max_retries = config.control_max_retries.max(5);
        effective_config.control_packet_ttl = config.control_packet_ttl.max(120.0);

        let arq = Arc::new(Arq {
            stream_id,
            session_id,
            enqueue_tx: enqueue_tx_cb,
            enqueue_control_tx: enqueue_control_tx_cb,
            mtu,
            config: effective_config,
            limit,
            inner,
            window_not_full,
            socks_connected: socks_connected.clone(),
            control_ack_map: ack_map,
            control_reverse_ack_map: reverse_map,
            io_task: None,
            rtx_task: None,
        });

        if !arq.config.is_socks {
            arq.socks_connected.notify_one();
        }

        // Spawn IO and retransmit tasks
        let arq_io = arq.clone();
        let arq_rtx = arq.clone();

        let io_handle = tokio::spawn(async move {
            arq_io.io_loop(reader, initial_data).await;
        });

        let rtx_handle = tokio::spawn(async move {
            arq_rtx.retransmit_loop().await;
        });

        // Store task handles (needs unsafe or interior mutability pattern)
        // For simplicity, we let tasks run independently and clean up via closed flag.
        let _ = io_handle;
        let _ = rtx_handle;

        arq
    }

    fn norm_sn(sn: u16) -> u16 {
        sn & 0xFFFF
    }

    pub async fn is_closed(&self) -> bool {
        self.inner.lock().await.closed
    }

    pub async fn is_reset(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.state == StreamState::Reset || inner.rst_received || inner.rst_sent
    }

    // -------------------------------------------------------------------------
    // IO Loop - reads from local socket, enqueues reliable outbound packets
    // -------------------------------------------------------------------------
    async fn io_loop(&self, mut reader: OwnedReadHalf, initial_data: Vec<u8>) {
        let mut reset_required = false;
        let mut graceful_eof = false;
        let mut error_reason: Option<String> = None;

        // Send initial data (SOCKS pre-connection payload)
        if self.config.is_socks && !initial_data.is_empty() {
            let mut offset = 0;
            while offset < initial_data.len() {
                let inner_closed = self.inner.lock().await.closed;
                if inner_closed { return; }

                let end = (offset + self.mtu).min(initial_data.len());
                let chunk = initial_data[offset..end].to_vec();

                let sn = {
                    let mut inner = self.inner.lock().await;
                    let sn = inner.snd_nxt;
                    inner.snd_nxt = sn.wrapping_add(1);
                    let now = Instant::now();
                    inner.snd_buf.insert(sn, PendingDataPacket {
                        data: chunk.clone(),
                        time: now,
                        create_time: now,
                        retries: 0,
                        current_rto: self.config.rto,
                    });
                    sn
                };

                (self.enqueue_tx)(3, self.stream_id, sn, chunk, false, false).await;
                offset = end;
            }
        }

        // Wait for SOCKS connection
        if self.config.is_socks {
            self.socks_connected.notified().await;
        }

        // Main read loop
        let mut buf = vec![0u8; self.mtu];
        loop {
            let inner_closed = self.inner.lock().await.closed;
            if inner_closed { break; }

            // Check window
            {
                let inner = self.inner.lock().await;
                if inner.snd_buf.len() >= self.limit {
                    drop(inner);
                    self.window_not_full.notified().await;
                    continue;
                }
            }

            // Check remote FIN
            {
                let inner = self.inner.lock().await;
                if inner.stop_local_read {
                    break;
                }
                if inner.fin_received && !inner.stop_local_read {
                    // will be handled below
                }
            }

            match reader.read(&mut buf).await {
                Ok(0) => {
                    error_reason = Some("Local App Closed Connection (EOF)".to_string());
                    graceful_eof = true;
                    break;
                }
                Ok(n) => {
                    let raw_data = buf[..n].to_vec();
                    let sn = {
                        let mut inner = self.inner.lock().await;
                        inner.last_activity = Instant::now();
                        let sn = inner.snd_nxt;
                        inner.snd_nxt = sn.wrapping_add(1);
                        let now = Instant::now();
                        inner.snd_buf.insert(sn, PendingDataPacket {
                            data: raw_data.clone(),
                            time: now,
                            create_time: now,
                            retries: 0,
                            current_rto: self.config.rto,
                        });

                        if inner.snd_buf.len() >= self.limit {
                            // Window full, will wait on next iteration
                        }
                        sn
                    };

                    (self.enqueue_tx)(3, self.stream_id, sn, raw_data, false, false).await;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::ConnectionReset {
                        error_reason = Some("Local App Reset Connection (Dropped)".to_string());
                    } else {
                        error_reason = Some(format!("Read Error: {}", e));
                    }
                    reset_required = true;
                    break;
                }
            }
        }

        // Finalization
        let already_closed = self.inner.lock().await.closed;
        if already_closed {
            return;
        }

        if reset_required {
            self.abort(error_reason.as_deref().unwrap_or("Local reset/error"), true).await;
        } else {
            let fin_received = self.inner.lock().await.fin_received;
            if fin_received {
                // Drain and close
                let deadline = Instant::now() + std::time::Duration::from_secs_f64(self.config.fin_drain_timeout);
                loop {
                    let inner = self.inner.lock().await;
                    if inner.snd_buf.is_empty() || inner.closed || Instant::now() >= deadline {
                        break;
                    }
                    drop(inner);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }

                let inner = self.inner.lock().await;
                if !inner.snd_buf.is_empty() && !inner.closed {
                    drop(inner);
                    self.abort("Remote FIN received but local send buffer did not drain", true).await;
                } else if !inner.closed {
                    drop(inner);
                    self.initiate_graceful_close("Remote FIN fully handled").await;
                }
            } else if graceful_eof {
                self.initiate_graceful_close(error_reason.as_deref().unwrap_or("Local EOF")).await;
            }
        }
    }

    async fn initiate_graceful_close(&self, reason: &str) {
        {
            let mut inner = self.inner.lock().await;
            if inner.closed { return; }
            inner.close_reason = reason.to_string();
            if inner.state != StreamState::Reset && inner.state != StreamState::Closed {
                inner.state = StreamState::Draining;
            }
        }

        let deadline = Instant::now() + std::time::Duration::from_secs_f64(self.config.graceful_drain_timeout);
        loop {
            let inner = self.inner.lock().await;
            if inner.snd_buf.is_empty() || inner.closed || Instant::now() >= deadline {
                break;
            }
            drop(inner);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let inner = self.inner.lock().await;
        if inner.closed { return; }
        if !inner.snd_buf.is_empty() {
            drop(inner);
            self.abort(&format!("{} but send buffer did not drain", reason), true).await;
            return;
        }
        drop(inner);
        self.close(reason, true).await;
    }

    // -------------------------------------------------------------------------
    // Retransmit loop
    // -------------------------------------------------------------------------
    async fn retransmit_loop(&self) {
        loop {
            let closed = self.inner.lock().await.closed;
            if closed { break; }

            let base_interval = {
                let _inner = self.inner.lock().await;
                let rto = self.config.rto;
                let ctrl_rto = if self.config.enable_control_reliability {
                    self.config.control_rto
                } else {
                    rto
                };
                (rto.min(ctrl_rto) / 3.0).max(0.05)
            };

            let has_pending = {
                let inner = self.inner.lock().await;
                !inner.snd_buf.is_empty()
                    || (self.config.enable_control_reliability && !inner.control_snd_buf.is_empty())
            };

            let interval = if has_pending {
                base_interval
            } else {
                (base_interval * 4.0).max(0.2)
            };

            tokio::time::sleep(std::time::Duration::from_secs_f64(interval)).await;

            let closed = self.inner.lock().await.closed;
            if closed { break; }

            self.check_retransmits().await;
        }
    }

    // -------------------------------------------------------------------------
    // Data plane
    // -------------------------------------------------------------------------
    /// Handle inbound STREAM_DATA and emit STREAM_DATA_ACK.
    pub async fn receive_data(&self, sn: u16, data: Vec<u8>, writer: &mut OwnedWriteHalf) {
        let inner_guard = self.inner.lock().await;
        if inner_guard.closed || inner_guard.state == StreamState::Reset
            || inner_guard.rst_received || inner_guard.rst_sent
        {
            return;
        }
        drop(inner_guard);

        let sn = Self::norm_sn(sn);

        {
            let mut inner = self.inner.lock().await;
            inner.last_activity = Instant::now();

            let diff = sn.wrapping_sub(inner.rcv_nxt);
            if diff >= 32768 {
                // Dup ACK throttle
                let now = Instant::now();
                let rto = self.config.rto;
                let ack_throttle = rto.min(0.3).max(0.05);
                let should_ack = inner.last_dup_ack_sn != Some(sn)
                    || now.duration_since(inner.last_dup_ack_time).as_secs_f64() >= ack_throttle;

                if should_ack {
                    inner.last_dup_ack_sn = Some(sn);
                    inner.last_dup_ack_time = now;
                    drop(inner);
                    (self.enqueue_tx)(0, self.stream_id, sn, Vec::new(), true, false).await;
                }
                return;
            }

            if diff as usize > self.config.window_size {
                return;
            }

            // Hard cap reordering buffer
            if !inner.rcv_buf.contains_key(&sn) && inner.rcv_buf.len() >= self.config.window_size {
                return;
            }

            inner.rcv_buf.entry(sn).or_insert(data);

            // Deliver in-order data
            let mut data_to_write = Vec::new();
            loop {
                let nxt = inner.rcv_nxt;
                if let Some(d) = inner.rcv_buf.remove(&nxt) {
                    data_to_write.push(d);
                    inner.rcv_nxt = nxt.wrapping_add(1);
                } else {
                    break;
                }
            }
            drop(inner);

            if !data_to_write.is_empty() {
                let combined: Vec<u8> = data_to_write.into_iter().flatten().collect();
                if let Err(e) = writer.write_all(&combined).await {
                    tracing::debug!("Stream {} writer error: {}", self.stream_id, e);
                    self.abort(&format!("Writer Error: {}", e), true).await;
                    return;
                }
            }
        }

        (self.enqueue_tx)(0, self.stream_id, sn, Vec::new(), true, false).await;

        // Try finalize remote EOF
        self.try_finalize_remote_eof(writer).await;
    }

    /// Handle inbound STREAM_DATA_ACK.
    pub async fn receive_ack(&self, sn: u16) {
        let sn = Self::norm_sn(sn);
        let mut inner = self.inner.lock().await;
        inner.last_activity = Instant::now();
        if inner.snd_buf.remove(&sn).is_some() {
            if inner.snd_buf.len() < self.limit {
                self.window_not_full.notify_one();
            }
        }
    }

    async fn try_finalize_remote_eof(&self, _writer: &mut OwnedWriteHalf) {
        let mut inner = self.inner.lock().await;
        if inner.closed || inner.remote_write_closed || !inner.fin_received {
            return;
        }
        if let Some(fin_seq) = inner.fin_seq_received {
            if inner.rcv_nxt != fin_seq {
                return;
            }
        } else {
            return;
        }

        inner.remote_write_closed = true;
        let fin_seq = inner.fin_seq_received.unwrap();
        drop(inner);

        // Send FIN_ACK
        self.send_control_packet(
            PacketType::STREAM_FIN_ACK, fin_seq, &[], 0, false, None,
        ).await;

        let inner = self.inner.lock().await;
        if inner.fin_sent && inner.fin_acked && inner.snd_buf.is_empty() {
            drop(inner);
            self.close("Both FIN sides fully acknowledged", false).await;
        }
    }

    // -------------------------------------------------------------------------
    // Control plane
    // -------------------------------------------------------------------------
    async fn send_control_frame(
        &self,
        packet_type: u8,
        sequence_num: u16,
        payload: &[u8],
        priority: i32,
        is_retransmit: bool,
    ) -> bool {
        let sn = Self::norm_sn(sequence_num);
        (self.enqueue_control_tx)(
            priority,
            self.stream_id,
            sn,
            packet_type,
            payload.to_vec(),
            is_retransmit,
        ).await;
        true
    }

    pub async fn send_control_packet(
        &self,
        packet_type: u8,
        sequence_num: u16,
        payload: &[u8],
        priority: i32,
        track_for_ack: bool,
        ack_type: Option<u8>,
    ) -> bool {
        let sn = Self::norm_sn(sequence_num);

        let sent = self.send_control_frame(packet_type, sn, payload, priority, false).await;
        if !sent { return false; }

        if !(self.config.enable_control_reliability && track_for_ack) {
            return true;
        }

        let expected_ack = ack_type.or_else(|| self.control_ack_map.get(&packet_type).copied());
        if expected_ack.is_none() {
            return true;
        }

        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        let key = (packet_type, sn);
        if !inner.control_snd_buf.contains_key(&key) {
            inner.control_snd_buf.insert(key, PendingControlPacket {
                packet_type,
                sequence_num: sn,
                ack_type: expected_ack.unwrap(),
                payload: payload.to_vec(),
                priority,
                retries: 0,
                current_rto: self.config.control_rto,
                time: now,
                create_time: now,
            });
        }

        true
    }

    pub async fn receive_control_ack(&self, ack_packet_type: u8, sequence_num: u16) -> bool {
        let sn = Self::norm_sn(sequence_num);
        {
            let mut inner = self.inner.lock().await;
            inner.last_activity = Instant::now();

            if ack_packet_type == PacketType::STREAM_FIN_ACK {
                if let Some(fin_seq) = inner.fin_seq_sent {
                    if sn == fin_seq {
                        inner.fin_acked = true;
                    }
                }
                if inner.fin_received {
                    inner.state = StreamState::Closing;
                }
            } else if ack_packet_type == PacketType::STREAM_RST_ACK {
                if let Some(rst_seq) = inner.rst_seq_sent {
                    if sn == rst_seq {
                        inner.rst_acked = true;
                    }
                }
                inner.state = StreamState::Reset;
            }

            // Remove from control send buffer
            if let Some(origin_ptype) = self.control_reverse_ack_map.get(&ack_packet_type) {
                return inner.control_snd_buf.remove(&(*origin_ptype, sn)).is_some();
            }
            inner.control_snd_buf.remove(&(ack_packet_type, sn)).is_some()
        }
    }

    // -------------------------------------------------------------------------
    // FIN/RST state hooks
    // -------------------------------------------------------------------------
    pub async fn mark_fin_sent(&self, seq_num: Option<u16>) {
        let mut inner = self.inner.lock().await;
        inner.fin_sent = true;
        if let Some(sn) = seq_num {
            inner.fin_seq_sent = Some(Self::norm_sn(sn));
        } else if inner.fin_seq_sent.is_none() {
            inner.fin_seq_sent = Some(Self::norm_sn(inner.snd_nxt));
        }
        if inner.fin_received {
            inner.state = StreamState::Closing;
        } else {
            inner.state = StreamState::HalfClosedLocal;
        }
    }

    pub async fn mark_fin_received(&self, seq_num: u16) {
        let mut inner = self.inner.lock().await;
        inner.fin_received = true;
        inner.fin_seq_received = Some(Self::norm_sn(seq_num));
        inner.stop_local_read = true;
        if inner.fin_sent {
            inner.state = StreamState::Closing;
        } else {
            inner.state = StreamState::HalfClosedRemote;
        }
    }

    pub async fn mark_rst_sent(&self, seq_num: Option<u16>) {
        let mut inner = self.inner.lock().await;
        inner.rst_sent = true;
        if let Some(sn) = seq_num {
            inner.rst_seq_sent = Some(Self::norm_sn(sn));
        } else if inner.rst_seq_sent.is_none() {
            inner.rst_seq_sent = Some(Self::norm_sn(inner.snd_nxt));
        }
        inner.state = StreamState::Reset;
    }

    pub async fn mark_rst_received(&self, seq_num: u16) {
        let mut inner = self.inner.lock().await;
        inner.rst_received = true;
        inner.rst_seq_received = Some(Self::norm_sn(seq_num));
        inner.state = StreamState::Reset;
        inner.snd_buf.clear();
        inner.rcv_buf.clear();
        inner.control_snd_buf.clear();
    }

    /// Handle inbound STREAM_DATA using the ARQ-owned writer.
    /// Buffers data in rcv_buf, delivers in-order data to the local TCP stream,
    /// and sends an ACK back immediately.
    pub async fn receive_data_only(&self, sn: u16, data: Vec<u8>) {
        let inner_guard = self.inner.lock().await;
        if inner_guard.closed || inner_guard.state == StreamState::Reset
            || inner_guard.rst_received || inner_guard.rst_sent
        {
            return;
        }
        drop(inner_guard);

        let sn = Self::norm_sn(sn);

        {
            let mut inner = self.inner.lock().await;
            inner.last_activity = Instant::now();

            let diff = sn.wrapping_sub(inner.rcv_nxt);
            if diff >= 32768 {
                let now = Instant::now();
                let rto = self.config.rto;
                let ack_throttle = rto.min(0.3).max(0.05);
                let should_ack = inner.last_dup_ack_sn != Some(sn)
                    || now.duration_since(inner.last_dup_ack_time).as_secs_f64() >= ack_throttle;

                if should_ack {
                    inner.last_dup_ack_sn = Some(sn);
                    inner.last_dup_ack_time = now;
                    drop(inner);
                    (self.enqueue_tx)(0, self.stream_id, sn, Vec::new(), true, false).await;
                }
                return;
            }

            if diff as usize > self.config.window_size {
                return;
            }

            if !inner.rcv_buf.contains_key(&sn) && inner.rcv_buf.len() >= self.config.window_size {
                return;
            }

            inner.rcv_buf.entry(sn).or_insert(data);

            // Deliver in-order data to local TCP writer
            let mut data_to_write = Vec::new();
            loop {
                let nxt = inner.rcv_nxt;
                if let Some(d) = inner.rcv_buf.remove(&nxt) {
                    data_to_write.push(d);
                    inner.rcv_nxt = nxt.wrapping_add(1);
                } else {
                    break;
                }
            }

            if !data_to_write.is_empty() {
                if let Some(ref mut writer) = inner.writer {
                    let combined: Vec<u8> = data_to_write.into_iter().flatten().collect();
                    if let Err(e) = writer.write_all(&combined).await {
                        tracing::debug!("Stream {} writer error: {}", self.stream_id, e);
                        drop(inner);
                        self.abort(&format!("Writer Error: {}", e), true).await;
                        return;
                    }
                }
            }
        }

        (self.enqueue_tx)(0, self.stream_id, sn, Vec::new(), true, false).await;

        // Try finalize remote EOF
        self.try_finalize_remote_eof_internal().await;
    }

    /// Write raw bytes to the local TCP stream (e.g. SOCKS5 success reply).
    /// Must be called before notify_socks_connected() to avoid races.
    pub async fn write_to_local(&self, data: &[u8]) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        if let Some(ref mut writer) = inner.writer {
            writer
                .write_all(data)
                .await
                .map_err(|e| format!("write_to_local error: {}", e))
        } else {
            Err("No writer available".to_string())
        }
    }

    pub fn notify_socks_connected(&self) {
        self.socks_connected.notify_one();
    }

    /// Internal version of try_finalize_remote_eof using the ARQ-owned writer.
    async fn try_finalize_remote_eof_internal(&self) {
        let mut inner = self.inner.lock().await;
        if inner.closed || inner.remote_write_closed || !inner.fin_received {
            return;
        }
        if let Some(fin_seq) = inner.fin_seq_received {
            if inner.rcv_nxt != fin_seq {
                return;
            }
        } else {
            return;
        }

        inner.remote_write_closed = true;
        let fin_seq = inner.fin_seq_received.unwrap();
        drop(inner);

        // Send FIN_ACK
        self.send_control_packet(
            PacketType::STREAM_FIN_ACK, fin_seq, &[], 0, false, None,
        ).await;

        let inner = self.inner.lock().await;
        if inner.fin_sent && inner.fin_acked && inner.snd_buf.is_empty() {
            drop(inner);
            self.close("Both FIN sides fully acknowledged", false).await;
        }
    }

    // -------------------------------------------------------------------------
    // Retransmit / shutdown
    // -------------------------------------------------------------------------
    async fn check_retransmits(&self) {
        let mut inner = self.inner.lock().await;
        if inner.closed { return; }

        if inner.rst_received && inner.state != StreamState::Reset {
            let seq = inner.rst_seq_received.unwrap_or(0);
            inner.rst_received = true;
            inner.rst_seq_received = Some(seq);
            inner.state = StreamState::Reset;
            inner.snd_buf.clear();
            inner.rcv_buf.clear();
            inner.control_snd_buf.clear();
            drop(inner);
            self.abort("Peer reset signaled", false).await;
            return;
        }

        let now = Instant::now();

        // Inactivity timeout
        if now.duration_since(inner.last_activity).as_secs_f64() > self.config.inactivity_timeout {
            if !inner.snd_buf.is_empty()
                || (self.config.enable_control_reliability && !inner.control_snd_buf.is_empty())
            {
                inner.last_activity = now;
            } else {
                drop(inner);
                self.abort("Stream Inactivity Timeout (Dead)", true).await;
                return;
            }
        }

        // Data retransmissions
        let mut items_to_resend: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut abort_sn: Option<u16> = None;

        for (&sn, info) in inner.snd_buf.iter_mut() {
            if now.duration_since(info.create_time).as_secs_f64() >= self.config.data_packet_ttl
                && info.retries >= self.config.max_data_retries
            {
                abort_sn = Some(sn);
                break;
            }

            if now.duration_since(info.time).as_secs_f64() >= info.current_rto {
                items_to_resend.push((sn, info.data.clone()));
                info.time = now;
                info.retries += 1;
                info.current_rto = (info.current_rto * 1.2).min(self.config.max_rto).max(self.config.rto);
            }
        }

        if let Some(sn) = abort_sn {
            drop(inner);
            self.abort(&format!("Max retransmissions exceeded for sn={}", sn), true).await;
            return;
        }

        // Control retransmissions
        let mut control_to_resend: Vec<(u8, u16, Vec<u8>, i32)> = Vec::new();
        let mut control_to_remove: Vec<(u8, u16)> = Vec::new();

        if self.config.enable_control_reliability {
            for (&key, info) in inner.control_snd_buf.iter_mut() {
                if now.duration_since(info.create_time).as_secs_f64() >= self.config.control_packet_ttl
                    || info.retries >= self.config.control_max_retries
                {
                    control_to_remove.push(key);
                    continue;
                }

                if now.duration_since(info.time).as_secs_f64() >= info.current_rto {
                    control_to_resend.push((info.packet_type, info.sequence_num, info.payload.clone(), info.priority));
                    info.time = now;
                    info.retries += 1;
                    info.current_rto = (info.current_rto * 1.2).min(self.config.control_max_rto).max(self.config.control_rto);
                }
            }

            for key in &control_to_remove {
                inner.control_snd_buf.remove(key);
            }
        }

        drop(inner);

        // Execute retransmissions outside the lock
        for (sn, data) in items_to_resend {
            (self.enqueue_tx)(1, self.stream_id, sn, data, false, true).await;
        }

        for (ptype, sn, payload, priority) in control_to_resend {
            self.send_control_frame(ptype, sn, &payload, priority, true).await;
        }
    }

    /// Abort stream immediately (RST behavior).
    pub async fn abort(&self, reason: &str, send_rst: bool) {
        {
            let mut inner = self.inner.lock().await;
            if inner.closed { return; }
            inner.close_reason = reason.to_string();
            inner.state = StreamState::Reset;

            if send_rst && !inner.rst_sent && !inner.rst_received {
                inner.rst_sent = true;
                let sn = inner.snd_nxt;
                inner.rst_seq_sent = Some(Self::norm_sn(sn));
            }

            inner.snd_buf.clear();
            inner.rcv_buf.clear();
            inner.control_snd_buf.clear();
        }

        if send_rst {
            let sn = self.inner.lock().await.rst_seq_sent.unwrap_or(0);
            let _ = self.send_control_packet(
                PacketType::STREAM_RST, sn, &[], 0,
                self.config.enable_control_reliability,
                Some(PacketType::STREAM_RST_ACK),
            ).await;
        }

        self.close(reason, false).await;
    }

    /// Close stream gracefully (or directly) and finalize resources.
    pub async fn close(&self, reason: &str, send_fin: bool) {
        let mut inner = self.inner.lock().await;
        if inner.closed { return; }

        inner.close_reason = reason.to_string();

        if send_fin && !inner.fin_sent && !inner.rst_sent && !inner.rst_received {
            inner.fin_sent = true;
            let sn = inner.snd_nxt;
            inner.fin_seq_sent = Some(Self::norm_sn(sn));
            let fin_sn = inner.fin_seq_sent.unwrap();
            drop(inner);

            let _ = self.send_control_packet(
                PacketType::STREAM_FIN, fin_sn, &[], 4,
                self.config.enable_control_reliability,
                Some(PacketType::STREAM_FIN_ACK),
            ).await;

            let mut inner = self.inner.lock().await;
            self.finalize_close(&mut inner);
        } else {
            self.finalize_close(&mut inner);
        }
    }

    fn finalize_close(&self, inner: &mut ArqInner) {
        if inner.state == StreamState::Reset || inner.rst_received || inner.rst_sent {
            inner.state = StreamState::Reset;
        } else if inner.fin_sent && inner.fin_received {
            inner.state = StreamState::TimeWait;
        } else {
            inner.state = StreamState::Closing;
        }

        inner.closed = true;
        inner.snd_buf.clear();
        inner.rcv_buf.clear();
        inner.control_snd_buf.clear();
        inner.state = StreamState::Closed;
    }
}
