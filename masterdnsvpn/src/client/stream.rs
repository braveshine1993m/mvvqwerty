// MasterDnsVPN Client - Stream Lifecycle & ARQ Creation
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::dns_utils::arq::Arq;
use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueOwner};

use super::queue;
use super::state::{ClientState, StreamData};

// ---------------------------------------------------------------------------
// Stream ID allocation (mirrors Python _new_get_stream_id)
// ---------------------------------------------------------------------------

/// Allocate a new stream ID that is not currently in use.
/// Returns None if all IDs (1..=65535) are exhausted.
pub async fn allocate_stream_id(state: &Arc<ClientState>) -> Option<u16> {
    let streams = state.active_streams.lock().await;
    let start = state
        .last_stream_id
        .load(Ordering::Relaxed)
        .wrapping_add(1)
        .max(1);
    let mut id = start;
    let mut wrapped = false;

    loop {
        if state.is_stopping() {
            return None;
        }
        if id == 0 || id > 65534 {
            if wrapped {
                return None;
            }
            id = 1;
            wrapped = true;
        }
        if !streams.contains_key(&id) {
            state.last_stream_id.store(id, Ordering::Relaxed);
            return Some(id);
        }
        id = id.wrapping_add(1);
        if id == start && wrapped {
            return None;
        }
    }
}

// ---------------------------------------------------------------------------
// Create a client-side ARQ stream (mirrors Python _create_client_arq_stream)
// ---------------------------------------------------------------------------

/// Create an ARQ instance wired to the client's enqueue callbacks,
/// attach it to a TCP stream's read/write halves, and return it.
pub fn create_client_arq_stream(
    state: &Arc<ClientState>,
    stream_id: u16,
    reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
    initial_data: Vec<u8>,
) -> Arc<Arq> {
    let session_id = state.session_id.load(Ordering::Relaxed) as u8;

    let state_tx = state.clone();
    let enqueue_tx: crate::dns_utils::arq::EnqueueTxCb = Arc::new(
        move |priority, stream_id, sn, data, is_ack, is_resend| {
            let s = state_tx.clone();
            Box::pin(async move {
                let ptype = PacketQueueManager::resolve_arq_packet_type(
                    is_ack, false, false, false, false, false, false, false, is_resend,
                );
                queue::enqueue_packet(&s, priority, stream_id, sn, ptype, data).await;
            })
        },
    );

    let state_ctrl = state.clone();
    let enqueue_ctrl: crate::dns_utils::arq::EnqueueControlTxCb = Arc::new(
        move |priority, stream_id, sn, ptype, payload, _is_retransmit| {
            let s = state_ctrl.clone();
            Box::pin(async move {
                queue::enqueue_packet(&s, priority, stream_id, sn, ptype, payload).await;
            })
        },
    );

    Arq::new(
        stream_id,
        session_id,
        enqueue_tx,
        enqueue_ctrl,
        reader,
        writer,
        state.safe_uplink_mtu.load(Ordering::Relaxed),
        state.arq_config.clone(),
        initial_data,
    )
}

// ---------------------------------------------------------------------------
// Close stream (mirrors Python close_stream)
// ---------------------------------------------------------------------------

/// Safely close a stream. Handles graceful drain (FIN) and abortive (RST) paths.
/// Moves pending control packets from the stream queue to the main queue.
pub async fn close_stream(
    state: &Arc<ClientState>,
    stream_id: u16,
    reason: &str,
    abortive: bool,
    remote_reset: bool,
) {
    let mut streams = state.active_streams.lock().await;
    let sd = match streams.get_mut(&stream_id) {
        Some(s) => s,
        None => return,
    };

    let status = sd.status.as_str();
    if status == "CLOSING" || status == "TIME_WAIT" {
        return;
    }

    // Wake up any pending SOCKS5 handshake event
    if let Some(evt) = &sd.handshake_event {
        evt.notify_one();
    }

    let arq = sd.arq.clone();

    // Phase 1: graceful drain (don't finalize yet)
    if !abortive {
        if let Some(ref arq_obj) = arq {
            if !arq_obj.is_closed().await {
                // Check if FIN was already sent
                // If not, start draining
                sd.status = "DRAINING".to_string();
                tracing::debug!(
                    "Draining client stream {}. Reason: {}",
                    stream_id,
                    reason
                );
                let arq_clone = arq_obj.clone();
                drop(streams);
                arq_clone.close(reason, true).await;
                return;
            }
        }
    }

    // Phase 2: final cleanup
    sd.status = "CLOSING".to_string();
    let now = Instant::now();

    // Record in closed_streams
    {
        let mut closed = state.closed_streams.lock().await;
        closed.insert(stream_id, now);
        if closed.len() > state.max_closed_stream_records {
            if let Some(&oldest) = closed.keys().next() {
                closed.remove(&oldest);
            }
        }
    }

    tracing::debug!("Closing client stream {}. Reason: {}", stream_id, reason);

    // Abort/close ARQ
    if let Some(ref arq_obj) = arq {
        if abortive {
            if remote_reset {
                arq_obj.close(reason, false).await;
            } else {
                arq_obj.abort(reason, true).await;
            }
        } else if !arq_obj.is_closed().await {
            arq_obj.close(reason, true).await;
        }
    }

    // Move eligible pending control packets from stream queue to main queue
    let pending_items: Vec<_> = sd.tx_queue.drain().collect();
    let packable = &state.packable_control_types;

    // Clear stream tracking sets
    sd.tx_queue.clear();
    sd.queue_owner = QueueOwner::default();
    sd.status = "TIME_WAIT".to_string();
    sd.close_time = Some(now);

    // Must drop streams lock before enqueuing to main queue
    drop(streams);

    // Move packable control blocks to main queue
    for item in pending_items {
        let ptype = item.packet_type;
        if packable.contains(&ptype) && ptype != PacketType::SOCKS5_SYN {
            queue::enqueue_packet(state, item.priority, item.stream_id, item.sequence_num, ptype, item.data).await;
        }
    }

    queue::deactivate_response_queue(state, stream_id).await;
}

// ---------------------------------------------------------------------------
// Clear all runtime state after disconnect
// (mirrors Python _clear_runtime_state_after_disconnect)
// ---------------------------------------------------------------------------

/// Abort all streams and reset queues for a clean reconnect.
pub async fn clear_runtime_state(state: &Arc<ClientState>) {
    let mut streams = state.active_streams.lock().await;
    for (_, sd) in streams.drain() {
        if let Some(arq) = &sd.arq {
            arq.abort("Session disconnect", false).await;
        }
    }
    drop(streams);

    let mut closed = state.closed_streams.lock().await;
    closed.clear();
    drop(closed);

    let mut mq = state.main_queue.lock().await;
    mq.clear();
    drop(mq);

    let mut mq_owner = state.main_queue_owner.lock().await;
    *mq_owner = QueueOwner::default();
    drop(mq_owner);

    let mut ids = state.active_response_ids.lock().await;
    ids.clear();
    drop(ids);

    let mut resp_set = state.active_response_set.lock().await;
    resp_set.clear();
    drop(resp_set);

    *state.tunnel_sock.lock().await = None;
    state.session_established.store(false, Ordering::SeqCst);
    state.last_stream_id.store(0, Ordering::Relaxed);
    state.count_ping.store(0, Ordering::Relaxed);
}
