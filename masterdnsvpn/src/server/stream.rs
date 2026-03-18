// MasterDnsVPN Server - Stream Lifecycle
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;
use std::time::Instant;

use crate::dns_utils::arq::Arq;
use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueOwner};

use super::queue;
use super::state::ServerState;

// ---------------------------------------------------------------------------
// Close stream (mirrors Python close_stream on server)
// ---------------------------------------------------------------------------

/// Safely close a specific stream. Handles graceful drain and abortive paths.
/// Moves pending packable control packets from stream queue to main queue.
pub async fn close_stream(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    reason: &str,
    abortive: bool,
    remote_reset: bool,
) {
    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => return,
    };

    let sd = match session.streams.get_mut(&stream_id) {
        Some(s) => s,
        None => return,
    };

    let status = sd.status.as_str();
    if status == "CLOSING" || status == "TIME_WAIT" {
        return;
    }

    let arq = sd.arq.clone();

    // Phase 1: graceful drain
    if !abortive {
        if let Some(ref arq_obj) = arq {
            if !arq_obj.is_closed().await {
                sd.status = "DRAINING".to_string();
                tracing::debug!(
                    "Draining server stream {} in session {}. Reason: {}",
                    stream_id,
                    session_id,
                    reason
                );
                let arq_clone = arq_obj.clone();
                drop(sessions);
                arq_clone.close(reason, true).await;
                return;
            }
        }
    }

    // Phase 2: final cleanup
    sd.status = "CLOSING".to_string();
    let now = Instant::now();
    session
        .closed_streams
        .insert(stream_id, now);

    // Limit closed_streams size
    if session.closed_streams.len() > 1000 {
        if let Some(&oldest) = session.closed_streams.keys().next() {
            session.closed_streams.remove(&oldest);
        }
    }

    tracing::debug!(
        "Closing server stream {} in session {}. Reason: {}",
        stream_id,
        session_id,
        reason
    );

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
    } else {
        // No ARQ: send RST or FIN directly
        if abortive && !remote_reset {
            let rst_sn = sd.rst_seq_sent;
            sd.rst_sent = true;
            sd.rst_acked = false;

            let sid = session_id;
            drop(sessions);
            queue::enqueue_packet(state, sid, 0, stream_id, rst_sn, PacketType::STREAM_RST, vec![])
                .await;
            return;
        } else if !abortive {
            let sid = session_id;
            drop(sessions);
            queue::enqueue_packet(state, sid, 1, stream_id, 0, PacketType::STREAM_FIN, vec![])
                .await;
            return;
        }
    }

    // Move eligible pending control packets from stream to main queue
    let pending_items: Vec<_> = sd.tx_queue.drain().collect();
    let packable = &state.packable_control_types;

    // Clear stream tracking
    sd.tx_queue.clear();
    sd.queue_owner = QueueOwner::default();
    sd.priority_counts.clear();
    sd.syn_responses.clear();
    sd.socks_chunks.clear();
    sd.socks_expected_frags = None;
    sd.status = "TIME_WAIT".to_string();
    sd.close_time = Some(now);

    // Deactivate stream's response queue
    queue::deactivate_response_queue_session(session, stream_id);

    // Move packable items to main queue
    let main_was_empty = session.main_queue.is_empty();
    let mut moved_any = false;

    for item in pending_items {
        let ptype = item.packet_type;
        if packable.contains(&ptype) && ptype != PacketType::SOCKS5_SYN {
            let qm = state.queue_manager.lock().await;
            if qm.track_main_packet_once(
                &mut session.main_queue_owner,
                item.stream_id,
                ptype,
                item.sequence_num,
                &item.data,
            ) {
                PacketQueueManager::push_queue_item(
                    &mut session.main_queue,
                    &mut session.main_queue_owner,
                    item,
                    None,
                );
                moved_any = true;
            }
        }
    }

    if main_was_empty && moved_any {
        queue::activate_response_queue_session(session, 0);
    }

    drop(sessions);
}

// ---------------------------------------------------------------------------
// Create server-side ARQ stream (mirrors Python ARQ wiring in server)
// ---------------------------------------------------------------------------

/// Create an ARQ instance wired to the server's enqueue callbacks,
/// attach it to a TCP stream's read/write halves, and return it.
pub fn create_server_arq_stream(
    state: &Arc<ServerState>,
    session_id: u8,
    stream_id: u16,
    reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
    mtu: usize,
    initial_data: Vec<u8>,
) -> Arc<Arq> {
    let state_tx = state.clone();
    let enqueue_tx: crate::dns_utils::arq::EnqueueTxCb = Arc::new(
        move |priority, sid, sn, data, is_ack, is_resend| {
            let s = state_tx.clone();
            let sess_id = session_id;
            Box::pin(async move {
                let ptype = PacketQueueManager::resolve_arq_packet_type(
                    is_ack, false, false, false, false, false, false, false, is_resend,
                );
                queue::enqueue_packet(&s, sess_id, priority, sid, sn, ptype, data).await;
            })
        },
    );

    let state_ctrl = state.clone();
    let enqueue_ctrl: crate::dns_utils::arq::EnqueueControlTxCb = Arc::new(
        move |priority, sid, sn, ptype, payload, _is_retransmit| {
            let s = state_ctrl.clone();
            let sess_id = session_id;
            Box::pin(async move {
                queue::enqueue_packet(&s, sess_id, priority, sid, sn, ptype, payload).await;
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
        mtu,
        state.arq_config.clone(),
        initial_data,
    )
}
