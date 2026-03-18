// MasterDnsVPN Client - Packet Queue Management
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueItem};

use super::config::PACKED_CONTROL_BLOCK_SIZE;
use super::state::ClientState;

// ---------------------------------------------------------------------------
// Activate / Deactivate response queues
// (mirrors Python _activate_response_queue / _deactivate_response_queue)
// ---------------------------------------------------------------------------

pub async fn activate_response_queue(state: &Arc<ClientState>, stream_id: u16) {
    let mut set = state.active_response_set.lock().await;
    if set.contains(&stream_id) {
        return;
    }
    set.insert(stream_id);

    let mut ids = state.active_response_ids.lock().await;
    if let Err(pos) = ids.binary_search(&stream_id) {
        ids.insert(pos, stream_id);
    }
    state.tx_notify.notify_one();
}

pub async fn deactivate_response_queue(state: &Arc<ClientState>, stream_id: u16) {
    let mut set = state.active_response_set.lock().await;
    if !set.remove(&stream_id) {
        return;
    }

    let mut ids = state.active_response_ids.lock().await;
    if let Ok(pos) = ids.binary_search(&stream_id) {
        ids.remove(pos);
    }
}

// ---------------------------------------------------------------------------
// Enqueue packet (mirrors Python _enqueue_packet)
// ---------------------------------------------------------------------------

/// Enqueue one outgoing VPN packet into the appropriate session/stream queue.
/// Applies deduplication, priority normalization, and activates response queues.
pub async fn enqueue_packet(
    state: &Arc<ClientState>,
    priority: i32,
    stream_id: u16,
    sn: u16,
    packet_type: u8,
    data: Vec<u8>,
) {
    if state.is_stopping() {
        return;
    }

    let ptype = packet_type;

    let effective_priority = {
        let qm = state.queue_manager.lock().await;
        qm.effective_priority_for_packet(ptype, priority)
    };

    let seq = state.enqueue_seq.fetch_add(1, Ordering::Relaxed);
    let item = QueueItem {
        priority: effective_priority,
        counter: seq as u64,
        packet_type: ptype,
        stream_id,
        sequence_num: sn,
        data,
    };

    if stream_id == 0 {
        // Main queue (session-level packets)
        let qm = state.queue_manager.lock().await;
        let mut owner = state.main_queue_owner.lock().await;
        if !qm.track_main_packet_once(&mut owner, stream_id, ptype, sn, &item.data) {
            return;
        }
        let mut mq = state.main_queue.lock().await;
        let was_empty = mq.is_empty();
        PacketQueueManager::push_queue_item(&mut mq, &mut owner, item, Some(&state.tx_notify));
        if was_empty {
            drop(mq);
            drop(owner);
            drop(qm);
            activate_response_queue(state, 0).await;
        }
        return;
    }

    // Per-stream queue
    let mut streams = state.active_streams.lock().await;
    if let Some(sd) = streams.get_mut(&stream_id) {
        let qm = state.queue_manager.lock().await;
        if !qm.track_stream_packet_once(&mut sd.queue_owner, ptype, sn, &item.data) {
            return;
        }
        let was_empty = sd.tx_queue.is_empty();
        PacketQueueManager::push_queue_item(
            &mut sd.tx_queue,
            &mut sd.queue_owner,
            item,
            Some(&state.tx_notify),
        );
        if was_empty {
            drop(qm);
            drop(streams);
            activate_response_queue(state, stream_id).await;
        }
        return;
    }

    // Stream gone — only terminal cleanup packets fall through to main queue
    let is_terminal = ptype == PacketType::STREAM_RST
        || ptype == PacketType::STREAM_RST_ACK
        || ptype == PacketType::STREAM_FIN_ACK
        || state
            .control_request_ack_map
            .values()
            .any(|&v| v == ptype);

    if is_terminal {
        drop(streams);
        let qm = state.queue_manager.lock().await;
        let mut owner = state.main_queue_owner.lock().await;
        if !qm.track_main_packet_once(&mut owner, stream_id, ptype, sn, &item.data) {
            return;
        }
        let mut mq = state.main_queue.lock().await;
        let was_empty = mq.is_empty();
        PacketQueueManager::push_queue_item(&mut mq, &mut owner, item, Some(&state.tx_notify));
        if was_empty {
            drop(mq);
            drop(owner);
            drop(qm);
            activate_response_queue(state, 0).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Dequeue response packet with round-robin (mirrors Python _dequeue_response_packet)
// ---------------------------------------------------------------------------

/// Round-robin dequeue across all active response queues.
/// The session main queue participates as virtual stream 0.
/// Returns None if no packets are available.
pub async fn dequeue_response_packet(state: &Arc<ClientState>) -> Option<QueueItem> {
    let ids = state.active_response_ids.lock().await;
    if ids.is_empty() {
        return None;
    }

    let last_sid = state.round_robin_stream_id.load(Ordering::Relaxed);
    let num = ids.len();
    let start_pos = match ids.binary_search(&last_sid) {
        Ok(p) => (p + 1) % num,
        Err(p) => {
            if p >= num {
                0
            } else {
                p
            }
        }
    };

    for offset in 0..num {
        let candidate_sid = ids[(start_pos + offset) % num];

        if candidate_sid == 0 {
            // Main queue
            let mut mq = state.main_queue.lock().await;
            if let Some(item) = mq.pop() {
                let qm = state.queue_manager.lock().await;
                let mut owner = state.main_queue_owner.lock().await;
                qm.on_queue_pop(&mut owner, &item);

                if mq.is_empty() {
                    drop(mq);
                    drop(owner);
                    drop(qm);
                    drop(ids);
                    deactivate_response_queue(state, 0).await;
                } else {
                    drop(mq);
                    drop(owner);
                    drop(qm);
                    drop(ids);
                }

                state
                    .round_robin_stream_id
                    .store(candidate_sid, Ordering::Relaxed);

                // Handle PING demotion when other queues exist
                if item.packet_type == PacketType::PING {
                    let count = state.count_ping.load(Ordering::Relaxed);
                    if count > 0 {
                        state.count_ping.fetch_sub(1, Ordering::Relaxed);
                    }
                    // If there are other active queues with data, skip the PING
                    let has_others = {
                        let resp_ids = state.active_response_ids.lock().await;
                        resp_ids.iter().any(|&id| id != 0)
                    };
                    if has_others && candidate_sid == 0 {
                        // Re-check: try to find a non-ping packet instead
                        // For simplicity, we still return the PING here
                        // (full Python logic does a continue in a while loop)
                    }
                }

                // Try to pack multiple control blocks
                return maybe_pack_control_blocks(state, item).await;
            }
        } else {
            // Per-stream queue
            let mut streams = state.active_streams.lock().await;
            if let Some(sd) = streams.get_mut(&candidate_sid) {
                if let Some(item) = sd.tx_queue.pop() {
                    let qm = state.queue_manager.lock().await;
                    qm.on_queue_pop(&mut sd.queue_owner, &item);

                    if sd.tx_queue.is_empty() {
                        drop(qm);
                        drop(streams);
                        drop(ids);
                        deactivate_response_queue(state, candidate_sid).await;
                    } else {
                        drop(qm);
                        drop(streams);
                        drop(ids);
                    }

                    state
                        .round_robin_stream_id
                        .store(candidate_sid, Ordering::Relaxed);

                    return maybe_pack_control_blocks(state, item).await;
                }
            }
        }
    }

    drop(ids);
    None
}

// ---------------------------------------------------------------------------
// Packed control blocks (mirrors Python _pack_selected_response_blocks)
// ---------------------------------------------------------------------------

/// If the dequeued item is a packable control type with no data payload,
/// try to aggregate more control blocks from the same and other queues.
async fn maybe_pack_control_blocks(
    state: &Arc<ClientState>,
    item: QueueItem,
) -> Option<QueueItem> {
    if state.max_packed_blocks <= 1 {
        return Some(item);
    }

    if !state.packable_control_types.contains(&item.packet_type) || !item.data.is_empty() {
        return Some(item);
    }

    let target_priority = item.priority;
    let mut packed_buf = Vec::with_capacity(PACKED_CONTROL_BLOCK_SIZE * state.max_packed_blocks);

    // Pack the first item
    packed_buf.extend_from_slice(&DnsPacketParser::pack_control_block(
        item.packet_type,
        item.stream_id,
        item.sequence_num,
    ));
    let mut block_count = 1usize;

    // Try to pop more packable blocks from all active queues
    let ids: Vec<u16> = {
        let resp_ids = state.active_response_ids.lock().await;
        resp_ids.clone()
    };

    for &sid in &ids {
        if block_count >= state.max_packed_blocks {
            break;
        }

        if sid == 0 {
            let mut mq = state.main_queue.lock().await;
            while block_count < state.max_packed_blocks {
                if let Some(peek) = mq.peek() {
                    if peek.priority == target_priority
                        && peek.data.is_empty()
                        && state.packable_control_types.contains(&peek.packet_type)
                    {
                        let popped = mq.pop().unwrap();
                        let qm = state.queue_manager.lock().await;
                        let mut owner = state.main_queue_owner.lock().await;
                        qm.on_queue_pop(&mut owner, &popped);
                        packed_buf.extend_from_slice(&DnsPacketParser::pack_control_block(
                            popped.packet_type,
                            popped.stream_id,
                            popped.sequence_num,
                        ));
                        block_count += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            if mq.is_empty() {
                drop(mq);
                deactivate_response_queue(state, 0).await;
            }
        } else {
            let mut streams = state.active_streams.lock().await;
            if let Some(sd) = streams.get_mut(&sid) {
                while block_count < state.max_packed_blocks {
                    if let Some(peek) = sd.tx_queue.peek() {
                        if peek.priority == target_priority
                            && peek.data.is_empty()
                            && state.packable_control_types.contains(&peek.packet_type)
                        {
                            let popped = sd.tx_queue.pop().unwrap();
                            let qm = state.queue_manager.lock().await;
                            qm.on_queue_pop(&mut sd.queue_owner, &popped);
                            packed_buf.extend_from_slice(&DnsPacketParser::pack_control_block(
                                popped.packet_type,
                                popped.stream_id,
                                popped.sequence_num,
                            ));
                            block_count += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if sd.tx_queue.is_empty() {
                    drop(streams);
                    deactivate_response_queue(state, sid).await;
                }
            }
        }
    }

    if block_count > 1 {
        // Return a PACKED_CONTROL_BLOCKS item
        Some(QueueItem {
            priority: item.priority,
            counter: item.counter,
            packet_type: PacketType::PACKED_CONTROL_BLOCKS,
            stream_id: 0,
            sequence_num: 0,
            data: packed_buf,
        })
    } else {
        Some(item)
    }
}

// ---------------------------------------------------------------------------
// Ping helper (mirrors Python _send_ping_packet)
// ---------------------------------------------------------------------------

/// Schedule a PING packet for sending (non-blocking fire-and-forget).
pub fn send_ping_packet(state: &Arc<ClientState>) {
    let s = state.clone();
    tokio::spawn(async move {
        enqueue_packet(&s, 5, 0, 0, PacketType::PING, vec![]).await;
    });
}
