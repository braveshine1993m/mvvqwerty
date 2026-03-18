// MasterDnsVPN Server - Packet Queue Management
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;

use crate::dns_utils::dns_enums::PacketType;
use crate::dns_utils::dns_packet_parser::DnsPacketParser;
use crate::dns_utils::packet_queue::{PacketQueueManager, QueueItem};

use super::config::PACKED_CONTROL_BLOCK_SIZE;
use super::state::{ServerState, SessionState};

// ---------------------------------------------------------------------------
// Activate / Deactivate response queues (session-level helpers)
// ---------------------------------------------------------------------------

/// Activate a stream's response queue within a session (caller holds sessions lock).
pub fn activate_response_queue_session(session: &mut SessionState, stream_id: u16) {
    if session.active_response_set.contains(&stream_id) {
        return;
    }
    session.active_response_set.insert(stream_id);
    if let Err(pos) = session.active_response_ids.binary_search(&stream_id) {
        session.active_response_ids.insert(pos, stream_id);
    }
}

/// Deactivate a stream's response queue within a session (caller holds sessions lock).
pub fn deactivate_response_queue_session(session: &mut SessionState, stream_id: u16) {
    if !session.active_response_set.remove(&stream_id) {
        return;
    }
    if let Ok(pos) = session.active_response_ids.binary_search(&stream_id) {
        session.active_response_ids.remove(pos);
    }
}

// ---------------------------------------------------------------------------
// Enqueue packet (mirrors Python server _enqueue_packet)
// ---------------------------------------------------------------------------

/// Enqueue one outgoing VPN packet into the appropriate session/stream queue.
pub async fn enqueue_packet(
    state: &Arc<ServerState>,
    session_id: u8,
    priority: i32,
    stream_id: u16,
    sn: u16,
    packet_type: u8,
    data: Vec<u8>,
) {
    let ptype = packet_type;

    let effective_priority = {
        let qm = state.queue_manager.lock().await;
        qm.effective_priority_for_packet(ptype, priority)
    };

    let mut sessions = state.sessions.lock().await;
    let session = match sessions.get_mut(&session_id) {
        Some(s) => s,
        None => return,
    };

    session.enqueue_seq = session.enqueue_seq.wrapping_add(1) & 0x7FFFFFFF;
    let item = QueueItem {
        priority: effective_priority,
        counter: session.enqueue_seq as u64,
        packet_type: ptype,
        stream_id,
        sequence_num: sn,
        data,
    };

    if stream_id == 0 {
        // Main queue (session-level packets)
        let qm = state.queue_manager.lock().await;
        if !qm.track_main_packet_once(
            &mut session.main_queue_owner,
            stream_id,
            ptype,
            sn,
            &item.data,
        ) {
            return;
        }
        let was_empty = session.main_queue.is_empty();
        PacketQueueManager::push_queue_item(
            &mut session.main_queue,
            &mut session.main_queue_owner,
            item,
            None,
        );
        if was_empty {
            activate_response_queue_session(session, 0);
        }
        return;
    }

    // Per-stream queue
    if let Some(sd) = session.streams.get_mut(&stream_id) {
        let qm = state.queue_manager.lock().await;
        if !qm.track_stream_packet_once(&mut sd.queue_owner, ptype, sn, &item.data) {
            return;
        }
        let was_empty = sd.tx_queue.is_empty();
        PacketQueueManager::push_queue_item(
            &mut sd.tx_queue,
            &mut sd.queue_owner,
            item,
            None,
        );
        if was_empty {
            activate_response_queue_session(session, stream_id);
        }
        return;
    }

    // Stream gone — only terminal cleanup packets fall through to main queue
    if state.terminal_fallback_types.contains(&ptype) {
        let qm = state.queue_manager.lock().await;
        if !qm.track_main_packet_once(
            &mut session.main_queue_owner,
            stream_id,
            ptype,
            sn,
            &item.data,
        ) {
            return;
        }
        let was_empty = session.main_queue.is_empty();
        PacketQueueManager::push_queue_item(
            &mut session.main_queue,
            &mut session.main_queue_owner,
            item,
            None,
        );
        if was_empty {
            activate_response_queue_session(session, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Dequeue response packet (round-robin across streams within a session)
// (mirrors Python server _dequeue_response_packet)
// ---------------------------------------------------------------------------

/// Round-robin dequeue from a session's active response queues.
/// Returns None if no packets are available.
/// Caller must hold the sessions lock.
pub fn dequeue_response_packet(
    _state: &ServerState,
    session: &mut SessionState,
) -> Option<QueueItem> {
    if session.active_response_ids.is_empty() {
        return None;
    }

    let last_sid = session.round_robin_idx;
    let num = session.active_response_ids.len();
    let start_pos = match session.active_response_ids.binary_search(&last_sid) {
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
        let candidate_sid = session.active_response_ids[(start_pos + offset) % num];

        if candidate_sid == 0 {
            if let Some(item) = session.main_queue.pop() {
                // Can't acquire async lock here - queue_manager is sync-safe for on_queue_pop
                // We skip on_queue_pop tracking in the sync path and handle it externally
                if session.main_queue.is_empty() {
                    deactivate_response_queue_session(session, 0);
                }
                session.round_robin_idx = candidate_sid;
                return Some(item);
            }
        } else {
            if let Some(sd) = session.streams.get_mut(&candidate_sid) {
                if let Some(item) = sd.tx_queue.pop() {
                    if sd.tx_queue.is_empty() {
                        deactivate_response_queue_session(session, candidate_sid);
                    }
                    session.round_robin_idx = candidate_sid;
                    return Some(item);
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Pack selected response blocks (mirrors Python _pack_selected_response_blocks)
// ---------------------------------------------------------------------------

/// Try to aggregate multiple packable control blocks into a single
/// PACKED_CONTROL_BLOCKS item for bandwidth efficiency.
pub fn maybe_pack_control_blocks(
    state: &ServerState,
    session: &mut SessionState,
    item: QueueItem,
) -> QueueItem {
    let max_blocks = session.max_packed_blocks;
    if max_blocks <= 1 {
        return item;
    }

    if !state.packable_control_types.contains(&item.packet_type) || !item.data.is_empty() {
        return item;
    }

    let target_priority = item.priority;
    let mut packed_buf = Vec::with_capacity(PACKED_CONTROL_BLOCK_SIZE * max_blocks);

    // Pack the first item
    packed_buf.extend_from_slice(&DnsPacketParser::pack_control_block(
        item.packet_type,
        item.stream_id,
        item.sequence_num,
    ));
    let mut block_count = 1usize;

    // Try to pop more packable blocks from all active queues in this session
    let ids: Vec<u16> = session.active_response_ids.clone();

    for &sid in &ids {
        if block_count >= max_blocks {
            break;
        }

        if sid == 0 {
            while block_count < max_blocks {
                if let Some(peek) = session.main_queue.peek() {
                    if peek.priority == target_priority
                        && peek.data.is_empty()
                        && state.packable_control_types.contains(&peek.packet_type)
                    {
                        let popped = session.main_queue.pop().unwrap();
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
            if session.main_queue.is_empty() {
                deactivate_response_queue_session(session, 0);
            }
        } else {
            if let Some(sd) = session.streams.get_mut(&sid) {
                while block_count < max_blocks {
                    if let Some(peek) = sd.tx_queue.peek() {
                        if peek.priority == target_priority
                            && peek.data.is_empty()
                            && state.packable_control_types.contains(&peek.packet_type)
                        {
                            let popped = sd.tx_queue.pop().unwrap();
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
                    deactivate_response_queue_session(session, sid);
                }
            }
        }
    }

    if block_count > 1 {
        QueueItem {
            priority: item.priority,
            counter: item.counter,
            packet_type: PacketType::PACKED_CONTROL_BLOCKS,
            stream_id: 0,
            sequence_num: 0,
            data: packed_buf,
        }
    } else {
        item
    }
}
