// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

use super::dns_enums::PacketType;

/// A single item in the priority queue.
#[derive(Debug, Clone)]
pub struct QueueItem {
    pub priority: i32,
    pub counter: u64,
    pub packet_type: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub data: Vec<u8>,
}

// Min-heap ordering: lower priority value = higher urgency.
impl Eq for QueueItem {}

impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.counter == other.counter
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap: lower priority first, then lower counter first
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.counter.cmp(&self.counter))
    }
}

/// Tracking state for dedup within a queue owner.
#[derive(Debug, Default)]
pub struct QueueOwner {
    pub priority_counts: HashMap<i32, usize>,
    pub track_data: HashSet<TrackKey>,
    pub track_ack: HashSet<TrackKey>,
    pub track_resend: HashSet<TrackKey>,
    pub track_types: HashSet<TrackKey>,
    pub track_syn_ack: HashSet<u8>,
    pub track_fin: HashSet<u8>,
    pub track_seq_packets: HashSet<(u8, u16)>,
    pub track_fragment_packets: HashSet<(u8, u16, Vec<u8>)>,
    /// Optional stream_id that scopes this owner to a single stream.
    pub stream_id: Option<u16>,
}

/// A tracking key that can be either a plain sequence number or a (stream_id, sn) pair.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TrackKey {
    Plain(u16),
    Scoped(u16, u16), // (stream_id, value)
    Type(u8),
    ScopedType(u16, u8),
}

// Sets defined at module level (mirrors Python class-level frozensets)
fn priority_zero_types() -> HashSet<u8> {
    [
        PacketType::STREAM_DATA_ACK,
        PacketType::STREAM_RST,
        PacketType::STREAM_RST_ACK,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_SYN_ACK,
        PacketType::SOCKS5_SYN_ACK,
    ]
    .into_iter()
    .collect()
}

fn syn_track_types() -> HashSet<u8> {
    [PacketType::STREAM_SYN, PacketType::STREAM_SYN_ACK]
        .into_iter()
        .collect()
}

fn single_instance_queue_types() -> HashSet<u8> {
    [
        PacketType::STREAM_FIN,
        PacketType::STREAM_RST,
        PacketType::STREAM_RST_ACK,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_SYN,
        PacketType::STREAM_SYN_ACK,
    ]
    .into_iter()
    .collect()
}

fn seq_keyed_queue_types() -> HashSet<u8> {
    [
        PacketType::STREAM_KEEPALIVE,
        PacketType::STREAM_KEEPALIVE_ACK,
        PacketType::STREAM_WINDOW_UPDATE,
        PacketType::STREAM_WINDOW_UPDATE_ACK,
        PacketType::STREAM_PROBE,
        PacketType::STREAM_PROBE_ACK,
        PacketType::SOCKS5_CONNECT_FAIL,
        PacketType::SOCKS5_CONNECT_FAIL_ACK,
        PacketType::SOCKS5_RULESET_DENIED,
        PacketType::SOCKS5_RULESET_DENIED_ACK,
        PacketType::SOCKS5_NETWORK_UNREACHABLE,
        PacketType::SOCKS5_NETWORK_UNREACHABLE_ACK,
        PacketType::SOCKS5_HOST_UNREACHABLE,
        PacketType::SOCKS5_HOST_UNREACHABLE_ACK,
        PacketType::SOCKS5_CONNECTION_REFUSED,
        PacketType::SOCKS5_CONNECTION_REFUSED_ACK,
        PacketType::SOCKS5_TTL_EXPIRED,
        PacketType::SOCKS5_TTL_EXPIRED_ACK,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED_ACK,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        PacketType::SOCKS5_AUTH_FAILED,
        PacketType::SOCKS5_AUTH_FAILED_ACK,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    ]
    .into_iter()
    .collect()
}

fn fragment_keyed_queue_types() -> HashSet<u8> {
    [PacketType::SOCKS5_SYN, PacketType::SOCKS5_SYN_ACK]
        .into_iter()
        .collect()
}

fn drop_queue_types() -> HashSet<u8> {
    [PacketType::PACKED_CONTROL_BLOCKS, PacketType::ERROR_DROP]
        .into_iter()
        .collect()
}

/// Shared queue/priority bookkeeping for client and server packet schedulers.
pub struct PacketQueueManager {
    priority_zero: HashSet<u8>,
    syn_track: HashSet<u8>,
    single_instance: HashSet<u8>,
    seq_keyed: HashSet<u8>,
    fragment_keyed: HashSet<u8>,
    drop_types: HashSet<u8>,
    counter: u64,
}

impl PacketQueueManager {
    pub fn new() -> Self {
        PacketQueueManager {
            priority_zero: priority_zero_types(),
            syn_track: syn_track_types(),
            single_instance: single_instance_queue_types(),
            seq_keyed: seq_keyed_queue_types(),
            fragment_keyed: fragment_keyed_queue_types(),
            drop_types: drop_queue_types(),
            counter: 0,
        }
    }

    pub fn compute_mtu_based_pack_limit(
        mtu_size: usize,
        usage_percent: f64,
        block_size: usize,
    ) -> usize {
        let mtu = mtu_size;
        let pct = usage_percent.clamp(1.0, 100.0);
        let blk = block_size.max(1);
        let usable_budget = (mtu as f64 * (pct / 100.0)) as usize;
        (usable_budget / blk).max(1)
    }

    fn inc_priority_counter(owner: &mut QueueOwner, priority: i32) {
        *owner.priority_counts.entry(priority).or_insert(0) += 1;
    }

    fn dec_priority_counter(owner: &mut QueueOwner, priority: i32) {
        if let Some(count) = owner.priority_counts.get_mut(&priority) {
            if *count <= 1 {
                owner.priority_counts.remove(&priority);
            } else {
                *count -= 1;
            }
        }
    }

    fn owner_track_key(owner: &QueueOwner, stream_id: u16, value: u16) -> TrackKey {
        if owner.stream_id.is_some() || stream_id == 0 {
            TrackKey::Plain(value)
        } else {
            TrackKey::Scoped(stream_id, value)
        }
    }

    fn owner_track_key_type(owner: &QueueOwner, stream_id: u16, ptype: u8) -> TrackKey {
        if owner.stream_id.is_some() || stream_id == 0 {
            TrackKey::Type(ptype)
        } else {
            TrackKey::ScopedType(stream_id, ptype)
        }
    }

    pub fn owner_has_priority(owner: &QueueOwner, priority: i32) -> bool {
        owner.priority_counts.get(&priority).map_or(false, |&c| c > 0)
    }

    /// Resolve ARQ boolean flags to a packet type (legacy compat).
    pub fn resolve_arq_packet_type(
        is_ack: bool,
        is_fin: bool,
        is_fin_ack: bool,
        is_rst: bool,
        is_rst_ack: bool,
        is_syn_ack: bool,
        is_socks_syn_ack: bool,
        is_socks_syn: bool,
        is_resend: bool,
    ) -> u8 {
        if is_ack { return PacketType::STREAM_DATA_ACK; }
        if is_fin { return PacketType::STREAM_FIN; }
        if is_fin_ack { return PacketType::STREAM_FIN_ACK; }
        if is_rst { return PacketType::STREAM_RST; }
        if is_rst_ack { return PacketType::STREAM_RST_ACK; }
        if is_syn_ack { return PacketType::STREAM_SYN_ACK; }
        if is_socks_syn_ack { return PacketType::SOCKS5_SYN_ACK; }
        if is_socks_syn { return PacketType::SOCKS5_SYN; }
        if is_resend { return PacketType::STREAM_RESEND; }
        PacketType::STREAM_DATA
    }

    /// Compute effective priority for a packet, overriding for certain control types.
    pub fn effective_priority_for_packet(&self, packet_type: u8, priority: i32) -> i32 {
        if self.priority_zero.contains(&packet_type) {
            return 0;
        }
        if packet_type == PacketType::STREAM_FIN {
            return 4;
        }
        if packet_type == PacketType::STREAM_RESEND {
            return 1;
        }
        priority
    }

    /// Track whether a packet should be enqueued into the main (session-wide) queue.
    /// Returns true if the packet is accepted (not a duplicate).
    pub fn track_main_packet_once(
        &self,
        owner: &mut QueueOwner,
        stream_id: u16,
        ptype: u8,
        sn: u16,
        _payload: &[u8],
    ) -> bool {
        if self.drop_types.contains(&ptype) {
            return false;
        }

        let sn_key = Self::owner_track_key(owner, stream_id, sn);
        let ptype_key = Self::owner_track_key_type(owner, stream_id, ptype);

        if ptype == PacketType::STREAM_RESEND {
            if owner.track_data.contains(&sn_key) || owner.track_data.contains(&TrackKey::Plain(sn)) {
                return false;
            }
            if owner.track_resend.contains(&sn_key) || owner.track_resend.contains(&TrackKey::Plain(sn)) {
                return false;
            }
            owner.track_resend.insert(sn_key);
            return true;
        }

        if self.single_instance.contains(&ptype) {
            if owner.track_types.contains(&ptype_key) || owner.track_types.contains(&TrackKey::Type(ptype)) {
                return false;
            }
            owner.track_types.insert(ptype_key);
            return true;
        }

        if ptype == PacketType::STREAM_DATA_ACK {
            if owner.track_ack.contains(&sn_key) || owner.track_ack.contains(&TrackKey::Plain(sn)) {
                return false;
            }
            owner.track_ack.insert(sn_key);
            return true;
        }

        if self.seq_keyed.contains(&ptype) {
            let seq_key = (ptype, sn);
            if owner.track_seq_packets.contains(&seq_key) {
                return false;
            }
            owner.track_seq_packets.insert(seq_key);
            return true;
        }

        if ptype == PacketType::STREAM_DATA {
            if owner.track_resend.contains(&sn_key) || owner.track_resend.contains(&TrackKey::Plain(sn)) {
                return false;
            }
            if owner.track_data.contains(&sn_key) || owner.track_data.contains(&TrackKey::Plain(sn)) {
                return false;
            }
            owner.track_data.insert(sn_key);
            return true;
        }

        true
    }

    /// Track whether a packet should be enqueued into a stream-local queue.
    pub fn track_stream_packet_once(
        &self,
        owner: &mut QueueOwner,
        ptype: u8,
        sn: u16,
        _payload: &[u8],
    ) -> bool {
        if self.drop_types.contains(&ptype) {
            return false;
        }

        if ptype == PacketType::STREAM_RESEND {
            let sn_key = TrackKey::Plain(sn);
            if owner.track_data.contains(&sn_key) || owner.track_resend.contains(&sn_key) {
                return false;
            }
            owner.track_resend.insert(sn_key);
            return true;
        }

        if self.single_instance.contains(&ptype) {
            let ptype_key = TrackKey::Type(ptype);
            if owner.track_types.contains(&ptype_key) {
                return false;
            }
            owner.track_types.insert(ptype_key.clone());
            if ptype == PacketType::STREAM_FIN {
                owner.track_fin.insert(ptype);
            } else if ptype == PacketType::STREAM_SYN_ACK {
                owner.track_syn_ack.insert(ptype);
            }
            return true;
        }

        if ptype == PacketType::STREAM_DATA_ACK {
            let sn_key = TrackKey::Plain(sn);
            if owner.track_ack.contains(&sn_key) {
                return false;
            }
            owner.track_ack.insert(sn_key);
            return true;
        }

        if self.seq_keyed.contains(&ptype) {
            let seq_key = (ptype, sn);
            if owner.track_seq_packets.contains(&seq_key) {
                return false;
            }
            owner.track_seq_packets.insert(seq_key);
            return true;
        }

        if ptype == PacketType::STREAM_DATA {
            let sn_key = TrackKey::Plain(sn);
            if owner.track_data.contains(&sn_key) || owner.track_resend.contains(&sn_key) {
                return false;
            }
            owner.track_data.insert(sn_key);
            return true;
        }

        true
    }

    /// Release tracking on pop so future retransmits aren't suppressed.
    pub fn release_tracking_on_pop(
        &self,
        owner: &mut QueueOwner,
        packet_type: u8,
        stream_id: u16,
        sn: u16,
    ) {
        let sn_key = Self::owner_track_key(owner, stream_id, sn);
        let ptype_key = Self::owner_track_key_type(owner, stream_id, packet_type);

        match packet_type {
            pt if pt == PacketType::STREAM_DATA => {
                owner.track_data.remove(&sn_key);
                owner.track_data.remove(&TrackKey::Plain(sn));
            }
            pt if pt == PacketType::STREAM_DATA_ACK => {
                owner.track_ack.remove(&sn_key);
                owner.track_ack.remove(&TrackKey::Plain(sn));
            }
            pt if pt == PacketType::STREAM_RESEND => {
                owner.track_resend.remove(&sn_key);
                owner.track_resend.remove(&TrackKey::Plain(sn));
            }
            pt if pt == PacketType::STREAM_FIN => {
                owner.track_fin.remove(&packet_type);
                owner.track_types.remove(&ptype_key);
                owner.track_types.remove(&TrackKey::Type(packet_type));
            }
            pt if pt == PacketType::STREAM_RST
                || pt == PacketType::STREAM_RST_ACK
                || pt == PacketType::STREAM_FIN_ACK =>
            {
                owner.track_types.remove(&ptype_key);
                owner.track_types.remove(&TrackKey::Type(packet_type));
            }
            pt if self.syn_track.contains(&pt) => {
                owner.track_syn_ack.remove(&packet_type);
                owner.track_types.remove(&ptype_key);
                owner.track_types.remove(&TrackKey::Type(packet_type));
            }
            pt if self.seq_keyed.contains(&pt) => {
                owner.track_seq_packets.remove(&(packet_type, sn));
            }
            _ => {}
        }
    }

    /// Pop from queue and update tracking.
    pub fn on_queue_pop(&self, owner: &mut QueueOwner, item: &QueueItem) {
        Self::dec_priority_counter(owner, item.priority);
        self.release_tracking_on_pop(owner, item.packet_type, item.stream_id, item.sequence_num);
    }

    /// Push item into queue and update tracking.
    pub fn push_queue_item(
        queue: &mut BinaryHeap<QueueItem>,
        owner: &mut QueueOwner,
        item: QueueItem,
        tx_notify: Option<&tokio::sync::Notify>,
    ) {
        Self::inc_priority_counter(owner, item.priority);
        queue.push(item);
        if let Some(notify) = tx_notify {
            notify.notify_one();
        }
    }

    /// Get a unique counter value for ordering.
    pub fn next_counter(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }
}
