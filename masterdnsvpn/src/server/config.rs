// MasterDnsVPN Server - Configuration & Constants
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::{HashMap, HashSet};

use crate::dns_utils::dns_enums::PacketType;

pub const BUILD_VERSION: &str = crate::build_version::BUILD_VERSION;
pub const DEFAULT_CONFIG_FILE: &str = "server_config.toml";
pub const PACKED_CONTROL_BLOCK_SIZE: usize = 5;

// ---------------------------------------------------------------------------
// Packet type lookup tables (mirrors Python server frozensets)
// ---------------------------------------------------------------------------

/// Maps SOCKS5 error ACK types back to the original error packet type.
/// Used when the server receives an ACK from the client for a SOCKS5 error.
pub fn socks5_error_ack_map() -> HashMap<u8, u8> {
    [
        (PacketType::SOCKS5_CONNECT_FAIL_ACK, PacketType::SOCKS5_CONNECT_FAIL),
        (PacketType::SOCKS5_RULESET_DENIED_ACK, PacketType::SOCKS5_RULESET_DENIED),
        (PacketType::SOCKS5_NETWORK_UNREACHABLE_ACK, PacketType::SOCKS5_NETWORK_UNREACHABLE),
        (PacketType::SOCKS5_HOST_UNREACHABLE_ACK, PacketType::SOCKS5_HOST_UNREACHABLE),
        (PacketType::SOCKS5_CONNECTION_REFUSED_ACK, PacketType::SOCKS5_CONNECTION_REFUSED),
        (PacketType::SOCKS5_TTL_EXPIRED_ACK, PacketType::SOCKS5_TTL_EXPIRED),
        (PacketType::SOCKS5_COMMAND_UNSUPPORTED_ACK, PacketType::SOCKS5_COMMAND_UNSUPPORTED),
        (PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK, PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED),
        (PacketType::SOCKS5_AUTH_FAILED_ACK, PacketType::SOCKS5_AUTH_FAILED),
        (PacketType::SOCKS5_UPSTREAM_UNAVAILABLE_ACK, PacketType::SOCKS5_UPSTREAM_UNAVAILABLE),
    ]
    .into_iter()
    .collect()
}

/// All control ACK types the server recognises from the client.
pub fn control_ack_types() -> HashSet<u8> {
    [
        PacketType::STREAM_SYN_ACK,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_RST_ACK,
        PacketType::SOCKS5_SYN_ACK,
        PacketType::SOCKS5_CONNECT_FAIL_ACK,
        PacketType::SOCKS5_RULESET_DENIED_ACK,
        PacketType::SOCKS5_NETWORK_UNREACHABLE_ACK,
        PacketType::SOCKS5_HOST_UNREACHABLE_ACK,
        PacketType::SOCKS5_CONNECTION_REFUSED_ACK,
        PacketType::SOCKS5_TTL_EXPIRED_ACK,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED_ACK,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        PacketType::SOCKS5_AUTH_FAILED_ACK,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        PacketType::STREAM_KEEPALIVE_ACK,
        PacketType::STREAM_WINDOW_UPDATE_ACK,
        PacketType::STREAM_PROBE_ACK,
    ]
    .into_iter()
    .collect()
}

/// Packet types that can be packed into PACKED_CONTROL_BLOCKS.
pub fn packable_control_types() -> HashSet<u8> {
    [
        PacketType::STREAM_DATA_ACK,
        PacketType::STREAM_FIN,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_RST,
        PacketType::STREAM_RST_ACK,
        PacketType::STREAM_SYN_ACK,
        PacketType::SOCKS5_SYN_ACK,
        PacketType::SOCKS5_CONNECT_FAIL,
        PacketType::SOCKS5_RULESET_DENIED,
        PacketType::SOCKS5_NETWORK_UNREACHABLE,
        PacketType::SOCKS5_HOST_UNREACHABLE,
        PacketType::SOCKS5_CONNECTION_REFUSED,
        PacketType::SOCKS5_TTL_EXPIRED,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PacketType::SOCKS5_AUTH_FAILED,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE,
        PacketType::STREAM_KEEPALIVE,
        PacketType::STREAM_KEEPALIVE_ACK,
        PacketType::STREAM_WINDOW_UPDATE,
        PacketType::STREAM_WINDOW_UPDATE_ACK,
        PacketType::STREAM_PROBE,
        PacketType::STREAM_PROBE_ACK,
    ]
    .into_iter()
    .collect()
}

/// Valid VPN packet types accepted by the server.
pub fn valid_packet_types() -> HashSet<u8> {
    [
        PacketType::SESSION_INIT,
        PacketType::SET_MTU_REQ,
        PacketType::MTU_UP_REQ,
        PacketType::MTU_DOWN_REQ,
        PacketType::PING,
        PacketType::STREAM_SYN,
        PacketType::STREAM_DATA,
        PacketType::STREAM_DATA_ACK,
        PacketType::STREAM_RESEND,
        PacketType::STREAM_FIN,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_RST,
        PacketType::STREAM_RST_ACK,
        PacketType::PACKED_CONTROL_BLOCKS,
        PacketType::SOCKS5_SYN,
        PacketType::SOCKS5_CONNECT_FAIL_ACK,
        PacketType::SOCKS5_RULESET_DENIED_ACK,
        PacketType::SOCKS5_NETWORK_UNREACHABLE_ACK,
        PacketType::SOCKS5_HOST_UNREACHABLE_ACK,
        PacketType::SOCKS5_CONNECTION_REFUSED_ACK,
        PacketType::SOCKS5_TTL_EXPIRED_ACK,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED_ACK,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        PacketType::SOCKS5_AUTH_FAILED_ACK,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        PacketType::STREAM_KEEPALIVE,
        PacketType::STREAM_KEEPALIVE_ACK,
        PacketType::STREAM_WINDOW_UPDATE,
        PacketType::STREAM_WINDOW_UPDATE_ACK,
        PacketType::STREAM_PROBE,
        PacketType::STREAM_PROBE_ACK,
    ]
    .into_iter()
    .collect()
}

/// Pre-session packet types (no session required).
pub fn pre_session_packet_types() -> HashSet<u8> {
    [
        PacketType::SESSION_INIT,
        PacketType::MTU_UP_REQ,
        PacketType::MTU_DOWN_REQ,
    ]
    .into_iter()
    .collect()
}

/// SOCKS5 error packet types that the server sends.
pub fn socks5_error_packet_types() -> HashSet<u8> {
    [
        PacketType::SOCKS5_CONNECT_FAIL,
        PacketType::SOCKS5_RULESET_DENIED,
        PacketType::SOCKS5_NETWORK_UNREACHABLE,
        PacketType::SOCKS5_HOST_UNREACHABLE,
        PacketType::SOCKS5_CONNECTION_REFUSED,
        PacketType::SOCKS5_TTL_EXPIRED,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PacketType::SOCKS5_AUTH_FAILED,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE,
    ]
    .into_iter()
    .collect()
}

/// Terminal cleanup packet types that can fall through to main queue
/// even after a stream is removed.
pub fn terminal_fallback_packet_types() -> HashSet<u8> {
    [
        PacketType::STREAM_RST,
        PacketType::STREAM_RST_ACK,
        PacketType::STREAM_FIN_ACK,
        PacketType::SOCKS5_CONNECT_FAIL,
        PacketType::SOCKS5_RULESET_DENIED,
        PacketType::SOCKS5_NETWORK_UNREACHABLE,
        PacketType::SOCKS5_HOST_UNREACHABLE,
        PacketType::SOCKS5_CONNECTION_REFUSED,
        PacketType::SOCKS5_TTL_EXPIRED,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        PacketType::SOCKS5_AUTH_FAILED,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE,
    ]
    .into_iter()
    .collect()
}
