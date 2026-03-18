// MasterDnsVPN Client - Configuration & Constants
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::{HashMap, HashSet};

use crate::dns_utils::dns_enums::PacketType;

pub const BUILD_VERSION: &str = crate::build_version::BUILD_VERSION;
pub const DEFAULT_CONFIG_FILE: &str = "client_config.toml";
pub const PACKED_CONTROL_BLOCK_SIZE: usize = 5;

// ---------------------------------------------------------------------------
// Packet type lookup tables (mirrors Python frozensets)
// ---------------------------------------------------------------------------

/// Maps control-request packet types to their corresponding ACK types.
/// When the client receives one of these from the server, it sends back the ACK.
pub fn control_request_ack_map() -> HashMap<u8, u8> {
    [
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

/// Control ACK types the client recognises from the server.
pub fn control_ack_types() -> HashSet<u8> {
    [
        PacketType::STREAM_SYN_ACK,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_RST_ACK,
        PacketType::SOCKS5_SYN_ACK,
        PacketType::STREAM_KEEPALIVE_ACK,
        PacketType::STREAM_WINDOW_UPDATE_ACK,
        PacketType::STREAM_PROBE_ACK,
    ]
    .into_iter()
    .collect()
}

/// SOCKS5-specific error packet types sent by the server.
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

/// Maps each SOCKS5 error packet type to the SOCKS5 REP code byte for the
/// failure reply sent to the local client application.
pub fn socks5_error_reply_map() -> HashMap<u8, u8> {
    [
        (PacketType::SOCKS5_CONNECT_FAIL, 0x01u8),
        (PacketType::SOCKS5_RULESET_DENIED, 0x02),
        (PacketType::SOCKS5_NETWORK_UNREACHABLE, 0x03),
        (PacketType::SOCKS5_HOST_UNREACHABLE, 0x04),
        (PacketType::SOCKS5_CONNECTION_REFUSED, 0x05),
        (PacketType::SOCKS5_TTL_EXPIRED, 0x06),
        (PacketType::SOCKS5_COMMAND_UNSUPPORTED, 0x07),
        (PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED, 0x08),
        (PacketType::SOCKS5_AUTH_FAILED, 0x01),
        (PacketType::SOCKS5_UPSTREAM_UNAVAILABLE, 0x04),
    ]
    .into_iter()
    .collect()
}

/// Packet types that can be packed into a PACKED_CONTROL_BLOCKS payload.
pub fn packable_control_types() -> HashSet<u8> {
    [
        PacketType::STREAM_DATA_ACK,
        PacketType::STREAM_FIN,
        PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_RST,
        PacketType::STREAM_RST_ACK,
        PacketType::STREAM_SYN,
        PacketType::STREAM_SYN_ACK,
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

/// Pre-session packet types that do not require a session cookie.
pub fn pre_session_packet_types() -> HashSet<u8> {
    [
        PacketType::SESSION_INIT,
        PacketType::SESSION_ACCEPT,
        PacketType::MTU_UP_REQ,
        PacketType::MTU_UP_RES,
        PacketType::MTU_DOWN_REQ,
        PacketType::MTU_DOWN_RES,
        PacketType::ERROR_DROP,
    ]
    .into_iter()
    .collect()
}
