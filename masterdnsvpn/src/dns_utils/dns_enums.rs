// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

// References:
// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
// https://en.wikipedia.org/wiki/List_of_DNS_record_types
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

#[allow(non_upper_camel_case_types)]
pub struct PacketType;

impl PacketType {
    // Session / MTU negotiation
    pub const MTU_UP_REQ: u8 = 0x01;
    pub const MTU_UP_RES: u8 = 0x02;
    pub const MTU_DOWN_REQ: u8 = 0x03;
    pub const MTU_DOWN_RES: u8 = 0x04;
    pub const SESSION_INIT: u8 = 0x05;
    pub const SESSION_ACCEPT: u8 = 0x06;
    pub const SET_MTU_REQ: u8 = 0x07;
    pub const SET_MTU_RES: u8 = 0x08;

    // Session liveness
    pub const PING: u8 = 0x09;
    pub const PONG: u8 = 0x0A;

    // Stream lifecycle and data
    pub const STREAM_SYN: u8 = 0x0B;
    pub const STREAM_SYN_ACK: u8 = 0x0C;
    pub const STREAM_DATA: u8 = 0x0D;
    pub const STREAM_DATA_ACK: u8 = 0x0E;
    pub const STREAM_RESEND: u8 = 0x0F;
    pub const PACKED_CONTROL_BLOCKS: u8 = 0x10;

    // Stream closure/reset
    pub const STREAM_FIN: u8 = 0x11;
    pub const STREAM_FIN_ACK: u8 = 0x12;
    pub const STREAM_RST: u8 = 0x13;
    pub const STREAM_RST_ACK: u8 = 0x14;

    // TCP-like stream control
    pub const STREAM_KEEPALIVE: u8 = 0x15;
    pub const STREAM_KEEPALIVE_ACK: u8 = 0x16;
    pub const STREAM_WINDOW_UPDATE: u8 = 0x17;
    pub const STREAM_WINDOW_UPDATE_ACK: u8 = 0x18;
    pub const STREAM_PROBE: u8 = 0x19;
    pub const STREAM_PROBE_ACK: u8 = 0x1A;

    // SOCKS handshake
    pub const SOCKS5_SYN: u8 = 0x1B;
    pub const SOCKS5_SYN_ACK: u8 = 0x1C;

    // SOCKS5 result/error packet types
    pub const SOCKS5_CONNECT_FAIL: u8 = 0x1D;
    pub const SOCKS5_CONNECT_FAIL_ACK: u8 = 0x1E;
    pub const SOCKS5_RULESET_DENIED: u8 = 0x1F;
    pub const SOCKS5_RULESET_DENIED_ACK: u8 = 0x20;
    pub const SOCKS5_NETWORK_UNREACHABLE: u8 = 0x21;
    pub const SOCKS5_NETWORK_UNREACHABLE_ACK: u8 = 0x22;
    pub const SOCKS5_HOST_UNREACHABLE: u8 = 0x23;
    pub const SOCKS5_HOST_UNREACHABLE_ACK: u8 = 0x24;
    pub const SOCKS5_CONNECTION_REFUSED: u8 = 0x25;
    pub const SOCKS5_CONNECTION_REFUSED_ACK: u8 = 0x26;
    pub const SOCKS5_TTL_EXPIRED: u8 = 0x27;
    pub const SOCKS5_TTL_EXPIRED_ACK: u8 = 0x28;
    pub const SOCKS5_COMMAND_UNSUPPORTED: u8 = 0x29;
    pub const SOCKS5_COMMAND_UNSUPPORTED_ACK: u8 = 0x2A;
    pub const SOCKS5_ADDRESS_TYPE_UNSUPPORTED: u8 = 0x2B;
    pub const SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK: u8 = 0x2C;
    pub const SOCKS5_AUTH_FAILED: u8 = 0x2D;
    pub const SOCKS5_AUTH_FAILED_ACK: u8 = 0x2E;
    pub const SOCKS5_UPSTREAM_UNAVAILABLE: u8 = 0x2F;
    pub const SOCKS5_UPSTREAM_UNAVAILABLE_ACK: u8 = 0x30;

    // System/control
    pub const ERROR_DROP: u8 = 0xFF;

    /// Returns all valid packet type values.
    pub fn all_values() -> &'static [u8] {
        &[
            Self::MTU_UP_REQ, Self::MTU_UP_RES, Self::MTU_DOWN_REQ, Self::MTU_DOWN_RES,
            Self::SESSION_INIT, Self::SESSION_ACCEPT, Self::SET_MTU_REQ, Self::SET_MTU_RES,
            Self::PING, Self::PONG,
            Self::STREAM_SYN, Self::STREAM_SYN_ACK, Self::STREAM_DATA, Self::STREAM_DATA_ACK,
            Self::STREAM_RESEND, Self::PACKED_CONTROL_BLOCKS,
            Self::STREAM_FIN, Self::STREAM_FIN_ACK, Self::STREAM_RST, Self::STREAM_RST_ACK,
            Self::STREAM_KEEPALIVE, Self::STREAM_KEEPALIVE_ACK,
            Self::STREAM_WINDOW_UPDATE, Self::STREAM_WINDOW_UPDATE_ACK,
            Self::STREAM_PROBE, Self::STREAM_PROBE_ACK,
            Self::SOCKS5_SYN, Self::SOCKS5_SYN_ACK,
            Self::SOCKS5_CONNECT_FAIL, Self::SOCKS5_CONNECT_FAIL_ACK,
            Self::SOCKS5_RULESET_DENIED, Self::SOCKS5_RULESET_DENIED_ACK,
            Self::SOCKS5_NETWORK_UNREACHABLE, Self::SOCKS5_NETWORK_UNREACHABLE_ACK,
            Self::SOCKS5_HOST_UNREACHABLE, Self::SOCKS5_HOST_UNREACHABLE_ACK,
            Self::SOCKS5_CONNECTION_REFUSED, Self::SOCKS5_CONNECTION_REFUSED_ACK,
            Self::SOCKS5_TTL_EXPIRED, Self::SOCKS5_TTL_EXPIRED_ACK,
            Self::SOCKS5_COMMAND_UNSUPPORTED, Self::SOCKS5_COMMAND_UNSUPPORTED_ACK,
            Self::SOCKS5_ADDRESS_TYPE_UNSUPPORTED, Self::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
            Self::SOCKS5_AUTH_FAILED, Self::SOCKS5_AUTH_FAILED_ACK,
            Self::SOCKS5_UPSTREAM_UNAVAILABLE, Self::SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
            Self::ERROR_DROP,
        ]
    }

    /// Check if a value is a valid packet type.
    pub fn is_valid(v: u8) -> bool {
        Self::all_values().contains(&v)
    }

    /// Get the name of a packet type.
    pub fn name(v: u8) -> &'static str {
        match v {
            Self::MTU_UP_REQ => "MTU_UP_REQ",
            Self::MTU_UP_RES => "MTU_UP_RES",
            Self::MTU_DOWN_REQ => "MTU_DOWN_REQ",
            Self::MTU_DOWN_RES => "MTU_DOWN_RES",
            Self::SESSION_INIT => "SESSION_INIT",
            Self::SESSION_ACCEPT => "SESSION_ACCEPT",
            Self::SET_MTU_REQ => "SET_MTU_REQ",
            Self::SET_MTU_RES => "SET_MTU_RES",
            Self::PING => "PING",
            Self::PONG => "PONG",
            Self::STREAM_SYN => "STREAM_SYN",
            Self::STREAM_SYN_ACK => "STREAM_SYN_ACK",
            Self::STREAM_DATA => "STREAM_DATA",
            Self::STREAM_DATA_ACK => "STREAM_DATA_ACK",
            Self::STREAM_RESEND => "STREAM_RESEND",
            Self::PACKED_CONTROL_BLOCKS => "PACKED_CONTROL_BLOCKS",
            Self::STREAM_FIN => "STREAM_FIN",
            Self::STREAM_FIN_ACK => "STREAM_FIN_ACK",
            Self::STREAM_RST => "STREAM_RST",
            Self::STREAM_RST_ACK => "STREAM_RST_ACK",
            Self::STREAM_KEEPALIVE => "STREAM_KEEPALIVE",
            Self::STREAM_KEEPALIVE_ACK => "STREAM_KEEPALIVE_ACK",
            Self::STREAM_WINDOW_UPDATE => "STREAM_WINDOW_UPDATE",
            Self::STREAM_WINDOW_UPDATE_ACK => "STREAM_WINDOW_UPDATE_ACK",
            Self::STREAM_PROBE => "STREAM_PROBE",
            Self::STREAM_PROBE_ACK => "STREAM_PROBE_ACK",
            Self::SOCKS5_SYN => "SOCKS5_SYN",
            Self::SOCKS5_SYN_ACK => "SOCKS5_SYN_ACK",
            Self::SOCKS5_CONNECT_FAIL => "SOCKS5_CONNECT_FAIL",
            Self::SOCKS5_CONNECT_FAIL_ACK => "SOCKS5_CONNECT_FAIL_ACK",
            Self::SOCKS5_RULESET_DENIED => "SOCKS5_RULESET_DENIED",
            Self::SOCKS5_RULESET_DENIED_ACK => "SOCKS5_RULESET_DENIED_ACK",
            Self::SOCKS5_NETWORK_UNREACHABLE => "SOCKS5_NETWORK_UNREACHABLE",
            Self::SOCKS5_NETWORK_UNREACHABLE_ACK => "SOCKS5_NETWORK_UNREACHABLE_ACK",
            Self::SOCKS5_HOST_UNREACHABLE => "SOCKS5_HOST_UNREACHABLE",
            Self::SOCKS5_HOST_UNREACHABLE_ACK => "SOCKS5_HOST_UNREACHABLE_ACK",
            Self::SOCKS5_CONNECTION_REFUSED => "SOCKS5_CONNECTION_REFUSED",
            Self::SOCKS5_CONNECTION_REFUSED_ACK => "SOCKS5_CONNECTION_REFUSED_ACK",
            Self::SOCKS5_TTL_EXPIRED => "SOCKS5_TTL_EXPIRED",
            Self::SOCKS5_TTL_EXPIRED_ACK => "SOCKS5_TTL_EXPIRED_ACK",
            Self::SOCKS5_COMMAND_UNSUPPORTED => "SOCKS5_COMMAND_UNSUPPORTED",
            Self::SOCKS5_COMMAND_UNSUPPORTED_ACK => "SOCKS5_COMMAND_UNSUPPORTED_ACK",
            Self::SOCKS5_ADDRESS_TYPE_UNSUPPORTED => "SOCKS5_ADDRESS_TYPE_UNSUPPORTED",
            Self::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK => "SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK",
            Self::SOCKS5_AUTH_FAILED => "SOCKS5_AUTH_FAILED",
            Self::SOCKS5_AUTH_FAILED_ACK => "SOCKS5_AUTH_FAILED_ACK",
            Self::SOCKS5_UPSTREAM_UNAVAILABLE => "SOCKS5_UPSTREAM_UNAVAILABLE",
            Self::SOCKS5_UPSTREAM_UNAVAILABLE_ACK => "SOCKS5_UPSTREAM_UNAVAILABLE_ACK",
            Self::ERROR_DROP => "ERROR_DROP",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open = 1,
    HalfClosedLocal = 2,
    HalfClosedRemote = 3,
    Draining = 4,
    Closing = 5,
    TimeWait = 6,
    Reset = 7,
    Closed = 8,
}

// DNS Resource Record Types (qType)
pub struct DnsRecordType;

impl DnsRecordType {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const MD: u16 = 3;
    pub const MF: u16 = 4;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const MB: u16 = 7;
    pub const MG: u16 = 8;
    pub const MR: u16 = 9;
    pub const NULL: u16 = 10;
    pub const WKS: u16 = 11;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MINFO: u16 = 14;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const RP: u16 = 17;
    pub const AFSDB: u16 = 18;
    pub const X25: u16 = 19;
    pub const ISDN: u16 = 20;
    pub const RT: u16 = 21;
    pub const NSAP: u16 = 22;
    pub const NSAP_PTR: u16 = 23;
    pub const SIG: u16 = 24;
    pub const KEY: u16 = 25;
    pub const PX: u16 = 26;
    pub const GPOS: u16 = 27;
    pub const AAAA: u16 = 28;
    pub const LOC: u16 = 29;
    pub const NXT: u16 = 30;
    pub const EID: u16 = 31;
    pub const NIMLOC: u16 = 32;
    pub const SRV: u16 = 33;
    pub const ATMA: u16 = 34;
    pub const NAPTR: u16 = 35;
    pub const KX: u16 = 36;
    pub const CERT: u16 = 37;
    pub const A6: u16 = 38;
    pub const DNAME: u16 = 39;
    pub const SINK: u16 = 40;
    pub const OPT: u16 = 41;
    pub const APL: u16 = 42;
    pub const DS: u16 = 43;
    pub const SSHFP: u16 = 44;
    pub const IPSECKEY: u16 = 45;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const DHCID: u16 = 49;
    pub const NSEC3: u16 = 50;
    pub const NSEC3PARAM: u16 = 51;
    pub const TLSA: u16 = 52;
    pub const SMIMEA: u16 = 53;
    pub const HIP: u16 = 55;
    pub const NINFO: u16 = 56;
    pub const RKEY: u16 = 57;
    pub const TALINK: u16 = 58;
    pub const CDS: u16 = 59;
    pub const CDNSKEY: u16 = 60;
    pub const OPENPGPKEY: u16 = 61;
    pub const CSYNC: u16 = 62;
    pub const ZONEMD: u16 = 63;
    pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65;
    pub const DSYNC: u16 = 66;
    pub const HHIT: u16 = 67;
    pub const BRID: u16 = 68;
    pub const SPF: u16 = 99;
    pub const UINFO: u16 = 100;
    pub const UID: u16 = 101;
    pub const GID: u16 = 102;
    pub const UNSPEC: u16 = 103;
    pub const NID: u16 = 104;
    pub const L32: u16 = 105;
    pub const L64: u16 = 106;
    pub const LP: u16 = 107;
    pub const EUI48: u16 = 108;
    pub const EUI64: u16 = 109;
    pub const NXNAME: u16 = 128;
    pub const TKEY: u16 = 249;
    pub const TSIG: u16 = 250;
    pub const IXFR: u16 = 251;
    pub const AXFR: u16 = 252;
    pub const MAILB: u16 = 253;
    pub const MAILA: u16 = 254;
    pub const ANY: u16 = 255;
    pub const URI: u16 = 256;
    pub const CAA: u16 = 257;
    pub const AVC: u16 = 258;
    pub const DOA: u16 = 259;
    pub const AMTRELAY: u16 = 260;
    pub const RESINFO: u16 = 261;
    pub const WALLET: u16 = 262;
    pub const CLA: u16 = 263;
    pub const IPN: u16 = 264;
    pub const TA: u16 = 32768;
    pub const DLV: u16 = 32769;

    /// Returns all valid record type values.
    pub fn all_values() -> Vec<u16> {
        vec![
            Self::A, Self::NS, Self::MD, Self::MF, Self::CNAME, Self::SOA,
            Self::MB, Self::MG, Self::MR, Self::NULL, Self::WKS, Self::PTR,
            Self::HINFO, Self::MINFO, Self::MX, Self::TXT, Self::RP, Self::AFSDB,
            Self::X25, Self::ISDN, Self::RT, Self::NSAP, Self::NSAP_PTR, Self::SIG,
            Self::KEY, Self::PX, Self::GPOS, Self::AAAA, Self::LOC, Self::NXT,
            Self::EID, Self::NIMLOC, Self::SRV, Self::ATMA, Self::NAPTR, Self::KX,
            Self::CERT, Self::A6, Self::DNAME, Self::SINK, Self::OPT, Self::APL,
            Self::DS, Self::SSHFP, Self::IPSECKEY, Self::RRSIG, Self::NSEC, Self::DNSKEY,
            Self::DHCID, Self::NSEC3, Self::NSEC3PARAM, Self::TLSA, Self::SMIMEA,
            Self::HIP, Self::NINFO, Self::RKEY, Self::TALINK, Self::CDS, Self::CDNSKEY,
            Self::OPENPGPKEY, Self::CSYNC, Self::ZONEMD, Self::SVCB, Self::HTTPS,
            Self::DSYNC, Self::HHIT, Self::BRID, Self::SPF, Self::UINFO, Self::UID,
            Self::GID, Self::UNSPEC, Self::NID, Self::L32, Self::L64, Self::LP,
            Self::EUI48, Self::EUI64, Self::NXNAME, Self::TKEY, Self::TSIG,
            Self::IXFR, Self::AXFR, Self::MAILB, Self::MAILA, Self::ANY, Self::URI,
            Self::CAA, Self::AVC, Self::DOA, Self::AMTRELAY, Self::RESINFO,
            Self::WALLET, Self::CLA, Self::IPN, Self::TA, Self::DLV,
        ]
    }
}

// rCode Values
pub struct DnsRCode;

impl DnsRCode {
    pub const NO_ERROR: u8 = 0;
    pub const FORMAT_ERROR: u8 = 1;
    pub const SERVER_FAILURE: u8 = 2;
    pub const NAME_ERROR: u8 = 3;
    pub const NOT_IMPLEMENTED: u8 = 4;
    pub const REFUSED: u8 = 5;
    pub const YXDOMAIN: u8 = 6;
    pub const YXRRSET: u8 = 7;
    pub const NXRRSET: u8 = 8;
    pub const NOT_AUTHORIZED: u8 = 9;
    pub const NOT_ZONE: u8 = 10;
}

// qClass Values
pub struct DnsQClass;

impl DnsQClass {
    pub const IN: u16 = 1;
    pub const CS: u16 = 2;
    pub const CH: u16 = 3;
    pub const HS: u16 = 4;
    pub const ANY: u16 = 255;
}
