// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashSet;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use base32;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use md5::{Digest as Md5Digest, Md5};
use rand::Rng;
use sha2::{Digest as Sha2Digest, Sha256};

use super::dns_enums::{DnsQClass, DnsRCode, DnsRecordType, PacketType};

/// Lazily computed sets for packet type extensions.
lazy_static_sets! {}

// We'll use module-level functions and a struct instead of lazy_static

fn pt_stream_ext() -> HashSet<u8> {
    [
        PacketType::STREAM_SYN, PacketType::STREAM_SYN_ACK,
        PacketType::STREAM_DATA, PacketType::STREAM_DATA_ACK,
        PacketType::STREAM_RESEND,
        PacketType::STREAM_FIN, PacketType::STREAM_FIN_ACK,
        PacketType::STREAM_RST, PacketType::STREAM_RST_ACK,
        PacketType::STREAM_KEEPALIVE, PacketType::STREAM_KEEPALIVE_ACK,
        PacketType::STREAM_WINDOW_UPDATE, PacketType::STREAM_WINDOW_UPDATE_ACK,
        PacketType::STREAM_PROBE, PacketType::STREAM_PROBE_ACK,
        PacketType::MTU_UP_REQ, PacketType::MTU_DOWN_RES,
        PacketType::SOCKS5_SYN, PacketType::SOCKS5_SYN_ACK,
        PacketType::SOCKS5_CONNECT_FAIL, PacketType::SOCKS5_CONNECT_FAIL_ACK,
        PacketType::SOCKS5_RULESET_DENIED, PacketType::SOCKS5_RULESET_DENIED_ACK,
        PacketType::SOCKS5_NETWORK_UNREACHABLE, PacketType::SOCKS5_NETWORK_UNREACHABLE_ACK,
        PacketType::SOCKS5_HOST_UNREACHABLE, PacketType::SOCKS5_HOST_UNREACHABLE_ACK,
        PacketType::SOCKS5_CONNECTION_REFUSED, PacketType::SOCKS5_CONNECTION_REFUSED_ACK,
        PacketType::SOCKS5_TTL_EXPIRED, PacketType::SOCKS5_TTL_EXPIRED_ACK,
        PacketType::SOCKS5_COMMAND_UNSUPPORTED, PacketType::SOCKS5_COMMAND_UNSUPPORTED_ACK,
        PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED, PacketType::SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        PacketType::SOCKS5_AUTH_FAILED, PacketType::SOCKS5_AUTH_FAILED_ACK,
        PacketType::SOCKS5_UPSTREAM_UNAVAILABLE, PacketType::SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    ].into_iter().collect()
}

fn pt_seq_ext() -> HashSet<u8> {
    // Same set as stream ext in this protocol
    pt_stream_ext()
}

fn pt_frag_ext() -> HashSet<u8> {
    [
        PacketType::STREAM_DATA, PacketType::STREAM_RESEND,
        PacketType::MTU_UP_REQ, PacketType::MTU_DOWN_RES,
        PacketType::SOCKS5_SYN,
    ].into_iter().collect()
}

fn pt_comp_ext() -> HashSet<u8> {
    [
        PacketType::STREAM_DATA, PacketType::STREAM_RESEND,
        PacketType::PACKED_CONTROL_BLOCKS,
    ].into_iter().collect()
}

fn valid_packet_types() -> HashSet<u8> {
    PacketType::all_values().iter().cloned().collect()
}

fn valid_qtypes() -> HashSet<u16> {
    DnsRecordType::all_values().into_iter().collect()
}

const VPN_HEADER_INTEGRITY_LEN: usize = 2;
const LOG2_36: usize = 5;
const PACKED_CONTROL_BLOCK_SIZE: usize = 5; // packet_type(1) + stream_id(2) + sequence_num(2)

#[derive(Debug, Clone)]
pub struct DnsHeaders {
    pub id: u16,
    pub qr: u8,
    pub opcode: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub z: u8,
    pub rcode: u8,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub headers: DnsHeaders,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

#[derive(Debug, Clone)]
pub struct VpnHeaderData {
    pub session_id: u8,
    pub packet_type: u8,
    pub stream_id: Option<u16>,
    pub sequence_num: Option<u16>,
    pub fragment_id: Option<u8>,
    pub total_fragments: Option<u8>,
    pub total_data_length: Option<u16>,
    pub compression_type: Option<u8>,
    pub session_cookie: u8,
}

/// DNS Packet Parser and Builder for VPN over DNS tunneling.
pub struct DnsPacketParser {
    pub encryption_key: Vec<u8>,
    pub encryption_method: u8,
    key: Vec<u8>,

    // Precomputed sets
    pt_stream: HashSet<u8>,
    pt_seq: HashSet<u8>,
    pt_frag: HashSet<u8>,
    pt_comp: HashSet<u8>,
    valid_packets: HashSet<u8>,
    valid_qtypes: HashSet<u16>,
    max_vpn_header_raw_size: usize,
}

impl DnsPacketParser {
    pub fn new(
        encryption_key: &str,
        encryption_method: u8,
    ) -> Self {
        let method = if ![0, 1, 2, 3, 4, 5].contains(&encryption_method) {
            tracing::debug!(
                "Invalid encryption_method value: {}. Defaulting to 1 (XOR encryption).",
                encryption_method
            );
            1
        } else {
            encryption_method
        };

        let enc_key_bytes = encryption_key.as_bytes().to_vec();
        let derived = Self::derive_key_static(encryption_key.as_bytes(), method);

        let pts = pt_stream_ext();
        let ptseq = pt_seq_ext();
        let ptf = pt_frag_ext();
        let ptc = pt_comp_ext();
        let vp = valid_packet_types();
        let vq = valid_qtypes();

        let max_hdr = PacketType::all_values()
            .iter()
            .map(|&pt| Self::vpn_header_raw_size_static(pt, &pts, &ptseq, &ptf, &ptc))
            .max()
            .unwrap_or(4);

        DnsPacketParser {
            encryption_key: enc_key_bytes,
            encryption_method: method,
            key: derived,
            pt_stream: pts,
            pt_seq: ptseq,
            pt_frag: ptf,
            pt_comp: ptc,
            valid_packets: vp,
            valid_qtypes: vq,
            max_vpn_header_raw_size: max_hdr,
        }
    }

    // -------------------------------------------------------------------------
    // VPN Header Size
    // -------------------------------------------------------------------------
    fn vpn_header_raw_size_static(
        packet_type: u8,
        pts: &HashSet<u8>,
        ptseq: &HashSet<u8>,
        ptf: &HashSet<u8>,
        ptc: &HashSet<u8>,
    ) -> usize {
        let mut size: usize = 2; // session_id + packet_type
        if pts.contains(&packet_type) { size += 2; }
        if ptseq.contains(&packet_type) { size += 2; }
        if ptf.contains(&packet_type) { size += 4; }
        if ptc.contains(&packet_type) { size += 1; }
        size + VPN_HEADER_INTEGRITY_LEN
    }

    pub fn get_vpn_header_raw_size(&self, packet_type: u8) -> usize {
        Self::vpn_header_raw_size_static(
            packet_type, &self.pt_stream, &self.pt_seq, &self.pt_frag, &self.pt_comp,
        )
    }

    pub fn get_max_vpn_header_raw_size(&self) -> usize {
        self.max_vpn_header_raw_size
    }

    // -------------------------------------------------------------------------
    // Header integrity check byte
    // -------------------------------------------------------------------------
    fn compute_header_check_byte(header_bytes: &[u8]) -> u8 {
        let mut acc: u8 = ((header_bytes.len().wrapping_mul(17)).wrapping_add(0x5D)) as u8;
        for (idx, &value) in header_bytes.iter().enumerate() {
            acc = acc.wrapping_add(value).wrapping_add(idx as u8);
            acc ^= value.wrapping_shl((idx & 0x03) as u32);
        }
        acc
    }

    // -------------------------------------------------------------------------
    // DNS Packet Parsing
    // -------------------------------------------------------------------------
    pub fn parse_dns_headers(data: &[u8]) -> Option<DnsHeaders> {
        if data.len() < 12 {
            return None;
        }
        let pkt_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qd = u16::from_be_bytes([data[4], data[5]]);
        let an = u16::from_be_bytes([data[6], data[7]]);
        let ns = u16::from_be_bytes([data[8], data[9]]);
        let ar = u16::from_be_bytes([data[10], data[11]]);

        Some(DnsHeaders {
            id: pkt_id,
            qr: ((flags >> 15) & 0x1) as u8,
            opcode: ((flags >> 11) & 0xF) as u8,
            aa: ((flags >> 10) & 0x1) as u8,
            tc: ((flags >> 9) & 0x1) as u8,
            rd: ((flags >> 8) & 0x1) as u8,
            ra: ((flags >> 7) & 0x1) as u8,
            z: ((flags >> 4) & 0x7) as u8,
            rcode: (flags & 0xF) as u8,
            qd_count: qd,
            an_count: an,
            ns_count: ns,
            ar_count: ar,
        })
    }

    fn parse_dns_name_from_bytes(data: &[u8], offset: usize) -> Result<(String, usize), &'static str> {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let data_len = data.len();
        let mut off = offset;
        let mut jumped = false;
        let mut jumps = 0;
        let mut orig_off = offset;

        loop {
            if off >= data_len {
                return Err("Bounds");
            }
            let length = data[off] as usize;

            if length == 0 {
                off += 1;
                break;
            }

            if length & 0xC0 == 0xC0 {
                if off + 1 >= data_len {
                    return Err("Bounds");
                }
                if jumps > 10 {
                    return Err("Loop");
                }
                if !jumped {
                    orig_off = off + 2;
                    jumped = true;
                }
                off = ((length & 0x3F) << 8) | (data[off + 1] as usize);
                jumps += 1;
                continue;
            }

            off += 1;
            let end = off + length;
            if end > data_len {
                return Err("Bounds");
            }
            labels.push(data[off..end].to_vec());
            off = end;
        }

        let name = labels
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect::<Vec<_>>()
            .join(".");

        Ok((name, if jumped { orig_off } else { off }))
    }

    pub fn parse_dns_question(
        data: &[u8],
        qd_count: u16,
        offset: usize,
    ) -> (Vec<DnsQuestion>, usize) {
        let mut questions = Vec::new();
        let mut off = offset;

        for _ in 0..qd_count {
            match Self::parse_dns_name_from_bytes(data, off) {
                Ok((name, new_off)) => {
                    off = new_off;
                    if off + 4 > data.len() {
                        return (questions, off);
                    }
                    let qtype = u16::from_be_bytes([data[off], data[off + 1]]);
                    let qclass = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                    off += 4;
                    questions.push(DnsQuestion {
                        qname: name,
                        qtype,
                        qclass,
                    });
                }
                Err(_) => return (questions, off),
            }
        }

        (questions, off)
    }

    fn parse_resource_records(
        data: &[u8],
        count: u16,
        offset: usize,
    ) -> (Vec<DnsResourceRecord>, usize) {
        let mut records = Vec::new();
        let mut off = offset;

        for _ in 0..count {
            match Self::parse_dns_name_from_bytes(data, off) {
                Ok((name, new_off)) => {
                    off = new_off;
                    if off + 10 > data.len() {
                        return (records, off);
                    }
                    let rr_type = u16::from_be_bytes([data[off], data[off + 1]]);
                    let rr_class = u16::from_be_bytes([data[off + 2], data[off + 3]]);
                    let ttl = u32::from_be_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
                    let rd_length = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
                    off += 10;
                    let end_rd = off + rd_length;
                    if end_rd > data.len() {
                        return (records, off);
                    }
                    let rdata = data[off..end_rd].to_vec();
                    off = end_rd;
                    records.push(DnsResourceRecord {
                        name,
                        rr_type,
                        rr_class,
                        ttl,
                        rdata,
                    });
                }
                Err(_) => return (records, off),
            }
        }

        (records, off)
    }

    pub fn parse_dns_packet(data: &[u8]) -> Option<DnsPacket> {
        if data.len() < 12 {
            return None;
        }
        let headers = Self::parse_dns_headers(data)?;
        let mut offset = 12usize;

        let (questions, new_off) = Self::parse_dns_question(data, headers.qd_count, offset);
        offset = new_off;

        let (answers, new_off) = Self::parse_resource_records(data, headers.an_count, offset);
        offset = new_off;

        let (authorities, new_off) = Self::parse_resource_records(data, headers.ns_count, offset);
        offset = new_off;

        let (additional, _) = Self::parse_resource_records(data, headers.ar_count, offset);

        Some(DnsPacket {
            headers,
            questions,
            answers,
            authorities,
            additional,
        })
    }

    // -------------------------------------------------------------------------
    // DNS Response Builders
    // -------------------------------------------------------------------------
    pub fn server_fail_response(request_data: &[u8]) -> Vec<u8> {
        if request_data.len() < 12 {
            return Vec::new();
        }
        let pkt_id = u16::from_be_bytes([request_data[0], request_data[1]]);
        let flags = (u16::from_be_bytes([request_data[2], request_data[3]]) | 0x8000) & 0xFFF0 | 0x0002;
        let qdcount = u16::from_be_bytes([request_data[4], request_data[5]]);

        let mut result = Vec::with_capacity(12 + request_data.len() - 12);
        result.extend_from_slice(&pkt_id.to_be_bytes());
        result.extend_from_slice(&flags.to_be_bytes());
        result.extend_from_slice(&qdcount.to_be_bytes());
        result.extend_from_slice(&0u16.to_be_bytes()); // an
        result.extend_from_slice(&0u16.to_be_bytes()); // ns
        result.extend_from_slice(&0u16.to_be_bytes()); // ar
        result.extend_from_slice(&request_data[12..]);
        result
    }

    fn basic_response_with_rcode(request_data: &[u8], rcode: u8) -> Vec<u8> {
        if request_data.len() < 12 {
            return Vec::new();
        }
        let pkt_id = u16::from_be_bytes([request_data[0], request_data[1]]);
        let mut flags = u16::from_be_bytes([request_data[2], request_data[3]]) | 0x8000;
        flags = (flags & 0xFFF0) | ((rcode as u16) & 0xF);
        let qd_count = u16::from_be_bytes([request_data[4], request_data[5]]);
        let ar_count = u16::from_be_bytes([request_data[10], request_data[11]]);

        let mut offset = 12usize;
        for _ in 0..qd_count {
            match Self::parse_dns_name_from_bytes(request_data, offset) {
                Ok((_, new_off)) => {
                    offset = new_off + 4;
                }
                Err(_) => break,
            }
        }

        let (res_ar_count, edns0_bytes): (u16, &[u8]) = if ar_count > 0 {
            (1, b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00")
        } else {
            (0, b"")
        };

        let mut result = Vec::new();
        result.extend_from_slice(&pkt_id.to_be_bytes());
        result.extend_from_slice(&flags.to_be_bytes());
        result.extend_from_slice(&qd_count.to_be_bytes());
        result.extend_from_slice(&0u16.to_be_bytes());
        result.extend_from_slice(&0u16.to_be_bytes());
        result.extend_from_slice(&res_ar_count.to_be_bytes());
        result.extend_from_slice(&request_data[12..offset]);
        if !edns0_bytes.is_empty() {
            result.extend_from_slice(edns0_bytes);
        }
        result
    }

    pub fn empty_noerror_response(request_data: &[u8]) -> Vec<u8> {
        Self::basic_response_with_rcode(request_data, DnsRCode::NO_ERROR)
    }

    pub fn format_error_response(request_data: &[u8]) -> Vec<u8> {
        Self::basic_response_with_rcode(request_data, DnsRCode::FORMAT_ERROR)
    }

    pub fn refused_response(request_data: &[u8]) -> Vec<u8> {
        Self::basic_response_with_rcode(request_data, DnsRCode::REFUSED)
    }

    // -------------------------------------------------------------------------
    // DNS Name Serialization
    // -------------------------------------------------------------------------
    fn serialize_dns_name(name: &str) -> Vec<u8> {
        let b_name = name.as_bytes();
        if b_name.is_empty() || b_name == b"." {
            return vec![0u8];
        }

        let mut result = Vec::new();
        for part in b_name.split(|&b| b == b'.') {
            let label_len = part.len();
            if label_len > 0 {
                if label_len > 63 {
                    return vec![0u8];
                }
                result.push(label_len as u8);
                result.extend_from_slice(part);
            }
        }
        result.push(0);
        result
    }

    fn serialize_resource_record(record: &DnsResourceRecord, compress_pointer: Option<&[u8]>) -> Vec<u8> {
        let name_bytes = match compress_pointer {
            Some(ptr) => ptr.to_vec(),
            None => Self::serialize_dns_name(&record.name),
        };

        let mut result = Vec::new();
        result.extend_from_slice(&name_bytes);
        result.extend_from_slice(&record.rr_type.to_be_bytes());
        result.extend_from_slice(&record.rr_class.to_be_bytes());
        result.extend_from_slice(&record.ttl.to_be_bytes());
        result.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
        result.extend_from_slice(&record.rdata);
        result
    }

    pub fn simple_answer_packet(answers: &[DnsResourceRecord], question_packet: &[u8]) -> Vec<u8> {
        if question_packet.len() < 12 {
            return Vec::new();
        }

        let pkt_id = u16::from_be_bytes([question_packet[0], question_packet[1]]);
        let flags = u16::from_be_bytes([question_packet[2], question_packet[3]]) | 0x8000;
        let qd_count = u16::from_be_bytes([question_packet[4], question_packet[5]]);
        let ar_count = u16::from_be_bytes([question_packet[10], question_packet[11]]);

        let mut offset = 12usize;
        for _ in 0..qd_count {
            match Self::parse_dns_name_from_bytes(question_packet, offset) {
                Ok((_, new_off)) => offset = new_off + 4,
                Err(_) => break,
            }
        }

        let (res_ar_count, edns0_bytes): (u16, &[u8]) = if ar_count > 0 {
            (1, b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00")
        } else {
            (0, b"")
        };

        let mut result = Vec::new();
        result.extend_from_slice(&pkt_id.to_be_bytes());
        result.extend_from_slice(&flags.to_be_bytes());
        result.extend_from_slice(&qd_count.to_be_bytes());
        result.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        result.extend_from_slice(&0u16.to_be_bytes());
        result.extend_from_slice(&res_ar_count.to_be_bytes());
        result.extend_from_slice(&question_packet[12..offset]);

        for ans in answers {
            result.extend_from_slice(&Self::serialize_resource_record(ans, Some(b"\xc0\x0c")));
        }

        if res_ar_count > 0 {
            result.extend_from_slice(edns0_bytes);
        }

        result
    }

    pub fn simple_question_packet(&self, domain: &str, q_type: u16) -> Vec<u8> {
        if !self.valid_qtypes.contains(&q_type) {
            return Vec::new();
        }

        let mut rng = rand::thread_rng();
        let pkt_id: u16 = rng.gen();

        let mut result = Vec::new();
        // Header
        result.extend_from_slice(&pkt_id.to_be_bytes());
        result.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        result.extend_from_slice(&1u16.to_be_bytes()); // QD=1
        result.extend_from_slice(&0u16.to_be_bytes()); // AN=0
        result.extend_from_slice(&0u16.to_be_bytes()); // NS=0
        result.extend_from_slice(&1u16.to_be_bytes()); // AR=1 (EDNS0)

        // Question section
        result.extend_from_slice(&Self::serialize_dns_name(domain));
        result.extend_from_slice(&q_type.to_be_bytes());
        result.extend_from_slice(&DnsQClass::IN.to_be_bytes());

        // EDNS0 OPT record
        result.extend_from_slice(b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00");

        result
    }

    // -------------------------------------------------------------------------
    // Base Encoding/Decoding
    // -------------------------------------------------------------------------
    pub fn base_encode(data: &[u8], lower_case_only: bool) -> String {
        if data.is_empty() {
            return String::new();
        }

        if lower_case_only {
            let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, data);
            encoded.to_lowercase()
        } else {
            BASE64_STANDARD.encode(data)
        }
    }

    pub fn base_decode(encoded_str: &str, lower_case_only: bool) -> Vec<u8> {
        if encoded_str.is_empty() {
            return Vec::new();
        }

        if lower_case_only {
            let upper = encoded_str.to_uppercase();
            // Add padding
            let pad_len = (8 - (upper.len() % 8)) % 8;
            let padded = format!("{}{}", upper, "=".repeat(pad_len));
            base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &padded)
                .unwrap_or_default()
        } else {
            let pad_len = (4 - (encoded_str.len() % 4)) % 4;
            let padded = format!("{}{}", encoded_str, "=".repeat(pad_len));
            BASE64_STANDARD.decode(&padded).unwrap_or_default()
        }
    }

    // -------------------------------------------------------------------------
    // Encryption / Decryption
    // -------------------------------------------------------------------------
    fn derive_key_static(raw_key: &[u8], method: u8) -> Vec<u8> {
        match method {
            2 | 5 => {
                let mut hasher = Sha256::new();
                hasher.update(raw_key);
                hasher.finalize().to_vec()
            }
            3 => {
                let mut hasher = Md5::new();
                hasher.update(raw_key);
                hasher.finalize().to_vec()
            }
            4 => {
                // 24 bytes: pad/truncate
                let mut result = raw_key.to_vec();
                result.resize(24, 0);
                result
            }
            _ => {
                // Default: 32 bytes padded
                let mut result = raw_key.to_vec();
                result.resize(32, 0);
                result
            }
        }
    }

    pub fn xor_data(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() || data.is_empty() {
            return data.to_vec();
        }
        let k_len = key.len();
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % k_len])
            .collect()
    }

    pub fn data_encrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return data.to_vec();
        }
        match self.encryption_method {
            0 => data.to_vec(),
            1 => Self::xor_data(data, &self.key),
            2 => self.chacha_encrypt(data),
            3 | 4 | 5 => self.aes_encrypt(data),
            _ => data.to_vec(),
        }
    }

    pub fn data_decrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return data.to_vec();
        }
        match self.encryption_method {
            0 => data.to_vec(),
            1 => Self::xor_data(data, &self.key),
            2 => self.chacha_decrypt(data),
            3 | 4 | 5 => self.aes_decrypt(data),
            _ => data.to_vec(),
        }
    }

    fn aes_encrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return data.to_vec();
        }
        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let result = match self.encryption_method {
            3 => {
                // AES-128-GCM (16-byte key)
                let cipher = Aes128Gcm::new_from_slice(&self.key[..16]);
                match cipher {
                    Ok(c) => c.encrypt(nonce, data),
                    Err(_) => return Vec::new(),
                }
            }
            5 => {
                // AES-256-GCM (32-byte key)
                let cipher = Aes256Gcm::new_from_slice(&self.key[..32]);
                match cipher {
                    Ok(c) => c.encrypt(nonce, data),
                    Err(_) => return Vec::new(),
                }
            }
            4 => {
                // AES-192-GCM - use AES-256 with padded key as aes-gcm crate doesn't natively support 192
                // Pad to 32 bytes
                let mut key32 = [0u8; 32];
                let copy_len = self.key.len().min(32);
                key32[..copy_len].copy_from_slice(&self.key[..copy_len]);
                let cipher = Aes256Gcm::new_from_slice(&key32);
                match cipher {
                    Ok(c) => c.encrypt(nonce, data),
                    Err(_) => return Vec::new(),
                }
            }
            _ => return Vec::new(),
        };

        match result {
            Ok(ciphertext) => {
                let mut output = Vec::with_capacity(12 + ciphertext.len());
                output.extend_from_slice(&nonce_bytes);
                output.extend_from_slice(&ciphertext);
                output
            }
            Err(_) => Vec::new(),
        }
    }

    fn aes_decrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.len() <= 12 {
            return Vec::new();
        }
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let result = match self.encryption_method {
            3 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key[..16]);
                match cipher {
                    Ok(c) => c.decrypt(nonce, ciphertext),
                    Err(_) => return Vec::new(),
                }
            }
            5 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key[..32]);
                match cipher {
                    Ok(c) => c.decrypt(nonce, ciphertext),
                    Err(_) => return Vec::new(),
                }
            }
            4 => {
                let mut key32 = [0u8; 32];
                let copy_len = self.key.len().min(32);
                key32[..copy_len].copy_from_slice(&self.key[..copy_len]);
                let cipher = Aes256Gcm::new_from_slice(&key32);
                match cipher {
                    Ok(c) => c.decrypt(nonce, ciphertext),
                    Err(_) => return Vec::new(),
                }
            }
            _ => return Vec::new(),
        };

        result.unwrap_or_default()
    }

    fn chacha_encrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return data.to_vec();
        }
        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; 12]; // ChaCha20 uses 12-byte nonce in this crate
        rng.fill(&mut nonce_bytes);

        let key_arr: [u8; 32] = {
            let mut k = [0u8; 32];
            let copy_len = self.key.len().min(32);
            k[..copy_len].copy_from_slice(&self.key[..copy_len]);
            k
        };

        let mut cipher = ChaCha20::new(&key_arr.into(), &nonce_bytes.into());
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);

        // Python uses 16-byte nonce; we prepend 16 bytes (12 nonce + 4 zero padding) for compat
        let mut output = Vec::with_capacity(16 + buffer.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&[0u8; 4]); // pad to 16 bytes like Python
        output.extend_from_slice(&buffer);
        output
    }

    fn chacha_decrypt(&self, data: &[u8]) -> Vec<u8> {
        if data.len() <= 16 {
            return Vec::new();
        }
        let nonce_bytes: [u8; 12] = {
            let mut n = [0u8; 12];
            n.copy_from_slice(&data[..12]);
            n
        };
        let ciphertext = &data[16..]; // skip 16 bytes (12 nonce + 4 pad)

        let key_arr: [u8; 32] = {
            let mut k = [0u8; 32];
            let copy_len = self.key.len().min(32);
            k[..copy_len].copy_from_slice(&self.key[..copy_len]);
            k
        };

        let mut cipher = ChaCha20::new(&key_arr.into(), &nonce_bytes.into());
        let mut buffer = ciphertext.to_vec();
        cipher.apply_keystream(&mut buffer);
        buffer
    }

    pub fn codec_transform(&self, data: &[u8], encrypt: bool) -> Vec<u8> {
        if self.encryption_method == 0 {
            return data.to_vec();
        }
        if encrypt {
            self.data_encrypt(data)
        } else {
            self.data_decrypt(data)
        }
    }

    // -------------------------------------------------------------------------
    // Encode / Decode helpers
    // -------------------------------------------------------------------------
    pub fn encrypt_and_encode_data(&self, data: &[u8], lower_case_only: bool) -> String {
        if data.is_empty() {
            return String::new();
        }
        if self.encryption_method == 0 {
            return Self::base_encode(data, lower_case_only);
        }
        let encrypted = self.codec_transform(data, true);
        Self::base_encode(&encrypted, lower_case_only)
    }

    pub fn decode_and_decrypt_data(&self, encoded_str: &str, lower_case_only: bool) -> Vec<u8> {
        if encoded_str.is_empty() {
            return Vec::new();
        }
        if self.encryption_method == 0 {
            return Self::base_decode(encoded_str, lower_case_only);
        }
        let data_encrypted = Self::base_decode(encoded_str, lower_case_only);
        if data_encrypted.is_empty() {
            return Vec::new();
        }
        self.codec_transform(&data_encrypted, false)
    }

    // -------------------------------------------------------------------------
    // VPN Header Creation / Parsing
    // -------------------------------------------------------------------------
    pub fn create_vpn_header(
        &self,
        session_id: u8,
        packet_type: u8,
        base36_encode: bool,
        stream_id: u16,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        total_data_length: u16,
        compression_type: u8,
        session_cookie: u8,
        encrypt_data: bool,
        base_encode: bool,
    ) -> Vec<u8> {
        let mut h_list: Vec<u8> = vec![session_id, packet_type];

        if self.pt_stream.contains(&packet_type) {
            h_list.push((stream_id >> 8) as u8);
            h_list.push((stream_id & 0xFF) as u8);
        }

        if self.pt_seq.contains(&packet_type) {
            h_list.push((sequence_num >> 8) as u8);
            h_list.push((sequence_num & 0xFF) as u8);
        }

        if self.pt_frag.contains(&packet_type) {
            h_list.push(fragment_id);
            h_list.push(total_fragments);
            h_list.push((total_data_length >> 8) as u8);
            h_list.push((total_data_length & 0xFF) as u8);
        }

        if self.pt_comp.contains(&packet_type) {
            h_list.push(compression_type);
        }

        h_list.push(session_cookie);
        let check = Self::compute_header_check_byte(&h_list);
        h_list.push(check);

        let encrypted_header = if !encrypt_data || self.encryption_method == 0 {
            h_list
        } else {
            self.codec_transform(&h_list, true)
        };

        if !base_encode {
            return encrypted_header;
        }

        Self::base_encode(&encrypted_header, base36_encode).into_bytes()
    }

    /// Returns string form of the header for DNS label embedding.
    pub fn create_vpn_header_string(
        &self,
        session_id: u8,
        packet_type: u8,
        base36_encode: bool,
        stream_id: u16,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        total_data_length: u16,
        compression_type: u8,
        session_cookie: u8,
    ) -> String {
        let bytes = self.create_vpn_header(
            session_id, packet_type, base36_encode,
            stream_id, sequence_num, fragment_id,
            total_fragments, total_data_length,
            compression_type, session_cookie,
            true, true,
        );
        String::from_utf8_lossy(&bytes).to_string()
    }

    pub fn parse_vpn_header_bytes(
        &self,
        header_bytes: &[u8],
        offset: usize,
        return_length: bool,
    ) -> (Option<VpnHeaderData>, usize) {
        let ln = header_bytes.len();
        if ln < offset + 2 {
            return (None, 0);
        }

        let session_id = header_bytes[offset];
        let ptype = header_bytes[offset + 1];

        if !self.valid_packets.contains(&ptype) {
            return (None, 0);
        }

        let mut hdr = VpnHeaderData {
            session_id,
            packet_type: ptype,
            stream_id: None,
            sequence_num: None,
            fragment_id: None,
            total_fragments: None,
            total_data_length: None,
            compression_type: None,
            session_cookie: 0,
        };

        let mut off = offset + 2;

        if self.pt_stream.contains(&ptype) {
            if ln < off + 2 { return (None, 0); }
            hdr.stream_id = Some(((header_bytes[off] as u16) << 8) | (header_bytes[off + 1] as u16));
            off += 2;
        }

        if self.pt_seq.contains(&ptype) {
            if ln < off + 2 { return (None, 0); }
            hdr.sequence_num = Some(((header_bytes[off] as u16) << 8) | (header_bytes[off + 1] as u16));
            off += 2;
        }

        if self.pt_frag.contains(&ptype) {
            if ln < off + 4 { return (None, 0); }
            hdr.fragment_id = Some(header_bytes[off]);
            hdr.total_fragments = Some(header_bytes[off + 1]);
            hdr.total_data_length = Some(((header_bytes[off + 2] as u16) << 8) | (header_bytes[off + 3] as u16));
            off += 4;
        }

        if self.pt_comp.contains(&ptype) {
            if ln < off + 1 { return (None, 0); }
            hdr.compression_type = Some(header_bytes[off]);
            off += 1;
        }

        if ln < off + VPN_HEADER_INTEGRITY_LEN {
            return (None, 0);
        }

        let session_cookie = header_bytes[off];
        let check_byte = header_bytes[off + 1];
        let expected_check = Self::compute_header_check_byte(&header_bytes[offset..off + 1]);
        if check_byte != expected_check {
            return (None, 0);
        }

        hdr.session_cookie = session_cookie;
        off += VPN_HEADER_INTEGRITY_LEN;

        if return_length {
            (Some(hdr), off - offset)
        } else {
            (Some(hdr), 0)
        }
    }

    // -------------------------------------------------------------------------
    // DNS label helpers
    // -------------------------------------------------------------------------
    pub fn data_to_labels(encoded_str: &str) -> String {
        if encoded_str.is_empty() {
            return String::new();
        }
        let n = encoded_str.len();
        if n <= 63 {
            return encoded_str.to_string();
        }
        encoded_str
            .as_bytes()
            .chunks(63)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(".")
    }

    pub fn extract_txt_from_rdata_bytes(rdata: &[u8]) -> Vec<u8> {
        if rdata.is_empty() {
            return Vec::new();
        }
        let mut extracted = Vec::new();
        let mut offset = 0;
        let total_len = rdata.len();

        while offset < total_len {
            let length = rdata[offset] as usize;
            offset += 1;
            if length == 0 {
                continue;
            }
            let end = (offset + length).min(total_len);
            extracted.extend_from_slice(&rdata[offset..end]);
            offset = end;
        }
        extracted
    }

    pub fn extract_txt_from_rdata(rdata: &[u8]) -> String {
        String::from_utf8_lossy(&Self::extract_txt_from_rdata_bytes(rdata)).to_string()
    }

    // -------------------------------------------------------------------------
    // VPN Label Extraction
    // -------------------------------------------------------------------------
    pub fn extract_vpn_header_from_labels(&self, labels: &str) -> Option<VpnHeaderData> {
        if labels.is_empty() {
            return None;
        }

        let header_encoded = match labels.rfind('.') {
            Some(pos) => &labels[pos + 1..],
            None => labels,
        };

        let header_decrypted = self.decode_and_decrypt_data(header_encoded, true);
        if header_decrypted.is_empty() {
            return None;
        }

        let (hdr, _) = self.parse_vpn_header_bytes(&header_decrypted, 0, false);
        hdr
    }

    pub fn extract_vpn_data_from_labels(&self, labels: &str) -> Vec<u8> {
        if labels.is_empty() {
            return Vec::new();
        }

        let last_dot = match labels.rfind('.') {
            Some(pos) if pos > 0 => pos,
            _ => return Vec::new(),
        };

        let left = &labels[..last_dot];
        if left.is_empty() {
            return Vec::new();
        }

        let data_encoded: String = left.replace('.', "");
        self.decode_and_decrypt_data(&data_encoded, true)
    }

    // -------------------------------------------------------------------------
    // Upload MTU Calculation
    // -------------------------------------------------------------------------
    pub fn calculate_upload_mtu(&self, domain: &str, mtu: usize) -> (usize, usize) {
        const MAX_DNS_TOTAL: usize = 253;
        const MAX_LABEL_LEN: usize = 63;

        let hb_len = self.get_max_vpn_header_raw_size();

        let bits = (hb_len + 1) * 8;
        let header_overhead_chars = (bits + LOG2_36 - 1) / LOG2_36 + 1;
        let domain_overhead_chars = domain.len() + 1;
        let total_overhead = header_overhead_chars + domain_overhead_chars + 1;

        if total_overhead >= MAX_DNS_TOTAL {
            return (0, 0);
        }

        let available_chars_space = MAX_DNS_TOTAL - total_overhead;
        let max_payload_chars = (available_chars_space * MAX_LABEL_LEN) / (MAX_LABEL_LEN + 1);
        if max_payload_chars == 0 {
            return (0, 0);
        }

        let bits_capacity = max_payload_chars * LOG2_36;
        let safe_bytes_capacity = bits_capacity / 8;

        if mtu > 0 && mtu < safe_bytes_capacity {
            let final_mtu_bytes = mtu;
            let final_mtu_chars = (mtu * 8 + LOG2_36 - 1) / LOG2_36;
            (final_mtu_chars, final_mtu_bytes)
        } else {
            (max_payload_chars, safe_bytes_capacity)
        }
    }

    // -------------------------------------------------------------------------
    // DNS Query building for VPN requests
    // -------------------------------------------------------------------------
    pub fn generate_labels(
        &self,
        domain: &str,
        session_id: u8,
        packet_type: u8,
        data: &[u8],
        mtu_chars: usize,
        encode_data: bool,
        stream_id: u16,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        total_data_length: u16,
        compression_type: u8,
        session_cookie: u8,
    ) -> Vec<String> {
        let data_str = if encode_data && !data.is_empty() {
            Self::base_encode(data, true)
        } else if data.is_empty() {
            String::new()
        } else {
            String::from_utf8_lossy(data).to_string()
        };

        let data_len = data_str.len();
        let calculated_total_fragments: usize = if data_len == 0 {
            1
        } else {
            (data_len + mtu_chars - 1) / mtu_chars
        };

        if calculated_total_fragments > 255 {
            tracing::debug!("Data too large, exceeds maximum 255 fragments.");
            return Vec::new();
        }

        let raw_data_len = data.len();

        let mut data_labels = Vec::new();

        // Single fragment fast-path
        if data_len <= mtu_chars {
            let header = self.create_vpn_header_string(
                session_id, packet_type, true,
                stream_id, sequence_num,
                0, calculated_total_fragments as u8,
                raw_data_len as u16,
                compression_type, session_cookie,
            );

            if data_len > 0 {
                if data_len <= 63 {
                    data_labels.push(format!("{}.{}.{}", data_str, header, domain));
                } else {
                    data_labels.push(format!("{}.{}.{}", Self::data_to_labels(&data_str), header, domain));
                }
            } else {
                data_labels.push(format!("{}.{}", header, domain));
            }
            return data_labels;
        }

        // Multi-fragment path
        for frag_id in 0..calculated_total_fragments {
            let start = frag_id * mtu_chars;
            let end = (start + mtu_chars).min(data_len);

            let chunk_str = if start < data_len {
                &data_str[start..end]
            } else {
                ""
            };

            let header = self.create_vpn_header_string(
                session_id, packet_type, true,
                stream_id, sequence_num,
                frag_id as u8, calculated_total_fragments as u8,
                raw_data_len as u16,
                compression_type, session_cookie,
            );

            if !chunk_str.is_empty() {
                if chunk_str.len() <= 63 {
                    data_labels.push(format!("{}.{}.{}", chunk_str, header, domain));
                } else {
                    data_labels.push(format!("{}.{}.{}", Self::data_to_labels(chunk_str), header, domain));
                }
            } else {
                data_labels.push(format!("{}.{}", header, domain));
            }
        }

        data_labels
    }

    pub fn build_request_dns_query(
        &self,
        domain: &str,
        session_id: u8,
        packet_type: u8,
        data: &[u8],
        mtu_chars: usize,
        encode_data: bool,
        q_type: u16,
        stream_id: u16,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        total_data_length: u16,
        compression_type: u8,
        session_cookie: u8,
    ) -> Vec<Vec<u8>> {
        let labels = self.generate_labels(
            domain, session_id, packet_type, data, mtu_chars,
            encode_data, stream_id, sequence_num,
            fragment_id, total_fragments, total_data_length,
            compression_type, session_cookie,
        );

        if labels.is_empty() {
            return Vec::new();
        }

        labels.iter().map(|label| self.simple_question_packet(label, q_type)).collect()
    }

    // -------------------------------------------------------------------------
    // VPN Response packet generation
    // -------------------------------------------------------------------------
    pub fn generate_vpn_response_packet(
        &self,
        domain: &str,
        session_id: u8,
        packet_type: u8,
        data: &[u8],
        question_packet: &[u8],
        stream_id: u16,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        total_data_length: u16,
        encode_data: bool,
        compression_type: u8,
        session_cookie: u8,
    ) -> Vec<u8> {
        let header_b = self.create_vpn_header(
            session_id, packet_type, false,
            stream_id, sequence_num,
            fragment_id, total_fragments, total_data_length,
            compression_type, session_cookie,
            false, false, // no encrypt, no base_encode -> raw bytes
        );

        let txt_type = DnsRecordType::TXT;
        let in_class = DnsQClass::IN;
        let max_payload: usize = if encode_data { 189 } else { 255 };

        let mut answers = Vec::new();

        // Condition 1: No Data
        if data.is_empty() {
            let payload = if encode_data {
                Self::base_encode(&header_b, false).into_bytes()
            } else {
                header_b.clone()
            };

            let mut rdata = vec![payload.len() as u8];
            rdata.extend_from_slice(&payload);

            answers.push(DnsResourceRecord {
                name: domain.to_string(),
                rr_type: txt_type,
                rr_class: in_class,
                ttl: 0,
                rdata,
            });
            return Self::simple_answer_packet(&answers, question_packet);
        }

        // Condition 2: Fits in single packet
        let mut single_payload = header_b.clone();
        single_payload.extend_from_slice(data);

        if single_payload.len() <= max_payload {
            let payload = if encode_data {
                Self::base_encode(&single_payload, false).into_bytes()
            } else {
                single_payload
            };

            let mut rdata = vec![payload.len() as u8];
            rdata.extend_from_slice(&payload);

            answers.push(DnsResourceRecord {
                name: domain.to_string(),
                rr_type: txt_type,
                rr_class: in_class,
                ttl: 0,
                rdata,
            });
            return Self::simple_answer_packet(&answers, question_packet);
        }

        // Condition 3: Chunked Data
        let chunk0_prefix_len = 2; // [0x00, total_chunks]
        let max_chunk0_data = max_payload - chunk0_prefix_len - header_b.len();
        let chunk0_payload = &data[..max_chunk0_data.min(data.len())];
        let remaining_data_len = if data.len() > max_chunk0_data {
            data.len() - max_chunk0_data
        } else {
            0
        };
        let max_chunk_n_data = max_payload - 1;

        let total_chunks = if remaining_data_len > 0 {
            1 + (remaining_data_len + max_chunk_n_data - 1) / max_chunk_n_data
        } else {
            1
        };

        if total_chunks > 255 {
            tracing::debug!("Data too large, exceeds maximum 255 fragments.");
            return Self::simple_answer_packet(&answers, question_packet);
        }

        // Chunk 0
        let mut raw_chunk0 = vec![0x00, total_chunks as u8];
        raw_chunk0.extend_from_slice(&header_b);
        raw_chunk0.extend_from_slice(chunk0_payload);

        let full_chunk0 = if encode_data {
            Self::base_encode(&raw_chunk0, false).into_bytes()
        } else {
            raw_chunk0
        };

        let mut rdata = vec![full_chunk0.len() as u8];
        rdata.extend_from_slice(&full_chunk0);
        answers.push(DnsResourceRecord {
            name: domain.to_string(),
            rr_type: txt_type,
            rr_class: in_class,
            ttl: 0,
            rdata,
        });

        // Subsequent chunks
        let mut cur = max_chunk0_data;
        let mut chunk_id: u8 = 1;

        while cur < data.len() {
            let end = (cur + max_chunk_n_data).min(data.len());
            let mut raw_chunk = vec![chunk_id];
            raw_chunk.extend_from_slice(&data[cur..end]);

            let chunk = if encode_data {
                Self::base_encode(&raw_chunk, false).into_bytes()
            } else {
                raw_chunk
            };

            let mut rdata = vec![chunk.len() as u8];
            rdata.extend_from_slice(&chunk);
            answers.push(DnsResourceRecord {
                name: domain.to_string(),
                rr_type: txt_type,
                rr_class: in_class,
                ttl: 0,
                rdata,
            });

            cur = end;
            chunk_id += 1;
        }

        Self::simple_answer_packet(&answers, question_packet)
    }

    /// Convenience wrapper: build a VPN response with default zero values for
    /// stream_id, sequence_num, fragment fields, and compression OFF.
    pub fn generate_simple_vpn_response(
        &self,
        domain: &str,
        session_id: u8,
        packet_type: u8,
        data: &[u8],
        question_packet: &[u8],
        encode_data: bool,
        session_cookie: u8,
    ) -> Vec<u8> {
        self.generate_vpn_response_packet(
            domain, session_id, packet_type, data, question_packet,
            0, 0, 0, 0, 0, encode_data, 0, session_cookie,
        )
    }

    /// Full VPN response with all header fields specified explicitly.
    pub fn generate_full_vpn_response(
        &self,
        domain: &str,
        session_id: u8,
        packet_type: u8,
        data: &[u8],
        question_packet: &[u8],
        stream_id: u16,
        sequence_num: u16,
        encode_data: bool,
        compression_type: u8,
        session_cookie: u8,
    ) -> Vec<u8> {
        self.generate_vpn_response_packet(
            domain, session_id, packet_type, data, question_packet,
            stream_id, sequence_num, 0, 0, 0, encode_data, compression_type, session_cookie,
        )
    }

    // -------------------------------------------------------------------------
    // VPN Response Extraction
    // -------------------------------------------------------------------------
    pub fn extract_vpn_response(
        &self,
        parsed_packet: &DnsPacket,
        is_encoded: bool,
    ) -> (Option<VpnHeaderData>, Vec<u8>) {
        if parsed_packet.answers.is_empty() {
            return (None, Vec::new());
        }

        let mut chunks: std::collections::HashMap<u8, Vec<u8>> = std::collections::HashMap::new();
        let mut header_dict: Option<VpnHeaderData> = None;
        let mut total_expected: u8 = 1;
        let mut is_chunked = false;

        let txt_answers: Vec<&DnsResourceRecord> = parsed_packet
            .answers
            .iter()
            .filter(|a| a.rr_type == DnsRecordType::TXT)
            .collect();

        let is_multi = txt_answers.len() > 1;

        for answer in &txt_answers {
            let raw_txt = Self::extract_txt_from_rdata_bytes(&answer.rdata);
            if raw_txt.is_empty() {
                continue;
            }

            let raw_txt = if is_encoded {
                let decoded = match std::str::from_utf8(&raw_txt) {
                    Ok(s) => Self::base_decode(s, false),
                    Err(_) => continue,
                };
                if decoded.is_empty() {
                    continue;
                }
                decoded
            } else {
                raw_txt
            };

            if is_multi {
                if raw_txt[0] == 0x00 {
                    is_chunked = true;
                    if raw_txt.len() < 4 {
                        continue;
                    }
                    total_expected = raw_txt[1];

                    let (parsed_hdr, hlen) = self.parse_vpn_header_bytes(&raw_txt, 2, true);
                    if parsed_hdr.is_none() {
                        continue;
                    }
                    header_dict = parsed_hdr;
                    chunks.insert(0, raw_txt[2 + hlen..].to_vec());
                } else {
                    is_chunked = true;
                    let chunk_id = raw_txt[0];
                    chunks.insert(chunk_id, raw_txt[1..].to_vec());
                }
            } else {
                is_chunked = false;
                total_expected = 1;

                let (parsed_hdr, hlen) = self.parse_vpn_header_bytes(&raw_txt, 0, true);
                if parsed_hdr.is_none() {
                    continue;
                }
                header_dict = parsed_hdr;
                chunks.insert(0, raw_txt[hlen..].to_vec());
            }
        }

        if header_dict.is_none() {
            return (None, Vec::new());
        }

        if is_chunked {
            if chunks.len() != total_expected as usize {
                return (None, Vec::new());
            }
            for i in 0..total_expected {
                if !chunks.contains_key(&i) {
                    return (None, Vec::new());
                }
            }
        }

        let mut assembled = Vec::new();
        for i in 0..total_expected {
            if let Some(chunk) = chunks.get(&i) {
                assembled.extend_from_slice(chunk);
            }
        }

        (header_dict, assembled)
    }

    // -------------------------------------------------------------------------
    // Packed control blocks
    // -------------------------------------------------------------------------
    pub fn pack_control_block(packet_type: u8, stream_id: u16, sequence_num: u16) -> [u8; PACKED_CONTROL_BLOCK_SIZE] {
        [
            packet_type,
            (stream_id >> 8) as u8,
            (stream_id & 0xFF) as u8,
            (sequence_num >> 8) as u8,
            (sequence_num & 0xFF) as u8,
        ]
    }

    pub fn unpack_control_block(data: &[u8]) -> Option<(u8, u16, u16)> {
        if data.len() < PACKED_CONTROL_BLOCK_SIZE {
            return None;
        }
        let packet_type = data[0];
        let stream_id = ((data[1] as u16) << 8) | (data[2] as u16);
        let sequence_num = ((data[3] as u16) << 8) | (data[4] as u16);
        Some((packet_type, stream_id, sequence_num))
    }
}
