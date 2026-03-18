// MasterDnsVPN payload compression helpers.
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionType;

impl CompressionType {
    pub const OFF: u8 = 0;
    pub const ZSTD: u8 = 1;
    pub const LZ4: u8 = 2;
    pub const ZLIB: u8 = 3;
}

pub const SUPPORTED_COMPRESSION_TYPES: &[u8] = &[
    CompressionType::OFF,
    CompressionType::ZSTD,
    CompressionType::LZ4,
    CompressionType::ZLIB,
];

pub fn normalize_compression_type(compression_type: u8) -> u8 {
    if SUPPORTED_COMPRESSION_TYPES.contains(&compression_type) {
        compression_type
    } else {
        CompressionType::OFF
    }
}

pub fn get_compression_name(compression_type: u8) -> &'static str {
    match compression_type {
        CompressionType::OFF => "OFF",
        CompressionType::ZSTD => "ZSTD",
        CompressionType::LZ4 => "LZ4",
        CompressionType::ZLIB => "ZLIB",
        _ => "UNKNOWN",
    }
}

pub fn is_compression_type_available(comp_type: u8) -> bool {
    match comp_type {
        CompressionType::ZLIB => true,
        CompressionType::ZSTD => true,
        CompressionType::LZ4 => true,
        _ => false,
    }
}

/// Compress payload only when useful.
/// Returns: (processed_data, actual_compression_type_used)
pub fn compress_payload(data: &[u8], comp_type: u8, min_size: usize) -> (Vec<u8>, u8) {
    if data.is_empty() {
        return (Vec::new(), CompressionType::OFF);
    }

    if comp_type == CompressionType::OFF {
        return (data.to_vec(), CompressionType::OFF);
    }

    if data.len() <= min_size {
        return (data.to_vec(), CompressionType::OFF);
    }

    if !is_compression_type_available(comp_type) {
        return (data.to_vec(), CompressionType::OFF);
    }

    let compressed = match comp_type {
        CompressionType::ZLIB => {
            let mut encoder = DeflateEncoder::new(data, Compression::fast());
            let mut buf = Vec::new();
            if encoder.read_to_end(&mut buf).is_ok() {
                Some(buf)
            } else {
                None
            }
        }
        CompressionType::ZSTD => {
            match zstd::encode_all(data, 1) {
                Ok(buf) => Some(buf),
                Err(_) => None,
            }
        }
        CompressionType::LZ4 => {
            let compressed = lz4_flex::compress_prepend_size(data);
            Some(compressed)
        }
        _ => None,
    };

    if let Some(comp_data) = compressed {
        if comp_data.len() < data.len() {
            return (comp_data, comp_type);
        }
    }

    (data.to_vec(), CompressionType::OFF)
}

/// Try to decompress payload.
/// Returns: (payload, success)
pub fn try_decompress_payload(data: &[u8], comp_type: u8) -> (Vec<u8>, bool) {
    if data.is_empty() || comp_type == CompressionType::OFF {
        return (data.to_vec(), true);
    }

    if !is_compression_type_available(comp_type) {
        return (Vec::new(), false);
    }

    match comp_type {
        CompressionType::ZLIB => {
            let mut decoder = DeflateDecoder::new(data);
            let mut buf = Vec::new();
            match decoder.read_to_end(&mut buf) {
                Ok(_) => (buf, true),
                Err(_) => (Vec::new(), false),
            }
        }
        CompressionType::ZSTD => {
            match zstd::decode_all(data) {
                Ok(buf) => (buf, true),
                Err(_) => (Vec::new(), false),
            }
        }
        CompressionType::LZ4 => {
            match lz4_flex::decompress_size_prepended(data) {
                Ok(buf) => (buf, true),
                Err(_) => (Vec::new(), false),
            }
        }
        _ => (Vec::new(), false),
    }
}

/// Backward-compatible decompression helper.
pub fn decompress_payload(data: &[u8], comp_type: u8) -> Vec<u8> {
    let (out, ok) = try_decompress_payload(data, comp_type);
    if ok { out } else { data.to_vec() }
}
