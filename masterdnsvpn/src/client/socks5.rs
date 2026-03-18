// MasterDnsVPN Client - SOCKS5 Handshake & Error Handling
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns_utils::dns_enums::PacketType;

use super::state::ClientState;

// ---------------------------------------------------------------------------
// SOCKS5 handshake result
// ---------------------------------------------------------------------------

pub struct Socks5HandshakeResult {
    /// The raw target payload: [ATYP] [ADDR_BYTES] [PORT_BYTES]
    pub target_payload: Vec<u8>,
    /// Address type byte (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
    pub atyp: u8,
    /// Raw address bytes (for building the success reply)
    pub target_addr_bytes: Vec<u8>,
    /// Raw port bytes (2 bytes big-endian)
    pub target_port_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// SOCKS5 local handshake (mirrors Python SOCKS5 handshake in _handle_local_tcp_connection)
// ---------------------------------------------------------------------------

/// Perform the local SOCKS5 handshake with the connecting application.
/// Returns the target payload to be sent to the server, or an error.
pub async fn handle_socks5_handshake(
    state: &Arc<ClientState>,
    stream: &mut TcpStream,
) -> Result<Socks5HandshakeResult, String> {
    // 1. Read greeting: VER(1) + NMETHODS(1)
    let mut greeting = [0u8; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_exact(&mut greeting),
    )
    .await
    .map_err(|_| "SOCKS5 greeting timeout".to_string())?
    .map_err(|e| format!("SOCKS5 greeting read error: {}", e))?;

    if greeting[0] != 0x05 {
        return Err("Not a SOCKS5 client".to_string());
    }

    let num_methods = greeting[1] as usize;
    let mut methods = vec![0u8; num_methods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| format!("SOCKS5 methods read error: {}", e))?;

    // 2. Auth negotiation
    if state.socks5_auth {
        if !methods.contains(&0x02) {
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err("Client does not support username/password auth".to_string());
        }
        stream
            .write_all(&[0x05, 0x02])
            .await
            .map_err(|e| e.to_string())?;

        // Read auth request: VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
        let mut auth_ver = [0u8; 1];
        stream
            .read_exact(&mut auth_ver)
            .await
            .map_err(|e| format!("Auth version read: {}", e))?;
        if auth_ver[0] != 0x01 {
            return Err("Invalid auth sub-negotiation version".to_string());
        }

        let mut ulen_buf = [0u8; 1];
        stream.read_exact(&mut ulen_buf).await.map_err(|e| e.to_string())?;
        let ulen = ulen_buf[0] as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await.map_err(|e| e.to_string())?;

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf).await.map_err(|e| e.to_string())?;
        let plen = plen_buf[0] as usize;
        let mut passwd = vec![0u8; plen];
        stream.read_exact(&mut passwd).await.map_err(|e| e.to_string())?;

        let user = String::from_utf8_lossy(&uname).to_string();
        let pass = String::from_utf8_lossy(&passwd).to_string();

        if user != state.socks5_user || pass != state.socks5_pass {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return Err(format!("Auth failed for user: {}", user));
        }

        stream
            .write_all(&[0x01, 0x00])
            .await
            .map_err(|e| e.to_string())?;
        tracing::debug!("SOCKS5 auth successful for user: {}", user);
    } else {
        if !methods.contains(&0x00) {
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err("Client does not support no-auth method".to_string());
        }
        stream
            .write_all(&[0x05, 0x00])
            .await
            .map_err(|e| e.to_string())?;
    }

    // 3. Connection request: VER(1) + CMD(1) + RSV(1) + ATYP(1)
    let mut req_header = [0u8; 4];
    stream
        .read_exact(&mut req_header)
        .await
        .map_err(|e| format!("SOCKS5 request header: {}", e))?;

    if req_header[0] != 0x05 {
        return Err("Invalid SOCKS5 request version".to_string());
    }

    let cmd = req_header[1];
    if cmd != 0x01 {
        // Only TCP CONNECT (0x01) is supported
        if cmd == 0x03 {
            tracing::debug!("SOCKS5 UDP Associate requested - not supported");
        }
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("Unsupported SOCKS5 command".to_string());
    }

    let atyp = req_header[3];
    let target_addr_bytes: Vec<u8>;

    match atyp {
        0x01 => {
            // IPv4: 4 bytes
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await.map_err(|e| e.to_string())?;
            target_addr_bytes = addr.to_vec();
        }
        0x03 => {
            // Domain: 1 byte length + N bytes domain
            let mut dlen_buf = [0u8; 1];
            stream
                .read_exact(&mut dlen_buf)
                .await
                .map_err(|e| e.to_string())?;
            let dlen = dlen_buf[0] as usize;
            let mut domain = vec![0u8; dlen];
            stream.read_exact(&mut domain).await.map_err(|e| e.to_string())?;
            // Include the length byte as part of target_addr_bytes
            let mut result = vec![dlen_buf[0]];
            result.extend_from_slice(&domain);
            target_addr_bytes = result;
        }
        0x04 => {
            // IPv6: 16 bytes
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.map_err(|e| e.to_string())?;
            target_addr_bytes = addr.to_vec();
        }
        _ => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err("Unsupported address type".to_string());
        }
    }

    // Read port: 2 bytes big-endian
    let mut target_port_bytes = [0u8; 2];
    stream
        .read_exact(&mut target_port_bytes)
        .await
        .map_err(|e| format!("SOCKS5 port: {}", e))?;

    // Build target payload: [ATYP] [ADDR_BYTES] [PORT_BYTES]
    let mut target_payload = vec![atyp];
    target_payload.extend_from_slice(&target_addr_bytes);
    target_payload.extend_from_slice(&target_port_bytes);

    Ok(Socks5HandshakeResult {
        target_payload,
        atyp,
        target_addr_bytes,
        target_port_bytes: target_port_bytes.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// SOCKS5 error reply building (mirrors Python _build_socks5_fail_reply)
// ---------------------------------------------------------------------------

/// Build a SOCKS5 failure reply from a server error packet type.
pub fn build_socks5_fail_reply(
    socks5_error_reply_map: &HashMap<u8, u8>,
    packet_type: u8,
) -> Vec<u8> {
    let rep = socks5_error_reply_map
        .get(&packet_type)
        .copied()
        .unwrap_or(0x01);
    vec![0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Build a SOCKS5 success reply echoing back the address info.
pub fn build_socks5_success_reply(
    atyp: u8,
    target_addr_bytes: &[u8],
    target_port_bytes: &[u8],
) -> Vec<u8> {
    let mut reply = vec![0x05, 0x00, 0x00]; // VER, REP=success, RSV
    reply.push(atyp);
    reply.extend_from_slice(target_addr_bytes);
    reply.extend_from_slice(target_port_bytes);
    reply
}

/// Check if a packet type is a SOCKS5 error packet.
pub fn is_socks5_error_packet(socks5_error_types: &std::collections::HashSet<u8>, ptype: u8) -> bool {
    socks5_error_types.contains(&ptype)
}
