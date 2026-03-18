// MasterDnsVPN Server - Retransmit Loop
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::Arc;
use std::time::Instant;

use crate::dns_utils::dns_enums::PacketType;

use super::queue;
use super::state::ServerState;
use super::stream;

// ---------------------------------------------------------------------------
// Server retransmit loop (mirrors Python _server_retransmit_loop)
// ---------------------------------------------------------------------------

/// Background task that handles:
/// 1. Handshake/connect timeout for streams stuck in CONNECTING/SOCKS_*
/// 2. TIME_WAIT cleanup after 45s
/// 3. RST retransmits for non-reliable-control streams in TIME_WAIT
/// 4. FIN retransmits for streams in TIME_WAIT that haven't been ACKed
/// 5. Detection of dead ARQ streams marked as closed
pub async fn server_retransmit_loop(state: &Arc<ServerState>) {
    while !state.is_stopping() {
        let has_sessions = {
            let sessions = state.sessions.lock().await;
            !sessions.is_empty()
        };
        let sleep_ms = if has_sessions { 500 } else { 1500 };
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;

        if state.is_stopping() {
            break;
        }

        let now = Instant::now();

        // Get session IDs
        let session_ids: Vec<u8> = {
            let sessions = state.sessions.lock().await;
            sessions.keys().cloned().collect()
        };

        for session_id in session_ids {
            if state.is_stopping() {
                break;
            }

            // Get stream IDs for this session
            let stream_ids: Vec<u16> = {
                let sessions = state.sessions.lock().await;
                match sessions.get(&session_id) {
                    Some(s) => s.streams.keys().cloned().collect(),
                    None => continue,
                }
            };

            if stream_ids.is_empty() {
                continue;
            }

            for sid in &stream_ids {
                if state.is_stopping() {
                    break;
                }

                let stream_info = {
                    let sessions = state.sessions.lock().await;
                    let session = match sessions.get(&session_id) {
                        Some(s) => s,
                        None => continue,
                    };
                    let sd = match session.streams.get(sid) {
                        Some(s) => s,
                        None => continue,
                    };
                    let arq_closed = if let Some(arq) = &sd.arq {
                        arq.is_closed().await
                    } else {
                        false
                    };
                    StreamRetransmitInfo {
                        status: sd.status.clone(),
                        last_activity: sd.last_activity,
                        close_time: sd.close_time,
                        has_arq: sd.arq.is_some(),
                        arq_closed,
                        rst_sent: sd.rst_sent,
                        rst_acked: sd.rst_acked,
                        rst_retries: sd.rst_retries,
                        rst_seq_sent: sd.rst_seq_sent,
                        fin_retries: sd.fin_retries,
                    }
                };

                match stream_info.status.as_str() {
                    // -------------------------------------------------------
                    // CONNECTING / SOCKS_HANDSHAKE / SOCKS_CONNECTING: timeout
                    // -------------------------------------------------------
                    "CONNECTING" | "SOCKS_HANDSHAKE" | "SOCKS_CONNECTING" => {
                        if now.duration_since(stream_info.last_activity).as_secs_f64()
                            > state.socks_handshake_timeout
                        {
                            stream::close_stream(
                                state,
                                session_id,
                                *sid,
                                "Handshake/connect timeout",
                                true,
                                false,
                            )
                            .await;
                        }
                    }

                    // -------------------------------------------------------
                    // TIME_WAIT: GC after 45s, retransmit FIN/RST if needed
                    // -------------------------------------------------------
                    "TIME_WAIT" => {
                        if let Some(ct) = stream_info.close_time {
                            if now.duration_since(ct).as_secs_f64() > 45.0 {
                                let mut sessions = state.sessions.lock().await;
                                if let Some(session) = sessions.get_mut(&session_id) {
                                    session.streams.remove(sid);
                                }
                                continue;
                            }
                        }

                        // ARQ with control reliability handles its own retransmits
                        if stream_info.has_arq {
                            continue;
                        }

                        let elapsed = now
                            .duration_since(stream_info.last_activity)
                            .as_secs_f64();

                        // RST retransmit
                        if stream_info.rst_sent
                            && !stream_info.rst_acked
                            && elapsed > 1.5
                            && stream_info.rst_retries < 10
                        {
                            // Update activity + retry count
                            {
                                let mut sessions = state.sessions.lock().await;
                                if let Some(session) = sessions.get_mut(&session_id) {
                                    if let Some(sd) = session.streams.get_mut(sid) {
                                        sd.last_activity = now;
                                        sd.rst_retries += 1;
                                    }
                                }
                            }
                            queue::enqueue_packet(
                                state,
                                session_id,
                                0,
                                *sid,
                                stream_info.rst_seq_sent,
                                PacketType::STREAM_RST,
                                vec![],
                            )
                            .await;
                        }
                        // FIN retransmit
                        else if !stream_info.rst_sent
                            && elapsed > 3.0
                            && stream_info.fin_retries < 15
                        {
                            {
                                let mut sessions = state.sessions.lock().await;
                                if let Some(session) = sessions.get_mut(&session_id) {
                                    if let Some(sd) = session.streams.get_mut(sid) {
                                        sd.last_activity = now;
                                        sd.fin_retries += 1;
                                    }
                                }
                            }
                            queue::enqueue_packet(
                                state,
                                session_id,
                                1,
                                *sid,
                                0,
                                PacketType::STREAM_FIN,
                                vec![],
                            )
                            .await;
                        }
                    }

                    // -------------------------------------------------------
                    // CONNECTED / DRAINING: detect dead ARQ streams
                    // -------------------------------------------------------
                    "CONNECTED" | "DRAINING" => {
                        if stream_info.arq_closed {
                            // Determine if abortive
                            let abortive = stream_info.rst_sent;
                            stream::close_stream(
                                state,
                                session_id,
                                *sid,
                                "Marked Closed by ARQStream",
                                abortive,
                                false,
                            )
                            .await;
                        }
                    }

                    _ => {}
                }
            }
        }
    }
}

struct StreamRetransmitInfo {
    status: String,
    last_activity: Instant,
    close_time: Option<Instant>,
    has_arq: bool,
    arq_closed: bool,
    rst_sent: bool,
    rst_acked: bool,
    rst_retries: u32,
    rst_seq_sent: u16,
    fin_retries: u32,
}
