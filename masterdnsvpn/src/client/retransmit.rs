// MasterDnsVPN Client - Retransmit Worker & Dead Stream Cleanup
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use crate::dns_utils::dns_enums::PacketType;

use super::queue;
use super::state::ClientState;
use super::stream;

// ---------------------------------------------------------------------------
// Retransmit Worker (mirrors Python _retransmit_worker)
// ---------------------------------------------------------------------------

/// Background loop that:
/// 1. Retransmits SYN for PENDING streams that have stalled
/// 2. Cleans up TIME_WAIT streams after 45s
/// 3. Detects dead ARQ streams and closes them
/// 4. Retransmits FIN/RST for streams stuck in TIME_WAIT
/// 5. Cleans up expired entries from the closed_streams map
pub async fn retransmit_worker(state: &Arc<ClientState>) {
    while !state.is_stopping() {
        let has_streams = {
            let streams = state.active_streams.lock().await;
            !streams.is_empty()
        };
        let sleep_ms = if has_streams { 500 } else { 1500 };
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;

        if state.is_stopping() {
            break;
        }

        let now = Instant::now();

        // Collect stream IDs to process
        let stream_ids: Vec<u16> = {
            let streams = state.active_streams.lock().await;
            streams.keys().cloned().collect()
        };

        for sid in stream_ids {
            if state.is_stopping() {
                break;
            }

            let (status, last_act, close_time, has_arq, is_arq_closed) = {
                let streams = state.active_streams.lock().await;
                let sd = match streams.get(&sid) {
                    Some(s) => s,
                    None => continue,
                };
                let arq_closed = if let Some(arq) = &sd.arq {
                    arq.is_closed().await
                } else {
                    false
                };
                (
                    sd.status.clone(),
                    sd.last_activity_time,
                    sd.close_time,
                    sd.arq.is_some(),
                    arq_closed,
                )
            };

            match status.as_str() {
                // -----------------------------------------------------------
                // PENDING: retransmit SYN if stalled > 1.5s
                // -----------------------------------------------------------
                "PENDING" => {
                    if now.duration_since(last_act).as_secs_f64() > 1.5 {
                        // Update activity time to avoid rapid-fire retransmits
                        {
                            let mut streams = state.active_streams.lock().await;
                            if let Some(sd) = streams.get_mut(&sid) {
                                sd.last_activity_time = now;
                            }
                        }

                        // Determine if this is a SOCKS5 stream (has initial payload)
                        let has_payload = {
                            let streams = state.active_streams.lock().await;
                            streams
                                .get(&sid)
                                .map(|sd| !sd.initial_payload.is_empty())
                                .unwrap_or(false)
                        };

                        if has_payload {
                            // SOCKS5 mode: retransmit the SOCKS5_SYN
                            let payload = {
                                let streams = state.active_streams.lock().await;
                                streams
                                    .get(&sid)
                                    .map(|sd| sd.initial_payload.clone())
                                    .unwrap_or_default()
                            };
                            queue::enqueue_packet(
                                state,
                                0,
                                sid,
                                0,
                                PacketType::SOCKS5_SYN,
                                payload,
                            )
                            .await;
                        } else {
                            queue::enqueue_packet(
                                state,
                                0,
                                sid,
                                0,
                                PacketType::STREAM_SYN,
                                vec![],
                            )
                            .await;
                        }
                    }
                }

                // -----------------------------------------------------------
                // SOCKS_HANDSHAKE / SOCKS_CONNECTING: timeout check
                // -----------------------------------------------------------
                "SOCKS_HANDSHAKE" | "SOCKS_CONNECTING" => {
                    if now.duration_since(last_act).as_secs_f64()
                        > state.socks_handshake_timeout
                    {
                        stream::close_stream(
                            state,
                            sid,
                            "Handshake/connect timeout",
                            true,
                            false,
                        )
                        .await;
                    }
                }

                // -----------------------------------------------------------
                // TIME_WAIT: GC after 45s, retransmit FIN/RST if needed
                // -----------------------------------------------------------
                "TIME_WAIT" => {
                    if let Some(ct) = close_time {
                        if now.duration_since(ct).as_secs_f64() > 45.0 {
                            let mut streams = state.active_streams.lock().await;
                            streams.remove(&sid);
                            continue;
                        }
                    }

                    // Retransmit FIN/RST for non-reliable-control streams
                    if has_arq {
                        // ARQ with control reliability handles its own retransmits
                        continue;
                    }

                    let mut streams = state.active_streams.lock().await;
                    if let Some(sd) = streams.get_mut(&sid) {
                        let elapsed = now.duration_since(last_act).as_secs_f64();

                        // RST retransmit
                        if sd.rst_retries > 0 && sd.rst_retries < 10 && elapsed > 1.5 {
                            sd.last_activity_time = now;
                            sd.rst_retries += 1;
                            drop(streams);
                            queue::enqueue_packet(
                                state,
                                0,
                                sid,
                                0,
                                PacketType::STREAM_RST,
                                vec![],
                            )
                            .await;
                        }
                        // FIN retransmit
                        else if sd.fin_retries < 15 && elapsed > 3.0 {
                            sd.last_activity_time = now;
                            sd.fin_retries += 1;
                            drop(streams);
                            queue::enqueue_packet(
                                state,
                                1,
                                sid,
                                0,
                                PacketType::STREAM_FIN,
                                vec![],
                            )
                            .await;
                        }
                    }
                }

                // -----------------------------------------------------------
                // ACTIVE / DRAINING: detect dead ARQ streams
                // -----------------------------------------------------------
                "ACTIVE" | "DRAINING" => {
                    if is_arq_closed {
                        stream::close_stream(state, sid, "ARQ closed", false, false).await;
                    }
                }

                _ => {}
            }
        }

        // -----------------------------------------------------------
        // Clean expired closed_streams entries
        // -----------------------------------------------------------
        let mut closed = state.closed_streams.lock().await;
        let expired: Vec<u16> = closed
            .iter()
            .filter(|(_, &t)| now.duration_since(t).as_secs_f64() > 45.0)
            .map(|(&k, _)| k)
            .collect();
        for k in expired {
            closed.remove(&k);
        }
    }
}
