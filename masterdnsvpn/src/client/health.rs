// MasterDnsVPN Client - Server Health & Timeout Guard
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use super::state::ClientState;

// ---------------------------------------------------------------------------
// Timeout guard worker (mirrors Python _timeout_guard_worker)
// ---------------------------------------------------------------------------

/// Background loop that monitors session health and triggers reconnect
/// when no server response has been received for too long.
pub async fn timeout_guard_worker(
    state: &Arc<ClientState>,
    session_timeout_secs: f64,
) {
    let mut last_download = state.total_download.load(Ordering::Relaxed);
    let mut last_check = Instant::now();

    while !state.is_stopping() {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if state.is_stopping() {
            break;
        }

        if !state.session_established.load(Ordering::Relaxed) {
            last_download = state.total_download.load(Ordering::Relaxed);
            last_check = Instant::now();
            continue;
        }

        let current_download = state.total_download.load(Ordering::Relaxed);
        if current_download != last_download {
            // Traffic is flowing, reset
            last_download = current_download;
            last_check = Instant::now();
            continue;
        }

        let elapsed = Instant::now().duration_since(last_check).as_secs_f64();
        if elapsed > session_timeout_secs {
            tracing::warn!(
                "No server response for {:.0}s (limit={:.0}s). Triggering reconnect.",
                elapsed,
                session_timeout_secs
            );
            state.session_restart.store(true, Ordering::SeqCst);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Inactive server recheck (mirrors Python _inactive_server_recheck_worker)
// ---------------------------------------------------------------------------

/// Periodically re-enables disabled servers so they get a second chance.
pub async fn inactive_server_recheck_worker(
    state: &Arc<ClientState>,
    recheck_interval_secs: f64,
) {
    while !state.is_stopping() {
        tokio::time::sleep(std::time::Duration::from_secs_f64(recheck_interval_secs)).await;

        if state.is_stopping() {
            break;
        }

        let now = Instant::now();
        let mut disabled = state.disabled_servers.lock().await;
        let to_reactivate: Vec<String> = disabled
            .iter()
            .filter(|(_, disabled_at)| {
                now.duration_since(disabled_at).as_secs_f64() > recheck_interval_secs
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in &to_reactivate {
            disabled.remove(key);
        }
        drop(disabled);

        if !to_reactivate.is_empty() {
            tracing::debug!(
                "Reactivated {} previously disabled server(s)",
                to_reactivate.len()
            );
        }
    }
}
