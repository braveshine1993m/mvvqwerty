// MasterDnsVPN Client - Config Recommendations & Diagnostics
// Mirrors Python _config_recommendations, _apply_scale_profile, _apply_session_compression_policy
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dns_utils::compression::{get_compression_name, CompressionType};

use super::state::ClientState;

// ---------------------------------------------------------------------------
// Scale Profile (mirrors Python _apply_scale_profile)
// ---------------------------------------------------------------------------
pub fn apply_scale_profile(state: &Arc<ClientState>, total_pairs: usize) {
    let n = total_pairs.max(1);

    let (profile, mtu_parallel, batch_size, recheck_interval, per_server_gap): (
        &str,
        usize,
        usize,
        f64,
        f64,
    ) = if n <= 50 {
        ("small", 10, 4, 600.0, 2.5)
    } else if n <= 1000 {
        ("medium", 12, 5, 900.0, 3.0)
    } else {
        ("large", 16, 8, 1200.0, 4.0)
    };

    state
        .recheck_batch_size
        .store(batch_size.max(1), Ordering::SeqCst);
    state
        .recheck_inactive_interval_seconds
        .store((recheck_interval.max(60.0)) as u64, Ordering::SeqCst);
    state
        .recheck_server_interval_seconds
        .store((per_server_gap.max(1.0)) as u64, Ordering::SeqCst);

    tracing::info!(
        "[Scale Profile: {}]: MTU_TEST_PARALLELISM: {} | RECHECK_BATCH_SIZE: {} | RECHECK_INACTIVE_INTERVAL_SECONDS: {} | RECHECK_SERVER_INTERVAL_SECONDS: {:.1}",
        profile,
        mtu_parallel.max(1),
        batch_size.max(1),
        recheck_interval.max(60.0) as u64,
        per_server_gap.max(1.0)
    );
}

// ---------------------------------------------------------------------------
// Session Compression Policy (mirrors Python _apply_session_compression_policy)
// ---------------------------------------------------------------------------
pub fn apply_session_compression_policy(state: &Arc<ClientState>) {
    let mut up = state.upload_compression;
    let mut down = state.download_compression;

    let synced_up = state.upload_mtu_bytes.load(Ordering::Relaxed);
    let synced_down = state.download_mtu_bytes.load(Ordering::Relaxed);

    if synced_up <= state.compression_min_size && up != CompressionType::OFF {
        up = CompressionType::OFF;
        tracing::info!(
            "[Compression] Upload compression disabled due to small MTU: {}",
            synced_up
        );
    }

    if synced_down <= state.compression_min_size && down != CompressionType::OFF {
        down = CompressionType::OFF;
        tracing::info!(
            "[Compression] Download compression disabled due to small MTU: {}",
            synced_down
        );
    }

    // Note: upload_compression and download_compression are not AtomicU8 in current state,
    // they are plain u8. For now we log the effective values. The actual compression
    // negotiation happens during session init with the server.

    tracing::info!(
        "[Compression] Effective Compression - Upload: {}, Download: {}",
        get_compression_name(up),
        get_compression_name(down)
    );
}

// ---------------------------------------------------------------------------
// Config Recommendations (mirrors Python _config_recommendations)
// ---------------------------------------------------------------------------
pub async fn config_recommendations(state: &Arc<ClientState>) {
    tracing::info!("{}", "=".repeat(80));
    tracing::info!("Join our Telegram channel: @MasterDNSVPN for support and updates!");
    tracing::info!("{}", "=".repeat(80));
    tracing::info!("Smart Config Recommendations & Diagnostics:");
    tracing::info!("Review these suggestions to maximize your speed, stability, and MTU!");

    let mut wait_time: u32 = 0;
    let mut has_warnings = false;
    let mut has_info = false;

    // --- Domain check ---
    let unique_domains: HashSet<&str> = state.domains.iter().map(|s| s.as_str()).collect();
    if unique_domains.len() > 1 {
        let min_len = unique_domains.iter().map(|d| d.len()).min().unwrap_or(0);
        let best: Vec<&&str> = unique_domains.iter().filter(|d| d.len() <= min_len).collect();
        let best_str: Vec<&str> = best.into_iter().copied().collect();
        tracing::warn!(
            "[Domains]: You have multiple domains. Shorter domains give larger MTU. Best to keep: {}",
            best_str.join(", ")
        );
        has_warnings = true;
    }

    // --- Resolver count ---
    let all_resolvers = {
        let bal = state.balancer.lock().await;
        bal.resolvers.len()
    };

    // We approximate unique resolver count from connection map
    if all_resolvers < 5 {
        tracing::warn!("[Resolvers]: Using less than 5 resolvers. Add more for better reliability.");
        has_warnings = true;
    }

    // Apply scale profile
    apply_scale_profile(state, all_resolvers);

    // --- Packet duplication ---
    if state.packet_duplication_count > 2 {
        tracing::warn!(
            "[Bandwidth]: PACKET_DUPLICATION_COUNT is {}. Reduce to 1-2 to save bandwidth.",
            state.packet_duplication_count
        );
        tracing::info!(
            "      [Bandwidth Tip]: Higher PACKET_DUPLICATION_COUNT can improve stability on bad networks but consumes more bandwidth. Recommended: 1 for stable, 2 for unstable."
        );
        has_warnings = true;
    }

    // --- Balancing strategy ---
    if state.resolver_balancing_strategy != 2 {
        tracing::info!(
            "[Balancing]: Consider using RESOLVER_BALANCING_STRATEGY = 2 (Round Robin) for even load distribution."
        );
        has_info = true;
    }

    // --- SOCKS5 security ---
    if state.protocol_type == "SOCKS5" && state.listen_ip == "0.0.0.0" {
        tracing::info!(
            "[Security]: SOCKS5 is bound to 0.0.0.0. If local-only, bind to 127.0.0.1"
        );
        has_info = true;

        if !state.socks5_auth && state.listen_ip == "0.0.0.0" {
            tracing::warn!(
                "[Security]: SOCKS5_AUTH is disabled on a public IP! Highly recommended to enable it."
            );
            has_warnings = true;
        }

        if state.socks5_auth
            && (state.socks5_user.is_empty() || state.socks5_pass.is_empty())
            && state.listen_ip == "0.0.0.0"
        {
            tracing::warn!(
                "[Security]: SOCKS5_AUTH is enabled but username or password is not set. Please set SOCKS5_USER and SOCKS5_PASS."
            );
            has_warnings = true;
        } else if state.socks5_auth
            && state.listen_ip == "0.0.0.0"
            && (state.socks5_user == "master_dns_vpn" || state.socks5_pass == "master_dns_vpn")
        {
            tracing::warn!(
                "[Security]: SOCKS5_AUTH is using the default username and/or password. Please change SOCKS5_USER and SOCKS5_PASS."
            );
            has_warnings = true;
        }

        let common_ports = [1080u16, 1081, 8080, 8000];
        if common_ports.contains(&state.listen_port) && state.listen_ip == "0.0.0.0" {
            let suggested: u16 = (rand::random::<u16>() % 55000) + 10000;
            tracing::warn!(
                "[Security]: Your SOCKS5 listener is using a common port ({}). Consider changing LISTEN_PORT to {} for better security.",
                state.listen_port,
                suggested
            );
            has_warnings = true;
        }
    }

    // --- ARQ tuning ---
    if state.arq_config.rto > 0.5 {
        tracing::info!(
            "[Latency]: ARQ_INITIAL_RTO is {}s. Reduce to 0.2s-0.5s for faster packet recovery.",
            state.arq_config.rto
        );
        has_info = true;
    }

    if state.arq_config.max_rto > 1.5 {
        tracing::info!(
            "[Latency]: ARQ_MAX_RTO is {}s. Keep below 1.5s for snappy connections.",
            state.arq_config.max_rto
        );
        has_info = true;
    }

    if state.arq_config.window_size < 500 {
        tracing::warn!(
            "[Throughput]: ARQ_WINDOW_SIZE is {}. Increase to 500+ for high speeds.",
            state.arq_config.window_size
        );
        has_warnings = true;
    }

    // --- Batch size ---
    if state.max_packed_blocks < 10 {
        tracing::warn!(
            "[Performance]: MAX_PACKETS_PER_BATCH is low ({}). Consider increasing to 10+ for better performance.",
            state.max_packed_blocks
        );
        has_warnings = true;
    }

    // --- MTU testing params ---
    if state.mtu_test_retries > 2 {
        tracing::info!(
            "[MTU Testing]: MTU_TEST_RETRIES is set to {}. Consider reducing to 1-2 for faster MTU testing.",
            state.mtu_test_retries
        );
        has_info = true;
    }

    if state.mtu_test_timeout > 2.0 {
        tracing::info!(
            "[MTU Testing]: MTU_TEST_TIMEOUT is set to {} seconds. Consider reducing to 0.5-2 seconds for faster MTU testing.",
            state.mtu_test_timeout
        );
        has_info = true;
    }

    // --- MTU Limits & Calculations ---
    {
        let max_len_domain = state
            .domains
            .iter()
            .max_by_key(|d| d.len())
            .cloned()
            .unwrap_or_default();

        let (_, optimal_up_mtu) = state.parser.calculate_upload_mtu(&max_len_domain, 0);

        tracing::info!("--- MTU Limits & Calculations ---");
        tracing::info!(
            "   [Upload Limit]: Based on your longest domain name, max theoretical Upload MTU is {} bytes.",
            optimal_up_mtu
        );
        let min_optimal_mtu = optimal_up_mtu.saturating_sub(5);
        tracing::info!(
            "      Best value for MIN_UPLOAD_MTU is {}-{} bytes.",
            min_optimal_mtu,
            optimal_up_mtu
        );
        tracing::info!(
            "      Best value for MAX_UPLOAD_MTU is {} bytes.",
            optimal_up_mtu
        );

        if state.min_upload_mtu < min_optimal_mtu {
            tracing::warn!(
                "   [MTU Warning]: Your MIN_UPLOAD_MTU ({}) is set very low. Consider increasing it to at least {} bytes for better performance!",
                state.min_upload_mtu,
                min_optimal_mtu
            );
            tracing::info!(
                "      Setting MIN_UPLOAD_MTU lower than this range will support more resolvers but will decrease your speed."
            );
        }
        if state.max_upload_mtu > optimal_up_mtu {
            tracing::warn!(
                "      [MTU Error]: Your MAX_UPLOAD_MTU ({}) exceeds the theoretical limit based on your domain names ({}). Please reduce it!",
                state.max_upload_mtu,
                optimal_up_mtu
            );
        }
        if state.min_upload_mtu > state.max_upload_mtu {
            tracing::warn!(
                "      [MTU Error]: Your MIN_UPLOAD_MTU ({}) is greater than your MAX_UPLOAD_MTU ({}). Please fix this!",
                state.min_upload_mtu,
                state.max_upload_mtu
            );
        }
        if state.min_upload_mtu > optimal_up_mtu {
            tracing::warn!(
                "      [MTU Warning]: Your MIN_UPLOAD_MTU ({}) is set higher than the optimal range ({}). This may cause MTU testing to fail.",
                state.min_upload_mtu,
                optimal_up_mtu
            );
        }

        if optimal_up_mtu < 80 {
            tracing::warn!(
                "      [Warning]: Your domain names are quite long, which significantly reduces your maximum Upload MTU to {} bytes. Consider using shorter domain names.",
                optimal_up_mtu
            );
        }

        // Download MTU calculations
        let dns_overhead: usize = 283;
        let max_vpn_header = state.parser.get_max_vpn_header_raw_size();

        let calc_down_capacity = |dns_limit: usize| -> usize {
            let available = if dns_limit > dns_overhead {
                dns_limit - dns_overhead
            } else {
                return 0;
            };
            let raw_cap = if state.base_encode_responses {
                (available as f64 * 0.75) as usize
            } else {
                available
            };
            raw_cap
                .saturating_sub(state.crypto_overhead)
                .saturating_sub(max_vpn_header)
        };

        let down_512 = calc_down_capacity(512);
        let min_down_512 = down_512.saturating_sub(10);
        let down_1232 = calc_down_capacity(1232);
        let _min_down_1232 = down_1232.saturating_sub(50);
        let down_4096 = calc_down_capacity(4096);
        let _min_down_4096 = down_4096.saturating_sub(100);

        let mode_str = if state.base_encode_responses {
            "Base64 (Encoded)"
        } else {
            "Raw Bytes"
        };
        tracing::info!(
            "   [Download Limits]: For a single Answer in {} mode:",
            mode_str
        );
        tracing::info!(
            "      No EDNS0 (512 limit): MAX_DOWNLOAD_MTU ~{} and MIN_DOWNLOAD_MTU ~{}",
            down_512,
            min_down_512
        );
        tracing::info!(
            "      Safe EDNS0 (1232 limit): MAX_DOWNLOAD_MTU ~{} and MIN_DOWNLOAD_MTU ~{}",
            down_1232,
            _min_down_1232
        );
        tracing::info!(
            "      Max EDNS0 (4096 limit): MAX_DOWNLOAD_MTU ~{} and MIN_DOWNLOAD_MTU ~{}",
            down_4096,
            _min_down_4096
        );
        tracing::info!(
            "      Note: You can try MIN_DOWNLOAD_MTU = {} and MAX_DOWNLOAD_MTU = {}, but if your network blocks EDNS0, set MAX_DOWNLOAD_MTU to {}.",
            min_down_512,
            down_4096,
            down_512
        );

        if state.min_download_mtu < 100 {
            tracing::warn!(
                "      [MTU Warning]: Your MIN_DOWNLOAD_MTU ({}) is set very low. Consider increasing it to at least {} bytes!",
                state.min_download_mtu,
                min_down_512
            );
        }

        if state.max_download_mtu > down_4096 {
            tracing::warn!(
                "      [MTU Error]: Your MAX_DOWNLOAD_MTU ({}) exceeds the absolute DNS limits ({}). Please reduce it!",
                state.max_download_mtu,
                down_4096
            );
            wait_time += 5;
            has_warnings = true;
        } else if state.max_download_mtu > down_512 {
            tracing::info!(
                "      [MTU Tip]: If your network drops packets and MTU tests fail, it means EDNS0 is blocked. Lower MAX_DOWNLOAD_MTU to {}.",
                down_512
            );
        }
    }

    // --- Encoding mode ---
    tracing::info!("{}", "=".repeat(80));
    if state.base_encode_responses {
        tracing::info!(
            "[Encoding Mode]: BASE_ENCODE_DATA is enabled. Pros: Most resolvers support it. Cons: ~33% overhead reduces max Download MTU."
        );
    } else {
        tracing::info!(
            "[Encoding Mode]: BASE_ENCODE_DATA is disabled. Pros: Larger Download MTU, higher performance. Cons: Some resolvers may reject raw binary data."
        );
    }

    // --- Config version ---
    if state.config_version < state.min_config_version {
        tracing::warn!(
            "[Config Version]: Your config version ({}) is outdated. Please update to the latest version ({}) for best performance.",
            state.config_version,
            state.min_config_version
        );
    }

    if has_warnings {
        wait_time += 5;
    }
    if has_info {
        wait_time += 3;
    }

    if wait_time > 0 {
        tracing::info!("{}", "=".repeat(80));
        tracing::info!("Join our Telegram channel: @MasterDNSVPN for support and updates!");
        tracing::info!("{}", "=".repeat(80));
        tracing::info!(
            "Waiting {} seconds so you can read the warnings above...",
            wait_time
        );
        tracing::info!("Press ENTER key to skip the wait and start immediately...");
        tracing::info!("Or press CTRL+C to stop and fix your configuration!");

        // Race: stdin readline vs timeout (mirrors Python's asyncio.wait_for + run_in_executor)
        let timeout_fut = tokio::time::sleep(std::time::Duration::from_secs(wait_time as u64));
        let stdin_fut = tokio::task::spawn_blocking(|| {
            let mut buf = String::new();
            let _ = std::io::stdin().read_line(&mut buf);
        });

        tokio::select! {
            _ = timeout_fut => {}
            _ = stdin_fut => {}
        }
    } else {
        tracing::info!("Your configuration looks great! No critical warnings found.");
    }
}
