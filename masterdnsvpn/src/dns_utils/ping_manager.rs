// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::{Duration, Instant};

/// PingManager tracks idle time and drives adaptive keep-alive pings.
pub struct PingManager {
    last_data_activity: AtomicU64,
    last_ping_time: AtomicU64,
    pub active_connections: AtomicUsize,
    send_func: Arc<dyn Fn() + Send + Sync>,
    epoch: Instant,
}

impl PingManager {
    pub fn new(send_func: Arc<dyn Fn() + Send + Sync>) -> Self {
        let epoch = Instant::now();
        let now_ms = 0u64;
        PingManager {
            last_data_activity: AtomicU64::new(now_ms),
            last_ping_time: AtomicU64::new(now_ms),
            active_connections: AtomicUsize::new(0),
            send_func,
            epoch,
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn update_activity(&self) {
        self.last_data_activity.store(self.now_ms(), Ordering::Relaxed);
    }

    pub async fn ping_loop(&self) {
        loop {
            let now = self.now_ms();
            let last_activity = self.last_data_activity.load(Ordering::Relaxed);
            let idle_time_ms = now.saturating_sub(last_activity);
            let idle_time = idle_time_ms as f64 / 1000.0;
            let conns = self.active_connections.load(Ordering::Relaxed);

            let (ping_interval, max_sleep) = if conns == 0 && idle_time > 20.0 {
                (10.0, 1.0)
            } else if idle_time >= 10.0 {
                (3.0, 0.5)
            } else if idle_time >= 5.0 {
                (1.0, 0.2)
            } else {
                (0.2, 0.18)
            };

            let last_ping = self.last_ping_time.load(Ordering::Relaxed);
            let time_since_last_ping = (now.saturating_sub(last_ping)) as f64 / 1000.0;

            let time_to_sleep = if time_since_last_ping >= ping_interval {
                (self.send_func)();
                self.last_ping_time.store(self.now_ms(), Ordering::Relaxed);
                ping_interval
            } else {
                ping_interval - time_since_last_ping
            };

            let actual_sleep = if time_to_sleep < max_sleep {
                time_to_sleep
            } else {
                max_sleep
            };

            if actual_sleep > 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(actual_sleep)).await;
            }
        }
    }
}
