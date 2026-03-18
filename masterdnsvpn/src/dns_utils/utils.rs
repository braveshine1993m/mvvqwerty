// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::fs;
use std::net::UdpSocket;
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::EnvFilter;

use super::config_loader::get_config_path;

/// Async UDP receive helper (Tokio native).
pub async fn async_recvfrom(
    sock: &TokioUdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    sock.recv_from(buf).await
}

/// Async UDP send helper (Tokio native).
pub async fn async_sendto(
    sock: &TokioUdpSocket,
    data: &[u8],
    addr: std::net::SocketAddr,
) -> std::io::Result<usize> {
    match sock.send_to(data, addr).await {
        Ok(n) => Ok(n),
        Err(e) => {
            // Ignore connection reset / broken pipe on UDP (mirrors Python behavior)
            let kind = e.kind();
            if matches!(
                kind,
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            ) {
                Ok(0)
            } else {
                // Check Windows-specific error codes
                #[cfg(windows)]
                {
                    if let Some(raw) = e.raw_os_error() {
                        if raw == 10054 || raw == 10038 || raw == 1236 {
                            return Ok(0);
                        }
                    }
                }
                Err(e)
            }
        }
    }
}

/// Load and return the contents of a text file, stripped of leading/trailing whitespace.
/// Returns None if the file does not exist or error occurs.
pub fn load_text(file_path: &str) -> Option<String> {
    match fs::read_to_string(file_path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => None,
    }
}

/// Save the given text to a file. Returns true on success, false otherwise.
pub fn save_text(file_path: &str, text: &str) -> bool {
    fs::write(file_path, text).is_ok()
}

/// Retrieve or generate an encryption key of appropriate length based on method_id.
/// method_id: 3 -> 16 chars, 4 -> 24 chars, else 32 chars.
/// Returns the key as a hex string.
pub fn get_encrypt_key(method_id: u8) -> String {
    let length: usize = match method_id {
        3 => 16,
        4 => 24,
        _ => 32,
    };

    let key_path = get_config_path("encrypt_key.txt");
    let key_path_str = key_path.to_string_lossy().to_string();

    if let Some(random_key) = load_text(&key_path_str) {
        if random_key.len() == length {
            return random_key;
        }
    }

    let random_key = generate_random_hex_text(length);
    save_text(&key_path_str, &random_key);
    random_key
}

/// Generate a random hexadecimal string of the specified length.
/// Always returns exactly `length` characters.
pub fn generate_random_hex_text(length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    use rand::Rng;
    let byte_len = (length + 1) / 2;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..byte_len).map(|_| rng.r#gen()).collect();
    let hex_str = hex::encode(&bytes);
    hex_str[..length].to_string()
}

/// Initialize the tracing-based logger (mirrors Python's loguru config).
pub fn init_logger(
    log_level: &str,
    log_file: Option<&str>,
    _max_log_size: usize,
    _backup_count: usize,
    is_server: bool,
) {
    let app_name = if is_server {
        "MasterDnsVPN Server"
    } else {
        "MasterDnsVPN Client"
    };

    let level = log_level.to_uppercase();
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(ChronoLocal::new("%H:%M:%S".to_string()))
        .with_ansi(true);

    if let Some(file_path) = log_file {
        // If a log file is specified, also write to file via a layer
        // For simplicity we use the file appender from tracing
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path);

        if let Ok(_file) = file {
            // Use stdout for now; file logging can be added with tracing-appender
            subscriber.init();
        } else {
            subscriber.init();
        }
    } else {
        subscriber.init();
    }

    tracing::info!("[{}] Logger initialized (level={})", app_name, level);
}

/// Set UDP socket buffer sizes.
pub fn set_socket_buffer_size(sock: &UdpSocket, size: usize) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let size_val = size as libc::c_int;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let sock_raw = sock.as_raw_socket();
        unsafe {
            let size_val = size as i32;
            let _ = windows_sys::Win32::Networking::WinSock::setsockopt(
                sock_raw as usize,
                windows_sys::Win32::Networking::WinSock::SOL_SOCKET as i32,
                windows_sys::Win32::Networking::WinSock::SO_RCVBUF as i32,
                &size_val as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
            let _ = windows_sys::Win32::Networking::WinSock::setsockopt(
                sock_raw as usize,
                windows_sys::Win32::Networking::WinSock::SOL_SOCKET as i32,
                windows_sys::Win32::Networking::WinSock::SO_SNDBUF as i32,
                &size_val as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}
