// MasterDnsVPN - Build Version
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_build_version() -> &'static str {
    let v = BUILD_VERSION;
    if v.is_empty() { "dev" } else { v }
}
