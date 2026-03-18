// MasterDnsVPN - Server Binary (thin entry point)
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

#[tokio::main]
async fn main() {
    masterdnsvpn::server::lifecycle::run().await;
}
