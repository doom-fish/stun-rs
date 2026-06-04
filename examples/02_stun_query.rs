//! Discover this host's server-reflexive address by sending a STUN Binding
//! request to a public STUN server over UDP.
//!
//! This example performs live network I/O, so it is gated behind the
//! `STUN_LIVE_TESTS` environment variable to keep offline builds and CI green:
//!
//! ```sh
//! STUN_LIVE_TESTS=1 cargo run --example 02_stun_query
//! # or target a specific server:
//! STUN_LIVE_TESTS=1 cargo run --example 02_stun_query -- stun:stun.l.google.com:19302
//! ```

use std::env;

use stun::{Endpoint, StunClient};

fn main() {
    if env::var("STUN_LIVE_TESTS").is_err() {
        eprintln!(
            "skipping live STUN query; set STUN_LIVE_TESTS=1 to run it \
             (this example sends a real UDP datagram to a public STUN server)"
        );
        return;
    }

    let uri = env::args()
        .nth(1)
        .unwrap_or_else(|| "stun:stun.l.google.com:19302".to_owned());

    let endpoint: Endpoint = uri.parse().expect("valid STUN URI or host:port");
    println!("Querying {}:{} ...", endpoint.host(), endpoint.port());

    let client = StunClient::new()
        .software(Some("doomfish-stun/0.1".to_owned()))
        .fingerprint(true);

    match client.bind(&endpoint) {
        Ok(addr) => println!("Server-reflexive address: {addr}"),
        Err(e) => {
            eprintln!("STUN query failed: {e}");
            std::process::exit(1);
        }
    }
}
