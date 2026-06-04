//! Synchronous STUN client over Network.framework UDP.
//!
//! [`StunClient::bind`] performs a STUN Binding transaction against a server
//! and returns the server-reflexive ([`MappedAddress`]) transport address. It
//! is fully synchronous: no async runtime is pulled in. Internally it uses a
//! background receiver thread and a [`std::sync::mpsc`] channel so the caller
//! can drive the RFC 5389 retransmission timers (see
//! [`crate::transaction::RetransmitSchedule`]) without blocking forever on the
//! callback-based Network.framework receive primitive.
//!
//! WebRTC peers and other ICE-compliant endpoints use exactly this exchange to
//! discover their public address before connectivity checks.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use networkframework::udp::UdpClient;

use crate::attribute::{types, Attribute};
use crate::error::{Error, Result};
use crate::message::{Class, Message, Method};
use crate::transaction::{timeout_error, RetransmitSchedule, TransactionId};

/// Default STUN port (RFC 5389 §9).
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// Maximum UDP datagram size we are willing to receive.
const MAX_DATAGRAM: usize = 1500;

/// A server-reflexive transport address learned from a STUN Binding response.
pub type MappedAddress = SocketAddr;

/// A parsed `stun:host:port` URI.
///
/// The `stuns:` (TLS) scheme is accepted as an alias but this client only
/// implements plaintext UDP transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunUri {
    /// The server host (DNS name or IP literal).
    pub host: String,
    /// The server port.
    pub port: u16,
}

impl FromStr for StunUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("stun:")
            .or_else(|| s.strip_prefix("stuns:"))
            .ok_or_else(|| Error::InvalidUri(s.to_owned()))?;
        let (host, port) = split_host_port(rest)?;
        Ok(Self { host, port })
    }
}

/// Split a `host:port` (or bare `host`) authority into its parts. Bracketed
/// IPv6 literals (`[::1]:3478`) are supported.
fn split_host_port(input: &str) -> Result<(String, u16)> {
    if input.is_empty() {
        return Err(Error::InvalidUri(input.to_owned()));
    }
    if let Some(after_bracket) = input.strip_prefix('[') {
        let (host, tail) = after_bracket
            .split_once(']')
            .ok_or_else(|| Error::InvalidUri(input.to_owned()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| Error::InvalidUri(input.to_owned()))?,
            None => DEFAULT_STUN_PORT,
        };
        return Ok((host.to_owned(), port));
    }
    match input.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| Error::InvalidUri(input.to_owned()))?;
            Ok((host.to_owned(), port))
        }
        None => Ok((input.to_owned(), DEFAULT_STUN_PORT)),
    }
}

/// A STUN server endpoint (host + port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    /// Construct an endpoint from a host and port.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The server host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The server port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl From<StunUri> for Endpoint {
    fn from(uri: StunUri) -> Self {
        Self {
            host: uri.host,
            port: uri.port,
        }
    }
}

impl FromStr for Endpoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self::from(s.parse::<StunUri>()?))
    }
}

/// A synchronous STUN client.
#[derive(Debug, Default, Clone)]
pub struct StunClient {
    software: Option<String>,
    fingerprint: bool,
}

impl StunClient {
    /// Create a client with default behavior (sends `SOFTWARE` +
    /// `FINGERPRINT`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            software: Some(concat!("doomfish-stun/", env!("CARGO_PKG_VERSION")).to_owned()),
            fingerprint: true,
        }
    }

    /// Override the `SOFTWARE` attribute value, or pass `None` to omit it.
    #[must_use]
    pub fn software(mut self, software: Option<String>) -> Self {
        self.software = software;
        self
    }

    /// Enable or disable the `FINGERPRINT` attribute (enabled by default).
    #[must_use]
    pub const fn fingerprint(mut self, enabled: bool) -> Self {
        self.fingerprint = enabled;
        self
    }

    /// Perform a STUN Binding transaction against `server` and return the
    /// reflexive transport address.
    ///
    /// Retransmits per RFC 5389 §7.2.1 (initial RTO 500 ms, doubling) until a
    /// matching response arrives or the schedule is exhausted.
    ///
    /// # Errors
    ///
    /// * [`Error::Network`] if the socket cannot be opened or a send fails.
    /// * [`Error::Timeout`] if no matching response arrives in time.
    /// * Decoding errors if the response is malformed.
    pub fn bind(&self, server: &Endpoint) -> Result<MappedAddress> {
        let transaction_id = TransactionId::random();
        let request = self.build_request(transaction_id);

        let socket = UdpClient::connect(server.host(), server.port())
            .map_err(|e| Error::Network(e.to_string()))?;
        let socket = Arc::new(socket);

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        spawn_receiver(Arc::clone(&socket), tx);

        // Send once up front, then resend on each elapsed retransmit interval.
        socket
            .send(&request)
            .map_err(|e| Error::Network(e.to_string()))?;

        for wait in RetransmitSchedule::new() {
            match rx.recv_timeout(wait) {
                Ok(datagram) => {
                    if let Some(addr) = match_response(&datagram, &transaction_id) {
                        return Ok(addr);
                    }
                    // Not our datagram; keep waiting within the same window.
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    socket
                        .send(&request)
                        .map_err(|e| Error::Network(e.to_string()))?;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Err(timeout_error())
    }

    /// Build the Binding request bytes for a given transaction ID.
    fn build_request(&self, transaction_id: TransactionId) -> Vec<u8> {
        let mut builder = Message::builder(Method::Binding, Class::Request).transaction_id(transaction_id);
        if let Some(software) = &self.software {
            builder = builder.attribute(Attribute::Software(software.clone()));
        }
        if self.fingerprint {
            builder = builder.with_fingerprint();
        }
        builder.build_and_encode()
    }
}

/// Spawn a detached receiver thread that forwards inbound datagrams.
///
/// The thread terminates when the socket is closed (the last [`Arc`] is
/// dropped) or a receive fails. On a successful or timed-out [`StunClient::bind`]
/// the caller drops its `Arc`; the next inbound datagram or socket teardown
/// unblocks the thread.
fn spawn_receiver(socket: Arc<UdpClient>, tx: mpsc::Sender<Vec<u8>>) {
    thread::spawn(move || {
        while let Ok(datagram) = socket.receive(MAX_DATAGRAM) {
            if tx.send(datagram).is_err() {
                break;
            }
        }
    });
}

/// Decode a datagram and, if it is the matching Binding response, extract the
/// reflexive address.
fn match_response(datagram: &[u8], expected: &TransactionId) -> Option<MappedAddress> {
    let message = Message::decode(datagram).ok()?;
    if message.transaction_id() != expected || message.method() != Method::Binding {
        return None;
    }
    if !matches!(message.class(), Class::SuccessResponse) {
        return None;
    }
    reflexive_address(&message)
}

/// Pull the reflexive address out of a response, preferring the XOR variant.
fn reflexive_address(message: &Message) -> Option<MappedAddress> {
    if let Some(Attribute::XorMappedAddress(addr)) = message.get(types::XOR_MAPPED_ADDRESS) {
        return Some(*addr);
    }
    if let Some(Attribute::MappedAddress(addr)) = message.get(types::MAPPED_ADDRESS) {
        return Some(*addr);
    }
    None
}
