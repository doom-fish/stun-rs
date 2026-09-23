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
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use networkframework::{Connection, ConnectionParameters, NetworkError};

use crate::attribute::{types, Attribute};
use crate::error::{Error, Result};
use crate::message::{Class, Message, Method};
use crate::transaction::{RetransmitSchedule, TransactionId, DEFAULT_RTO};

/// Default STUN port (RFC 5389 §9).
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// Maximum UDP datagram size we are willing to receive.
const MAX_DATAGRAM: usize = 1500;

const RESERVED_ATTRIBUTES: [u16; 7] = [0x0000, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x000B];

type Datagram = std::result::Result<Vec<u8>, NetworkError>;

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
#[derive(Debug, Clone)]
pub struct StunClient {
    software: Option<String>,
    fingerprint: bool,
    rto: Duration,
}

impl Default for StunClient {
    fn default() -> Self {
        Self {
            software: None,
            fingerprint: false,
            rto: DEFAULT_RTO,
        }
    }
}

impl StunClient {
    /// Create a client with default behavior (sends `SOFTWARE` +
    /// `FINGERPRINT`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            software: Some(concat!("doomfish-stun/", env!("CARGO_PKG_VERSION")).to_owned()),
            fingerprint: true,
            rto: DEFAULT_RTO,
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

    #[allow(missing_docs)]
    #[must_use]
    pub const fn rto(mut self, rto: Duration) -> Self {
        self.rto = rto;
        self
    }

    /// Perform a STUN Binding transaction against `server` and return the
    /// reflexive transport address.
    ///
    /// Retransmits per RFC 5389 §7.2.1 (initial RTO 500 ms unless set with
    /// [`StunClient::rto`], doubling) until a response to this transaction
    /// arrives or the schedule is exhausted.
    ///
    /// # Errors
    ///
    /// * [`Error::Network`] if the socket cannot be opened or a send or
    ///   receive fails.
    /// * [`Error::Timeout`] if no matching response arrives in time.
    /// * [`Error::ErrorResponse`] if the server answers with an error response.
    /// * [`Error::UnknownAttributes`] if the response carries
    ///   comprehension-required attributes this crate does not understand.
    /// * Decoding errors if the response is malformed.
    pub fn bind(&self, server: &Endpoint) -> Result<MappedAddress> {
        let transaction_id = TransactionId::try_random()?;
        let request = self.build_request(transaction_id)?;

        let parameters = ConnectionParameters::udp().map_err(|e| Error::Network(e.to_string()))?;
        let socket = Connection::connect_with_parameters(server.host(), server.port(), &parameters)
            .map_err(|e| Error::Network(e.to_string()))?;
        let socket = Arc::new(socket);

        let (tx, rx) = mpsc::channel();
        let receiver = {
            let socket = Arc::clone(&socket);
            thread::Builder::new()
                .name("stun-bind-receiver".to_owned())
                .spawn(move || receive_datagrams(&socket, &tx))
                .map_err(|e| Error::Network(e.to_string()))?
        };

        let outcome = run_transaction(&socket, &rx, &request, &transaction_id, self.rto);
        socket.force_cancel();
        if receiver.join().is_err() {
            return Err(Error::Network("STUN receiver thread panicked".to_owned()));
        }
        outcome
    }

    /// Build the Binding request bytes for a given transaction ID.
    fn build_request(&self, transaction_id: TransactionId) -> Result<Vec<u8>> {
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

fn receive_datagrams(socket: &Connection, datagrams: &Sender<Datagram>) {
    let error = loop {
        match socket.receive_message(MAX_DATAGRAM) {
            Ok(content) => {
                if datagrams.send(Ok(content.data)).is_err() {
                    return;
                }
            }
            Err(NetworkError::MessageTooLarge { .. }) => {}
            Err(error) => break error,
        }
    };
    let _ = datagrams.send(Err(error));
}

fn run_transaction(
    socket: &Connection,
    datagrams: &Receiver<Datagram>,
    request: &[u8],
    transaction_id: &TransactionId,
    rto: Duration,
) -> Result<MappedAddress> {
    let mut schedule = RetransmitSchedule::with_rto(rto).peekable();
    socket
        .send(request)
        .map_err(|e| Error::Network(e.to_string()))?;
    while let Some(wait) = schedule.next() {
        let started = Instant::now();
        while let Some(remaining) = wait.checked_sub(started.elapsed()) {
            match datagrams.recv_timeout(remaining) {
                Ok(Ok(datagram)) => {
                    if let Some(outcome) = match_response(&datagram, transaction_id) {
                        return outcome;
                    }
                }
                Ok(Err(error)) => return Err(Error::Network(error.to_string())),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::Network("STUN receiver stopped".to_owned()));
                }
            }
        }
        if schedule.peek().is_some() {
            socket
                .send(request)
                .map_err(|e| Error::Network(e.to_string()))?;
        }
    }
    Err(Error::Timeout)
}

/// Decode a datagram and, if it is the response to this Binding transaction,
/// return the transaction's outcome.
fn match_response(datagram: &[u8], expected: &TransactionId) -> Option<Result<MappedAddress>> {
    let message = Message::decode(datagram).ok()?;
    if message.transaction_id() != expected || message.method() != Method::Binding {
        return None;
    }
    if matches!(message.class(), Class::Request | Class::Indication) {
        return None;
    }
    if message.get(types::FINGERPRINT).is_some() && message.verify_fingerprint().is_err() {
        return None;
    }
    let unknown: Vec<u16> = message
        .unknown_comprehension_required()
        .into_iter()
        .filter(|attribute_type| !RESERVED_ATTRIBUTES.contains(attribute_type))
        .collect();
    if !unknown.is_empty() {
        return Some(Err(Error::UnknownAttributes(unknown)));
    }
    if message.class() == Class::ErrorResponse {
        return Some(Err(match message.get(types::ERROR_CODE) {
            Some(Attribute::ErrorCode(code)) => Error::ErrorResponse(code.clone()),
            _ => Error::MalformedAttribute("STUN error response without ERROR-CODE"),
        }));
    }
    Some(reflexive_address(&message).ok_or(Error::MalformedAttribute(
        "Binding success response without a mapped address",
    )))
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
