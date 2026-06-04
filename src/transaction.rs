//! STUN transaction IDs and the client retransmission schedule.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::rng;

/// Length of a STUN transaction ID in bytes (96 bits, RFC 5389 §6).
pub const TRANSACTION_ID_LEN: usize = 12;

/// A 96-bit STUN transaction ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; TRANSACTION_ID_LEN]);

impl TransactionId {
    /// Construct a transaction ID from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TRANSACTION_ID_LEN] {
        &self.0
    }

    /// Generate a fresh, cryptographically random transaction ID.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails, which does not happen on a healthy
    /// system. Use [`TransactionId::try_random`] for a fallible variant.
    #[must_use]
    pub fn random() -> Self {
        Self::try_random().expect("system RNG failed")
    }

    /// Generate a fresh, cryptographically random transaction ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the system RNG fails.
    pub fn try_random() -> Result<Self> {
        Ok(Self(rng::random_array::<TRANSACTION_ID_LEN>()?))
    }
}

impl From<[u8; TRANSACTION_ID_LEN]> for TransactionId {
    fn from(bytes: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for TransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TransactionId(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl core::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Default initial retransmission timeout (RFC 5389 §7.2.1).
pub const DEFAULT_RTO: Duration = Duration::from_millis(500);

/// Default number of retransmissions before giving up.
pub const DEFAULT_MAX_RETRANSMITS: u32 = 9;

/// The hard cap on total transaction time, expressed as a multiple of the RTO
/// (RFC 5389 §7.2.1 gives `39.5 * RTO`).
pub const TOTAL_TIMEOUT_RTO_MULTIPLIER: f64 = 39.5;

/// Iterator over the per-attempt wait durations of a STUN transaction.
///
/// The first attempt waits one RTO; each subsequent attempt doubles the wait
/// (`RTO * 2^n`). Iteration stops after [`DEFAULT_MAX_RETRANSMITS`] waits or
/// once the cumulative time reaches `39.5 * RTO`, whichever comes first. The
/// caller sends the request once up front and then resends each time the
/// yielded duration elapses without a response.
#[derive(Debug, Clone)]
pub struct RetransmitSchedule {
    rto: Duration,
    attempt: u32,
    max_retransmits: u32,
    elapsed: Duration,
    total_budget: Duration,
}

impl RetransmitSchedule {
    /// Create the default RFC 5389 schedule (RTO = 500 ms).
    #[must_use]
    pub fn new() -> Self {
        Self::with_rto(DEFAULT_RTO)
    }

    /// Create a schedule with a custom initial RTO.
    #[must_use]
    pub fn with_rto(rto: Duration) -> Self {
        let total_budget = rto.mul_f64(TOTAL_TIMEOUT_RTO_MULTIPLIER);
        Self {
            rto,
            attempt: 0,
            max_retransmits: DEFAULT_MAX_RETRANSMITS,
            elapsed: Duration::ZERO,
            total_budget,
        }
    }
}

impl Default for RetransmitSchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for RetransmitSchedule {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        if self.attempt > self.max_retransmits || self.elapsed >= self.total_budget {
            return None;
        }
        let wait = self.rto.saturating_mul(1u32 << self.attempt.min(31));
        // Clamp the final wait so the total never exceeds the budget.
        let remaining = self.total_budget.saturating_sub(self.elapsed);
        let wait = wait.min(remaining);
        self.elapsed += wait;
        self.attempt += 1;
        if wait.is_zero() {
            None
        } else {
            Some(wait)
        }
    }
}

/// Convert a [`crate::error::Error`] for a timed-out transaction.
#[must_use]
pub(crate) fn timeout_error() -> Error {
    Error::Timeout
}
