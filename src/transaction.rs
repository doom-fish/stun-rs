//! STUN transaction IDs and the client retransmission schedule.

use std::time::Duration;

use crate::error::Result;
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
    /// Returns [`Error::Rng`](crate::Error::Rng) if the system RNG fails.
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
pub const DEFAULT_MAX_RETRANSMITS: u32 = 6;

#[allow(missing_docs)]
pub const FINAL_WAIT_RTO_MULTIPLIER: u32 = 16;

/// Iterator over the per-request wait durations of a STUN transaction
/// (RFC 5389 §7.2.1).
///
/// The first request waits one RTO and each retransmission doubles the wait
/// (`RTO * 2^n`); after the last of [`DEFAULT_MAX_RETRANSMITS`]
/// retransmissions the client waits [`FINAL_WAIT_RTO_MULTIPLIER`] RTOs, so a
/// 500 ms RTO sends requests at 0, 500, 1500, 3500, 7500, 15500 and 31500 ms
/// and gives up at 39.5 s. The caller sends the request once up front and,
/// each time a yielded duration elapses without a response, resends it if
/// another duration follows.
#[derive(Debug, Clone)]
pub struct RetransmitSchedule {
    rto: Duration,
    attempt: u32,
    max_retransmits: u32,
}

impl RetransmitSchedule {
    /// Create the default RFC 5389 schedule (RTO = 500 ms).
    #[must_use]
    pub fn new() -> Self {
        Self::with_rto(DEFAULT_RTO)
    }

    /// Create a schedule with a custom initial RTO.
    #[must_use]
    pub const fn with_rto(rto: Duration) -> Self {
        Self {
            rto,
            attempt: 0,
            max_retransmits: DEFAULT_MAX_RETRANSMITS,
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
        if self.attempt > self.max_retransmits {
            return None;
        }
        let multiplier = if self.attempt == self.max_retransmits {
            FINAL_WAIT_RTO_MULTIPLIER
        } else {
            1u32 << self.attempt.min(31)
        };
        let wait = self.rto.saturating_mul(multiplier);
        self.attempt += 1;
        if wait.is_zero() {
            None
        } else {
            Some(wait)
        }
    }
}
