//! Cryptographically secure random bytes via Apple's `Security` framework.
//!
//! RFC 5389 §6 requires the 96-bit transaction ID to be drawn from a
//! cryptographically strong RNG. We bind `SecRandomCopyBytes` directly rather
//! than pulling in an external RNG crate, keeping the crate dependency-free at
//! runtime.

use core::ffi::c_void;

extern "C" {
    /// `SecRandomRef kSecRandomDefault;` — opaque default RNG handle.
    static kSecRandomDefault: *const c_void;

    /// `int SecRandomCopyBytes(SecRandomRef rnd, size_t count, void *bytes);`
    ///
    /// Returns `0` on success, `-1` on failure.
    fn SecRandomCopyBytes(rnd: *const c_void, count: usize, bytes: *mut u8) -> i32;
}

/// Fill `buf` with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`RngError`] if the system RNG fails (effectively never on a
/// healthy system).
pub fn fill(buf: &mut [u8]) -> Result<(), RngError> {
    if buf.is_empty() {
        return Ok(());
    }
    let status = unsafe { SecRandomCopyBytes(kSecRandomDefault, buf.len(), buf.as_mut_ptr()) };
    if status == 0 {
        Ok(())
    } else {
        Err(RngError)
    }
}

/// Return an array of `N` cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`RngError`] if the system RNG fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], RngError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// The system random-number generator reported a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecRandomCopyBytes failed")
    }
}

impl std::error::Error for RngError {}
