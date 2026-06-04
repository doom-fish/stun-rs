//! Build script for `stun-rs`.
//!
//! Links the Apple `Security` framework so the transaction-ID RNG can call
//! `SecRandomCopyBytes`. The HMAC-SHA1 / MD5 helpers call into CommonCrypto,
//! which lives in `libSystem` and is linked automatically — no extra flags
//! are needed for it.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    if std::env::var("DOCS_RS").is_ok() {
        return;
    }

    // SecRandomCopyBytes / kSecRandomDefault.
    println!("cargo:rustc-link-lib=framework=Security");
}
