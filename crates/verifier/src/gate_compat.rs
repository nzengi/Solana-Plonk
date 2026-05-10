//! Solana feature-gate compatibility shim.
//!
//! Devnet (May 2026) has activated:
//!   * SIMD-0284  — alt_bn128 little-endian byte order
//!   * SIMD-0302  — G2 add/mul syscalls
//!
//! Mainnet has neither. v1 targets devnet (with `devnet-feature-gates` on);
//! a v1.5 mainnet shim will:
//!   * convert LE↔BE in Rust
//!   * emulate G2 ops in pure BPF using `ark-bn254` (slow path)
//!
//! Stub for now — concrete impls land alongside task #11.

#[cfg(feature = "devnet-feature-gates")]
pub const ENDIANNESS: &str = "little";

#[cfg(not(feature = "devnet-feature-gates"))]
pub const ENDIANNESS: &str = "big";
