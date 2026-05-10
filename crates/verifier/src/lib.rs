#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! halo2-solana-verifier
//!
//! Tight BN254-only KZG/SHPLONK verifier for PSE-Halo2 proofs, designed for
//! the Solana BPF VM. Inspired by Light Protocol's `groth16-solana` pattern:
//! no generic Loader/CurveAffine abstraction, no halo2curves dependency —
//! direct calls to `solana_bn254` syscalls + arkworks types only.
//!
//! Architecture (decided in research+pivot phase):
//!   - On-chain: arkworks-bn254 for Fr/Fq arithmetic + alt_bn128 syscalls
//!     for G1/G2/pairing, Keccak transcript via sol_keccak256.
//!   - Off-chain: same code paths with feature `solana-syscalls` off; the
//!     syscalls module falls back to host arkworks ops (used for unit tests
//!     and the prover-side reference verifier).
//!
//! v1 targets devnet (SIMD-0284 LE byte order, SIMD-0302 G2 syscalls active).
//! v1.5 will add a mainnet fallback path that emulates G2 ops in pure BPF.
//!
//! See `vendor/snark-verifier/` (gitignored) for the upstream reference
//! implementation we cross-check against.

extern crate alloc;

pub mod error;
pub mod gate_compat;
pub mod syscalls;

pub mod field;
pub mod curve;
pub mod pairing;
pub mod transcript;

pub mod kzg;
pub mod plonk;
pub use plonk::proof_reader;

pub mod vk;
pub mod proof;
pub mod stage_state;

pub use error::Error;

use crate::kzg::KzgVk;

/// Verify a Halo2-PSE (BN254/KZG/SHPLONK) proof against the flat on-chain VK
/// bytes and a list of public inputs.
///
/// `kzg_vk` is the trimmed KZG verifying SRS (`[1]_1`, `[1]_2`, `[τ]_2`),
/// embedded as `const` in the calling BPF program's rodata. v1 ships a
/// StandardPlonk-specialised gate identity; arbitrary halo2 gate AST is v1.5.
pub fn verify(
    vk_bytes:      &[u8],
    proof_bytes:   &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk:        &KzgVk,
) -> Result<bool, Error> {
    plonk::verifier::verify(vk_bytes, proof_bytes, public_inputs, kzg_vk)
}
