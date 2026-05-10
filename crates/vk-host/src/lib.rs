//! Host-side compiler: PSE-Halo2 `VerifyingKey<G1Affine>`  →  on-chain bytes
//! consumed by `halo2_solana_verifier::vk::parse_vk`.
//!
//! Pipeline:
//!
//! ```text
//!   halo2_proofs::plonk::VerifyingKey<G1Affine>     ParamsKZG (provides k)
//!                          \                       /
//!                           ▼                     ▼
//!                          compile::compile_vk(...)
//!                                     │
//!                                     ▼
//!                          packed binary, BN254 BE field elements
//!                                     │
//!         embed as `const VK: &[u8]` in the BPF program (~500 B)
//!         OR write into a PDA account for multi-VK routing
//! ```
//!
//! `transcript_repr` (Halo2's Blake2b("Halo2-Verify-Key" ‖ pinned-VK) digest)
//! is read directly from `vk.transcript_repr()` — already pre-computed by
//! halo2 during `keygen_vk`. The on-chain verifier never needs Blake2b.

#![forbid(unsafe_code)]

pub mod compile;
pub mod encode;
pub mod expression_encoder;

pub use compile::{compile_vk, Error};
