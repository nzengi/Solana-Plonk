//! v1 test circuit: Standard PLONK gate.
//!
//! ```text
//!     q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0
//! ```
//!
//! Column ordering (must match `halo2_solana_verifier::plonk::verifier::standard_plonk`):
//!
//! ```text
//!   fixed:  [q_a, q_b, q_c, q_ab, q_const]
//!   advice: [a, b, c]
//! ```
//!
//! All advice columns are part of a single permutation argument so the
//! verifier exercises the grand-product identity. No lookups, no shuffles.

#![forbid(unsafe_code)]

pub mod circuit;
pub mod keccak_be_transcript;
pub mod prover;
pub mod shadow;

pub use circuit::StandardPlonk;
pub use prover::{generate_test_vector, generate_test_vector_with_vk, TestVector};
