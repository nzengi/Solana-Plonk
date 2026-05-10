//! v2.0 test circuit: shuffle argument.
//!
//! Halo2 declares `cs.shuffle("name", |meta| { vec![(input_expr, shuffle_expr)] })`
//! to assert that the multiset of `input` values equals the multiset of
//! `shuffle` values across the circuit's rows. Halo2 then commits to a
//! grand-product `z` and emits the 3 expressions our verifier covers in
//! `crates/verifier/src/plonk/shuffle.rs`.
//!
//! Constraints (2 advice columns `input` / `shuffled`, 1 shuffle argument):
//!
//! ```text
//! shuffle("permute 4 values", |meta| {
//!     let i = meta.query_advice(input,    Rotation::cur());
//!     let s = meta.query_advice(shuffled, Rotation::cur());
//!     vec![(i, s)]
//! });
//! ```
//!
//! Witness: `input = [1, 2, 3, 4]`, `shuffled = [3, 1, 4, 2]` — the same
//! multiset. Halo2's prover runs and emits a valid proof; we verify it.

pub mod circuit;
pub mod prover;
pub mod shadow;

pub use circuit::ShuffleCheckCircuit;
pub use prover::generate_sh_test_vector;
