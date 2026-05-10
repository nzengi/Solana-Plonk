//! KZG polynomial commitment scheme on BN254 + the SHPLONK (BDFG21) batched
//! multi-opening protocol used by PSE-Halo2 by default.
//!
//! Verifier's final step is one pairing equation (see `crate::pairing`).
//!
//! Filled in by task #5 (syscall bridge) and task #4 (algorithmic logic).

pub mod shplonk;

use crate::curve::{G1, G2};

/// Trimmed verifying SRS — all the on-chain verifier ever needs.
/// Lives in BPF rodata (≈192 B).
#[derive(Clone, Copy, Debug)]
pub struct KzgVk {
    pub g1_one: G1,    // [1]_1
    pub g2_one: G2,    // [1]_2
    pub g2_tau: G2,    // [τ]_2
}
