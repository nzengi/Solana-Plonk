//! On-chain proof byte format for PSE-Halo2 KZG/SHPLONK.
//!
//! Packed binary, BN254 big-endian. Layout determined off-chain by the proof
//! generator; on-chain we just deserialise.
//!
//! ```text
//! advice_commits:    [G1; num_advice]
//! lookup_commits:    [G1; 5*num_lookups]   // v1.5
//! z_commit:          G1                    // permutation grand product
//! vanishing_h:       [G1; cs_degree]
//! evaluations:       [Fr; ?]               // gate evals + perm evals
//! opening_proof:     [G1; 2]               // SHPLONK W₁, W₂
//! ```
//!
//! Filled in by task #4 (verifier core) + task #8 (proof generator).

use crate::{plonk::PlonkProof, Error};

pub fn parse_proof(_bytes: &[u8]) -> Result<PlonkProof, Error> {
    Err(Error::Protocol("proof::parse_proof — task #4"))
}
