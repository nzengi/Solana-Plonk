//! PRUV code-integrity circuit for native on-chain verification.
//!
//! Statement (5 public inputs, instance rows 0..5; row 4 is the constant 0 the sponge capacity lanes are pinned to):
//!   commitment = Poseidon(Poseidon(program_id, hash_lo), hash_hi)
//! where `program_id` is the dApp's pubkey (top two bits cleared), `hash_lo` /
//! `hash_hi` the two 16-byte halves of SHA-256(bytecode). Both Poseidon
//! permutations are fully constrained by the chip in `poseidon.rs` (ARK, x^5
//! S-box, MDS on every row, inputs copy-constrained).
//!
//! This is a port of `pruv/circuits/src/code_integrity.rs` from halo2 `main`
//! to the v0.3.0 tag the on-chain verifier is built against. The native
//! commitment must equal `pruv_circuits::code_integrity::compute_poseidon_commitment`
//! byte for byte (checked by `gen-ci-proof --expect-commitment`).

pub mod circuit;
pub mod poseidon;
pub mod prover;

pub use prover::{generate_ci_test_vector, CiTestVector};

use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

/// Little-endian bytes → Fr with the top byte cleared: always < 2^248 < r, so the
/// same value is accepted by the `sol_poseidon` syscall when the attestation
/// program recomputes the commitment on-chain.
pub fn field_from_le_bytes(b: &[u8; 32]) -> Fr {
    let mut repr = *b;
    repr[31] = 0;
    Fr::from_repr(repr).expect("< 2^248 is always a canonical field element")
}

/// 16 bytes of a hash → Fr (little-endian, zero-padded).
pub fn field_from_le_bytes_half(hash: &[u8; 32], range: std::ops::Range<usize>) -> Fr {
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&hash[range]);
    Fr::from_repr(buf).expect("128-bit value is a canonical field element")
}

/// The three field inputs and the native commitment for a (program_id, hash) pair.
pub fn public_inputs(program_id: &[u8; 32], program_hash: &[u8; 32]) -> [Fr; 4] {
    let pid = field_from_le_bytes(program_id);
    let lo = field_from_le_bytes_half(program_hash, 0..16);
    let hi = field_from_le_bytes_half(program_hash, 16..32);
    let inner = poseidon::hash_two(pid, lo);
    let commitment = poseidon::hash_two(inner, hi);
    [pid, lo, hi, commitment]
}

/// 32-byte little-endian encoding of a field element (PRUV's `fr_to_bytes`).
pub fn fr_to_bytes_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(f.to_repr().as_ref());
    out
}
