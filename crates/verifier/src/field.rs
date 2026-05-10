//! BN254 scalar (Fr) helpers.
//!
//! On-chain we only ever work with Fr arithmetic (challenges, evaluations,
//! linear combinations). Fq lives inside `alt_bn128_*` syscalls as opaque
//! 32-byte limbs — we never touch its arithmetic directly.
//!
//! Byte conventions: 32-byte big-endian (mirrors mainnet `alt_bn128_*_be`).
//! LE swaps (devnet under SIMD-0284) live in `gate_compat` and are not
//! exposed here.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use crate::Error;

/// BN254 Fr DELTA constant — `GENERATOR^(2^S)` where `t·2^S + 1 = r`, `t` odd.
/// Used by halo2's permutation argument as the coset shift multiplier.
/// Source: halo2curves 0.6.1 / src/bn256/fr.rs:138
///
/// Hex (BE): `0x09226b6e22c6f0ca64ec26aad4c86e715b5f898e5e963f25870e56bbe533e9a2`
pub const DELTA_BE: [u8; 32] = [
    0x09, 0x22, 0x6b, 0x6e, 0x22, 0xc6, 0xf0, 0xca,
    0x64, 0xec, 0x26, 0xaa, 0xd4, 0xc8, 0x6e, 0x71,
    0x5b, 0x5f, 0x89, 0x8e, 0x5e, 0x96, 0x3f, 0x25,
    0x87, 0x0e, 0x56, 0xbb, 0xe5, 0x33, 0xe9, 0xa2,
];

/// Lazy const accessor — Fr is not `const`-constructible from arkworks, so we
/// build it once on first call. (BPF has no thread-local storage and our code
/// is single-threaded, so a plain `static` would also work.)
pub fn delta() -> Fr {
    Fr::from_be_bytes_mod_order(&DELTA_BE)
}

/// Decode a 32-byte big-endian scalar, **rejecting** representations that
/// exceed the Fr modulus. This matches `groth16-solana::Groth16Verifier`'s
/// strict bound check on public inputs and is required for soundness.
pub fn fr_from_bytes_be(bytes: &[u8; 32]) -> Result<Fr, Error> {
    // Fr modulus, big-endian:
    // 30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    const MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
    ];
    if !is_strictly_less(bytes, &MODULUS_BE) {
        return Err(Error::PublicInputOutOfRange);
    }
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

/// Encode an Fr to its canonical 32-byte big-endian representation.
pub fn fr_to_bytes_be(x: &Fr) -> [u8; 32] {
    let bigint = x.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut out = [0u8; 32];
    for (i, b) in le_bytes.iter().rev().enumerate() {
        out[i] = *b;
    }
    out
}

#[inline]
fn is_strictly_less(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Less    => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal   => continue,
        }
    }
    false
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_random() {
        let x = Fr::from(123456789u64);
        let be = fr_to_bytes_be(&x);
        let y = fr_from_bytes_be(&be).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn rejects_at_modulus() {
        let modulus = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
        ];
        assert!(matches!(fr_from_bytes_be(&modulus), Err(Error::PublicInputOutOfRange)));
    }

    #[test]
    fn rejects_above_modulus() {
        let mut over = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
        ];
        over[31] = 0x02;
        assert!(matches!(fr_from_bytes_be(&over), Err(Error::PublicInputOutOfRange)));
    }

    #[test]
    fn accepts_zero() {
        let zero = [0u8; 32];
        let f = fr_from_bytes_be(&zero).unwrap();
        assert_eq!(f, Fr::from(0u64));
    }

    #[test]
    fn accepts_one_below_modulus() {
        let mut just_under = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
        ];
        just_under[31] = 0x00;
        let f = fr_from_bytes_be(&just_under).unwrap();
        let back = fr_to_bytes_be(&f);
        assert_eq!(back, just_under);
    }
}
