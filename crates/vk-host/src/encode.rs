//! Compact, mixed-endian binary encoder for the on-chain VK format.
//! Mirrors `halo2_solana_verifier::vk::parse_vk` byte-for-byte.

use halo2curves::bn256::{Fq, Fr, G1Affine};
use halo2curves::ff::PrimeField;
use halo2curves::group::prime::PrimeCurveAffine;

/// Magic bytes prefixed to every on-chain VK blob.
/// Tied to the verifier-router pattern — bumping the magic forces an explicit
/// VK migration if a soundness bug is ever found in the verifier.
pub const VK_MAGIC: &[u8; 8] = b"H2SV0003";
pub const VK_VERSION: u32 = 3;

/// Convert a halo2curves bn256 `Fr` (scalar) to canonical 32-byte big-endian.
/// `to_repr()` returns canonical (post-Montgomery) little-endian bytes.
pub fn fr_to_bytes_be(f: &Fr) -> [u8; 32] {
    let le = f.to_repr();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().rev().enumerate() {
        be[i] = *b;
    }
    be
}

/// Convert a halo2curves bn256 `Fq` (base field) to canonical 32-byte BE.
pub fn fq_to_bytes_be(f: &Fq) -> [u8; 32] {
    let le = f.to_repr();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().rev().enumerate() {
        be[i] = *b;
    }
    be
}

/// Encode a halo2curves `G1Affine` to 64-byte BE: `x ‖ y`.
/// Matches the byte layout consumed by `alt_bn128_*_be` syscalls.
pub fn g1_affine_to_bytes_be(p: &G1Affine) -> [u8; 64] {
    if bool::from(p.is_identity()) {
        return [0u8; 64];
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_bytes_be(&p.x));
    out[32..].copy_from_slice(&fq_to_bytes_be(&p.y));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::bn256::G1;
    use halo2curves::group::Curve;

    #[test]
    fn fr_to_bytes_be_zero() {
        let f = Fr::zero();
        assert_eq!(fr_to_bytes_be(&f), [0u8; 32]);
    }

    #[test]
    fn fr_to_bytes_be_one() {
        let f = Fr::one();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(fr_to_bytes_be(&f), expected);
    }

    #[test]
    fn g1_generator_be_layout() {
        // BN254 G1 generator is (1, 2). BE encoding: 31×0x00, 0x01, 31×0x00, 0x02.
        let gen: G1Affine = G1::generator().to_affine();
        let bytes = g1_affine_to_bytes_be(&gen);
        let mut expected = [0u8; 64];
        expected[31] = 1;
        expected[63] = 2;
        assert_eq!(bytes, expected);
    }

    #[test]
    fn g1_identity_serializes_to_zeros() {
        let id: G1Affine = G1Affine::identity();
        assert_eq!(g1_affine_to_bytes_be(&id), [0u8; 64]);
    }
}
