//! BN254 G1/G2 affine points + the Solana syscall bridge.
//!
//! Byte format (mainnet today, BE):
//!     G1 = X ‖ Y, 32-byte BE limbs (64 B total)
//!     G2 = X.c1 ‖ X.c0 ‖ Y.c1 ‖ Y.c0, 32-byte BE limbs (128 B total)
//!
//! These are the formats `solana_bn254::prelude::*_be` consume verbatim.

use crate::{syscalls, Error};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct G1(pub [u8; 64]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct G2(pub [u8; 128]);

impl G1 {
    pub const IDENTITY: G1 = G1([0u8; 64]);

    pub fn add(&self, other: &G1) -> Result<G1, Error> {
        syscalls::g1_add(&self.0, &other.0).map(G1)
    }

    pub fn scalar_mul(&self, scalar_be: &[u8; 32]) -> Result<G1, Error> {
        syscalls::g1_mul(&self.0, scalar_be).map(G1)
    }

    /// Sequential multi-scalar multiplication (no Pippenger in v1).
    /// CU profile: ~3,840·N + 334·(N−1) per syscall costs (May 2026 agave).
    pub fn msm(scalars: &[[u8; 32]], points: &[G1]) -> Result<G1, Error> {
        if scalars.len() != points.len() {
            return Err(Error::Protocol("msm: scalars and points length mismatch"));
        }
        if scalars.is_empty() {
            return Ok(G1::IDENTITY);
        }
        let mut acc = points[0].scalar_mul(&scalars[0])?;
        for (s, p) in scalars[1..].iter().zip(points[1..].iter()) {
            let term = p.scalar_mul(s)?;
            acc = acc.add(&term)?;
        }
        Ok(acc)
    }
}

impl G2 {
    pub const IDENTITY: G2 = G2([0u8; 128]);

    pub const fn from_bytes(bytes: [u8; 128]) -> Self { Self(bytes) }

    /// G2 ops are devnet-only today (SIMD-0302). On mainnet, the only G2
    /// operations our verifier performs are *loading* the SRS-fixed `[1]_2`
    /// and `[τ]_2` from rodata — no scalar mul needed in the basic path.
    pub fn add(&self, other: &G2) -> Result<G2, Error> {
        syscalls::g2_add(&self.0, &other.0).map(G2)
    }
    pub fn scalar_mul(&self, scalar_be: &[u8; 32]) -> Result<G2, Error> {
        syscalls::g2_mul(&self.0, scalar_be).map(G2)
    }
}

#[cfg(all(test, feature = "std", feature = "solana-syscalls"))]
mod tests {
    use super::*;

    /// G1 generator point on BN254, big-endian:
    ///   x = 1
    ///   y = 2
    fn g1_generator() -> G1 {
        let mut bytes = [0u8; 64];
        bytes[31] = 1; // x = 1
        bytes[63] = 2; // y = 2
        G1(bytes)
    }

    #[test]
    fn add_generator_to_identity() {
        let g = g1_generator();
        let s = g.add(&G1::IDENTITY).unwrap();
        assert_eq!(s, g, "G + 0 = G");
    }

    #[test]
    fn double_via_add_equals_mul_by_2() {
        let g = g1_generator();
        let g2_via_add = g.add(&g).unwrap();
        let mut two = [0u8; 32];
        two[31] = 2;
        let g2_via_mul = g.scalar_mul(&two).unwrap();
        assert_eq!(g2_via_add, g2_via_mul, "2G via add ≡ G·2 via mul");
    }

    #[test]
    fn mul_by_zero_yields_identity() {
        let g = g1_generator();
        let zero = [0u8; 32];
        let r = g.scalar_mul(&zero).unwrap();
        assert_eq!(r, G1::IDENTITY, "G·0 = O");
    }

    #[test]
    fn msm_matches_naive() {
        let g = g1_generator();
        let scalars = [
            { let mut s = [0u8; 32]; s[31] = 3; s },
            { let mut s = [0u8; 32]; s[31] = 5; s },
        ];
        let points = [g, g];
        let msm_result = G1::msm(&scalars, &points).unwrap();
        let mut eight = [0u8; 32];
        eight[31] = 8;
        let naive = g.scalar_mul(&eight).unwrap();
        assert_eq!(msm_result, naive, "MSM(3·G, 5·G) = 8·G");
    }
}
