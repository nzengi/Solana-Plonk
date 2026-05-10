//! Final BN254 pairing check.
//!
//! KZG/SHPLONK reduces verification to one batched pairing equation, e.g.
//!
//! ```text
//! e(W,  [τ]_2)  ·  e(F − [v]_1 − z·W,  [1]_2)  =  1
//! ```
//!
//! which encodes as 2 (G1, G2) pairs and one `alt_bn128_pairing` syscall
//! call. agave default cost: 36,364 + 12,121 = 48,485 CU + sha256 base + IO.

use crate::{curve::{G1, G2}, syscalls, Error};

/// Verify the multi-pairing equation `Π e(p.0, p.1) = 1` via one syscall.
pub fn pairing_check(pairs: &[(G1, G2)]) -> Result<bool, Error> {
    if pairs.is_empty() {
        return Err(Error::Protocol("pairing_check: empty input"));
    }
    let mut buf = alloc::vec::Vec::with_capacity(pairs.len() * 192);
    for (g1, g2) in pairs {
        buf.extend_from_slice(&g1.0);
        buf.extend_from_slice(&g2.0);
    }
    syscalls::pairing_check(&buf)
}

#[cfg(all(test, feature = "std", feature = "solana-syscalls"))]
mod tests {
    use super::*;

    /// G1 generator (1, 2).
    fn g1_gen() -> G1 {
        let mut b = [0u8; 64]; b[31] = 1; b[63] = 2; G1(b)
    }

    /// G2 generator (BN254). BE bytes from EIP-197 / arkworks.
    /// x.c1 = 0x198e9393…, x.c0 = 0x1800deef…, y.c1 = 0x090689d…, y.c0 = 0x12c85ea…
    fn g2_gen() -> G2 {
        // Standard EIP-197 G2 generator, BE order.
        let bytes: [u8; 128] = [
            0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a,
            0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
            0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12,
            0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
            0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76,
            0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
            0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd,
            0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
            0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75,
            0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
            0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3,
            0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
            0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb,
            0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
            0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b,
            0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
        ];
        G2(bytes)
    }

    /// e(G₁, G₂) · e(−G₁, G₂) = 1  ⇒  pairing-check passes.
    /// We construct −G₁ on BN254 by negating the y-coordinate: y → p − y
    /// (where p is the BN254 base-field modulus).
    #[test]
    fn negation_pairs_to_one() {
        // BN254 base field modulus Fq, BE:
        // 30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
        const Q_BE: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
            0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
        ];

        let g = g1_gen();
        let mut neg_g_bytes = [0u8; 64];
        neg_g_bytes[..32].copy_from_slice(&g.0[..32]); // x unchanged
        // y' = q − y. y = 2 here, so y' = q − 2.
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let y_byte = g.0[32 + i] as i32;
            let q_byte = Q_BE[i] as i32;
            let mut diff = q_byte - y_byte - borrow;
            if diff < 0 { diff += 256; borrow = 1; } else { borrow = 0; }
            neg_g_bytes[32 + i] = diff as u8;
        }
        let neg_g = G1(neg_g_bytes);
        let h = g2_gen();
        let ok = pairing_check(&[(g, h), (neg_g, h)]).unwrap();
        assert!(ok, "e(G,H) · e(-G,H) should equal 1");
    }
}
