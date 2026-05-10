//! Thin wrappers around Solana's `alt_bn128` and `keccak256` syscalls.
//!
//! Byte format on mainnet today: big-endian 32-byte field elements.
//! G1 = X ‖ Y (64 B); G2 = X.c1 ‖ X.c0 ‖ Y.c1 ‖ Y.c0 (128 B); scalar = 32 B BE.
//! Source of truth: agave `program-runtime/src/execution_budget.rs` (May 2026).
//!
//! The upstream `solana_bn254::prelude::*` functions already handle the
//! `target_os = "solana"` switch internally — on BPF they call the actual
//! `sol_alt_bn128_group_op` syscall, on host they fall back to arkworks
//! emulation. We therefore have ONE code path per primitive.
//!
//! Two compile paths in *this* crate:
//!   * `solana-syscalls` feature on  → upstream wrappers (BPF + host both work)
//!   * feature off                   → pure arkworks; used by unit tests that
//!                                     do not want a solana-program dep tree.
//!
//! Per-syscall CU costs (mainnet, agave May 2026):
//!     G1 add:        334
//!     G1 mul:      3,840
//!     G2 add (DN):   535
//!     G2 mul (DN): 15,670
//!     pairing:    36,364 + 12,121 per additional pair
//!
//! "DN" = devnet-only, gated behind SIMD-0302.

use crate::Error;

#[cfg(feature = "solana-syscalls")]
mod onchain {
    use super::Error;
    use solana_bn254::prelude::{
        alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
    };

    pub fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> Result<[u8; 64], Error> {
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(a);
        input[64..].copy_from_slice(b);
        let out = alt_bn128_g1_addition_be(&input)
            .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g1_add", code: e.into() })?;
        debug_assert_eq!(out.len(), 64);
        let mut result = [0u8; 64];
        result.copy_from_slice(&out);
        Ok(result)
    }

    pub fn g1_mul(p: &[u8; 64], scalar_be: &[u8; 32]) -> Result<[u8; 64], Error> {
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(p);
        input[64..].copy_from_slice(scalar_be);
        let out = alt_bn128_g1_multiplication_be(&input)
            .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g1_mul", code: e.into() })?;
        debug_assert_eq!(out.len(), 64);
        let mut result = [0u8; 64];
        result.copy_from_slice(&out);
        Ok(result)
    }

    /// Returns `Ok(true)` iff `Π e(p₁, p₂) = 1`.
    /// `pairs` must be already laid out as `[(G1‖G2); N]` flat bytes (192·N total).
    pub fn pairing_check(pairs: &[u8]) -> Result<bool, Error> {
        if pairs.is_empty() || pairs.len() % 192 != 0 {
            return Err(Error::Protocol("pairing_check: input not a multiple of 192"));
        }
        let out = alt_bn128_pairing_be(pairs)
            .map_err(|e| Error::SyscallFailed { which: "alt_bn128_pairing", code: e.into() })?;
        debug_assert_eq!(out.len(), 32);
        // BE BigInteger256: success → [0; 31, 1], failure → [0; 32].
        Ok(out[..31].iter().all(|&b| b == 0) && out[31] == 1)
    }

    /// Keccak-256 over `input`. Same syscall on BPF, sha3 emulation on host.
    pub fn keccak256(input: &[u8]) -> [u8; 32] {
        solana_program::keccak::hashv(&[input]).to_bytes()
    }

    // -------- G2 ops — devnet only (SIMD-0302) ---------------------------------

    #[cfg(feature = "devnet-feature-gates")]
    pub fn g2_add(a: &[u8; 128], b: &[u8; 128]) -> Result<[u8; 128], Error> {
        use solana_bn254::prelude::alt_bn128_g2_addition_be;
        let mut input = [0u8; 256];
        input[..128].copy_from_slice(a);
        input[128..].copy_from_slice(b);
        let out = alt_bn128_g2_addition_be(&input)
            .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g2_add", code: e.into() })?;
        debug_assert_eq!(out.len(), 128);
        let mut result = [0u8; 128];
        result.copy_from_slice(&out);
        Ok(result)
    }

    #[cfg(feature = "devnet-feature-gates")]
    pub fn g2_mul(p: &[u8; 128], scalar_be: &[u8; 32]) -> Result<[u8; 128], Error> {
        use solana_bn254::prelude::alt_bn128_g2_multiplication_be;
        let mut input = [0u8; 160];
        input[..128].copy_from_slice(p);
        input[128..].copy_from_slice(scalar_be);
        let out = alt_bn128_g2_multiplication_be(&input)
            .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g2_mul", code: e.into() })?;
        debug_assert_eq!(out.len(), 128);
        let mut result = [0u8; 128];
        result.copy_from_slice(&out);
        Ok(result)
    }

    #[cfg(not(feature = "devnet-feature-gates"))]
    pub fn g2_add(_a: &[u8; 128], _b: &[u8; 128]) -> Result<[u8; 128], Error> {
        // Mainnet fallback (v1.5): emulate with arkworks G2 ops.
        Err(Error::Protocol("g2_add requires SIMD-0302 (devnet) — mainnet shim TBD"))
    }

    #[cfg(not(feature = "devnet-feature-gates"))]
    pub fn g2_mul(_p: &[u8; 128], _scalar_be: &[u8; 32]) -> Result<[u8; 128], Error> {
        Err(Error::Protocol("g2_mul requires SIMD-0302 (devnet) — mainnet shim TBD"))
    }
}

#[cfg(not(feature = "solana-syscalls"))]
mod onchain {
    //! Pure-arkworks fallback for tests run without the `solana-syscalls`
    //! feature. Same byte semantics, no Solana dep tree.
    use super::Error;
    use ark_bn254::{Fr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::{Field, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

    fn parse_g1_be(bytes: &[u8; 64]) -> Result<G1Affine, Error> {
        if *bytes == [0u8; 64] { return Ok(G1Affine::zero()); }
        let mut le = [0u8; 64];
        for (dst, src) in le[..32].iter_mut().zip(bytes[..32].iter().rev()) { *dst = *src; }
        for (dst, src) in le[32..].iter_mut().zip(bytes[32..].iter().rev()) { *dst = *src; }
        let p = G1Affine::deserialize_with_mode(&le[..], Compress::No, Validate::Yes)
            .map_err(|_| Error::Protocol("host g1 parse"))?;
        Ok(p)
    }
    fn emit_g1_be(p: G1Affine) -> [u8; 64] {
        let mut out_le = [0u8; 64];
        if p.is_zero() { return [0u8; 64]; }
        let (x, y) = p.xy().expect("non-identity");
        x.serialize_with_mode(&mut out_le[..32], Compress::No).unwrap();
        y.serialize_with_mode(&mut out_le[32..], Compress::No).unwrap();
        let mut be = [0u8; 64];
        for (i, b) in out_le[..32].iter().rev().enumerate() { be[i] = *b; }
        for (i, b) in out_le[32..].iter().rev().enumerate() { be[32 + i] = *b; }
        be
    }

    pub fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> Result<[u8; 64], Error> {
        let pa = parse_g1_be(a)?;
        let pb = parse_g1_be(b)?;
        let sum: G1Affine = (pa + pb).into();
        Ok(emit_g1_be(sum))
    }

    pub fn g1_mul(p: &[u8; 64], scalar_be: &[u8; 32]) -> Result<[u8; 64], Error> {
        let pa = parse_g1_be(p)?;
        let s = Fr::from_be_bytes_mod_order(scalar_be);
        let prod: G1Affine = (pa * s).into();
        Ok(emit_g1_be(prod))
    }

    pub fn pairing_check(pairs: &[u8]) -> Result<bool, Error> {
        use ark_bn254::Bn254;
        use ark_ec::pairing::Pairing;
        if pairs.is_empty() || pairs.len() % 192 != 0 {
            return Err(Error::Protocol("pairing_check: input not multiple of 192"));
        }
        let mut g1s = alloc::vec::Vec::new();
        let mut g2s = alloc::vec::Vec::new();
        for chunk in pairs.chunks_exact(192) {
            let g1_bytes: &[u8; 64] = chunk[..64].try_into().unwrap();
            let g2_bytes: &[u8; 128] = chunk[64..].try_into().unwrap();
            g1s.push(parse_g1_be(g1_bytes)?);
            // G2 host parse — flip endianness like solana-bn254 does internally.
            let mut le = [0u8; 128];
            for chunk_idx in 0..4 {
                let s = chunk_idx * 32;
                for (i, &b) in g2_bytes[s..s+32].iter().rev().enumerate() {
                    le[s + i] = b;
                }
            }
            let p = G2Affine::deserialize_with_mode(&le[..], Compress::No, Validate::Yes)
                .map_err(|_| Error::Protocol("host g2 parse"))?;
            g2s.push(p);
        }
        let r = Bn254::multi_pairing(g1s.into_iter(), g2s.into_iter());
        Ok(r.0 == ark_bn254::Fq12::ONE)
    }

    pub fn keccak256(input: &[u8]) -> [u8; 32] {
        // Host fallback: lightweight sha3 via arkworks std-only path is non-trivial;
        // for now use a simple hand-rolled sponge from `tiny-keccak` if added,
        // or panic in tests until we wire the host-side dep.
        let _ = input;
        unimplemented!("host keccak256: enable `solana-syscalls` feature or wire tiny-keccak")
    }

    pub fn g2_add(_a: &[u8; 128], _b: &[u8; 128]) -> Result<[u8; 128], Error> {
        Err(Error::Protocol("g2_add: arkworks fallback TODO (needed only for tests)"))
    }
    pub fn g2_mul(_p: &[u8; 128], _scalar_be: &[u8; 32]) -> Result<[u8; 128], Error> {
        Err(Error::Protocol("g2_mul: arkworks fallback TODO (needed only for tests)"))
    }
}

pub use onchain::{g1_add, g1_mul, g2_add, g2_mul, keccak256, pairing_check};
