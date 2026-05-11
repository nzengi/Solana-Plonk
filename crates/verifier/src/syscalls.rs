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
    #[cfg(not(feature = "mainnet-le"))]
    use solana_bn254::prelude::{
        alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
    };
    #[cfg(feature = "mainnet-le")]
    use solana_bn254::prelude::{
        alt_bn128_g1_addition_le, alt_bn128_g1_multiplication_le, alt_bn128_pairing_le,
    };

    // BE ↔ LE byte-swap helpers (mainnet-le path). Matches solana-bn254's
    // `convert_endianness::<CHUNK, ARRAY>` semantics: reverse bytes within
    // each fixed-size field-element chunk.
    //
    // G1 (64 B): two 32-byte Fq chunks (x, y) reversed individually.
    // G2 (128 B): two 64-byte chunks (x = c1‖c0, y = c1‖c0) reversed as 64-byte
    //              spans, which both flips byte order AND swaps c0 / c1 outer
    //              positions — matches solana-bn254's `<64, 128>` shape.
    // Fr (32 B): single 32-byte reversal.
    #[cfg(feature = "mainnet-le")]
    #[inline]
    fn swap_g1(bytes: &[u8; 64]) -> [u8; 64] {
        let mut out = [0u8; 64];
        for c in 0..2 {
            for i in 0..32 {
                out[c * 32 + i] = bytes[c * 32 + (31 - i)];
            }
        }
        out
    }

    #[cfg(feature = "mainnet-le")]
    #[inline]
    fn swap_fr(bytes: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 { out[i] = bytes[31 - i]; }
        out
    }

    /// Swap an in-line `(G1 ‖ G2)` 192-byte pairing-input chunk between BE
    /// and LE. Per solana-bn254's `convert_endianness::<64, 128>` for G2,
    /// the operation is byte-reverse-within-64-byte-spans — which both
    /// flips byte order AND swaps the (c1, c0) outer positions of each
    /// Fq2 coordinate. Apply to G1's two 32-byte halves and G2's two
    /// 64-byte halves of one chunk.
    #[cfg(feature = "mainnet-le")]
    fn swap_pair_chunk(chunk: &[u8], out: &mut [u8]) {
        debug_assert_eq!(chunk.len(), 192);
        debug_assert_eq!(out.len(), 192);
        // G1: 64 B = 2 × 32 B Fq
        for c in 0..2 {
            for i in 0..32 {
                out[c * 32 + i] = chunk[c * 32 + (31 - i)];
            }
        }
        // G2: 128 B = 2 × 64 B Fq2 spans
        for c in 0..2 {
            let base = 64 + c * 64;
            for i in 0..64 {
                out[base + i] = chunk[base + (63 - i)];
            }
        }
    }

    pub fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> Result<[u8; 64], Error> {
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(a);
        input[64..].copy_from_slice(b);

        #[cfg(feature = "mainnet-le")]
        let out = {
            let le_a = swap_g1(a);
            let le_b = swap_g1(b);
            let mut le_input = [0u8; 128];
            le_input[..64].copy_from_slice(&le_a);
            le_input[64..].copy_from_slice(&le_b);
            let le_out = alt_bn128_g1_addition_le(&le_input)
                .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g1_add_le", code: e.into() })?;
            let mut le_arr = [0u8; 64];
            le_arr.copy_from_slice(&le_out);
            swap_g1(&le_arr)
        };
        #[cfg(not(feature = "mainnet-le"))]
        let out = {
            let raw = alt_bn128_g1_addition_be(&input)
                .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g1_add", code: e.into() })?;
            debug_assert_eq!(raw.len(), 64);
            let mut result = [0u8; 64];
            result.copy_from_slice(&raw);
            result
        };
        Ok(out)
    }

    pub fn g1_mul(p: &[u8; 64], scalar_be: &[u8; 32]) -> Result<[u8; 64], Error> {
        #[cfg(feature = "mainnet-le")]
        let out = {
            let le_p = swap_g1(p);
            let le_s = swap_fr(scalar_be);
            let mut le_input = [0u8; 96];
            le_input[..64].copy_from_slice(&le_p);
            le_input[64..].copy_from_slice(&le_s);
            let le_out = alt_bn128_g1_multiplication_le(&le_input)
                .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g1_mul_le", code: e.into() })?;
            let mut le_arr = [0u8; 64];
            le_arr.copy_from_slice(&le_out);
            swap_g1(&le_arr)
        };
        #[cfg(not(feature = "mainnet-le"))]
        let out = {
            let mut input = [0u8; 96];
            input[..64].copy_from_slice(p);
            input[64..].copy_from_slice(scalar_be);
            let raw = alt_bn128_g1_multiplication_be(&input)
                .map_err(|e| Error::SyscallFailed { which: "alt_bn128_g1_mul", code: e.into() })?;
            debug_assert_eq!(raw.len(), 64);
            let mut result = [0u8; 64];
            result.copy_from_slice(&raw);
            result
        };
        Ok(out)
    }

    /// Returns `Ok(true)` iff `Π e(p₁, p₂) = 1`.
    /// `pairs` must be already laid out as `[(G1‖G2); N]` flat bytes (192·N total).
    pub fn pairing_check(pairs: &[u8]) -> Result<bool, Error> {
        if pairs.is_empty() || pairs.len() % 192 != 0 {
            return Err(Error::Protocol("pairing_check: input not a multiple of 192"));
        }
        #[cfg(feature = "mainnet-le")]
        let out = {
            let mut le_pairs = alloc::vec![0u8; pairs.len()];
            for (i, chunk) in pairs.chunks_exact(192).enumerate() {
                let base = i * 192;
                swap_pair_chunk(chunk, &mut le_pairs[base..base + 192]);
            }
            alt_bn128_pairing_le(&le_pairs)
                .map_err(|e| Error::SyscallFailed { which: "alt_bn128_pairing_le", code: e.into() })?
        };
        #[cfg(not(feature = "mainnet-le"))]
        let out = alt_bn128_pairing_be(pairs)
            .map_err(|e| Error::SyscallFailed { which: "alt_bn128_pairing", code: e.into() })?;

        debug_assert_eq!(out.len(), 32);
        // Output is encoded `BigInteger256(0)` (pairing rejected) or `(1)`
        // (accepted) — single bit of information either way. Be lenient about
        // byte position so the same check works for the BE syscall's
        // `[0;31, 1]` and the LE syscall's `[1, 0;31]`. Any non-zero byte → ok.
        Ok(out.iter().any(|&b| b != 0))
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

// ---------------------------------------------------------------------------
// A2 — differential BE↔LE sanity tests. These run on the host but exercise
// the `mainnet-le` cfg branch when that feature is enabled, against an
// expected value derived via direct arkworks BN254 arithmetic. They assert
// that the wrapper's bytes-in / bytes-out interface is endian-agnostic to
// the caller (still BE) regardless of which underlying syscall is called.
// ---------------------------------------------------------------------------
#[cfg(all(test, feature = "std", feature = "solana-syscalls"))]
mod a2_tests {
    use super::*;
    use ark_bn254::{Fr as ArkFr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_serialize::{CanonicalSerialize, Compress};

    /// Encode an arkworks affine G1 as 64-byte BE (32 B X || 32 B Y).
    fn g1_to_be_bytes(p: G1Affine) -> [u8; 64] {
        if p.is_zero() { return [0u8; 64]; }
        let mut le = [0u8; 64];
        p.x.serialize_with_mode(&mut le[..32], Compress::No).unwrap();
        p.y.serialize_with_mode(&mut le[32..], Compress::No).unwrap();
        // ark serializes LE → flip each 32-B chunk to BE.
        let mut be = [0u8; 64];
        for c in 0..2 {
            for i in 0..32 {
                be[c * 32 + i] = le[c * 32 + (31 - i)];
            }
        }
        be
    }

    fn fr_to_be_bytes(s: ArkFr) -> [u8; 32] {
        let mut le_buf = [0u8; 32];
        s.serialize_with_mode(&mut le_buf[..], Compress::No).unwrap();
        let mut be = [0u8; 32];
        for i in 0..32 { be[i] = le_buf[31 - i]; }
        be
    }

    /// G1 add via our wrapper must equal arkworks `(p + q)` regardless of
    /// whether the BE or LE syscall variant is the one wired in.
    #[test]
    fn g1_add_matches_arkworks() {
        let g = G1Affine::generator();
        let scalar_p = ArkFr::from(7u64);
        let scalar_q = ArkFr::from(11u64);
        let p_proj: G1Projective = G1Affine::generator() * scalar_p;
        let q_proj: G1Projective = G1Affine::generator() * scalar_q;
        let p_aff = p_proj.into_affine();
        let q_aff = q_proj.into_affine();
        let expected_aff: G1Affine = (p_proj + q_proj).into_affine();

        let p_be = g1_to_be_bytes(p_aff);
        let q_be = g1_to_be_bytes(q_aff);
        let expected_be = g1_to_be_bytes(expected_aff);

        let got = onchain::g1_add(&p_be, &q_be).unwrap();
        assert_eq!(got, expected_be, "g1_add bytes-out mismatch (feature: mainnet-le={})",
            cfg!(feature = "mainnet-le"));

        // Touch `g` so the binding actually runs.
        let _ = g;
    }

    /// G1 scalar-mul via our wrapper must equal arkworks `s · p`.
    #[test]
    fn g1_mul_matches_arkworks() {
        let scalar = ArkFr::from(0xDEAD_BEEFu64);
        let p_proj: G1Projective = G1Affine::generator() * ArkFr::from(13u64);
        let p_aff = p_proj.into_affine();
        let expected_aff: G1Affine = (p_proj * scalar).into_affine();

        let p_be = g1_to_be_bytes(p_aff);
        let s_be = fr_to_be_bytes(scalar);
        let expected_be = g1_to_be_bytes(expected_aff);

        let got = onchain::g1_mul(&p_be, &s_be).unwrap();
        assert_eq!(got, expected_be, "g1_mul bytes-out mismatch (feature: mainnet-le={})",
            cfg!(feature = "mainnet-le"));
    }
}

pub use onchain::{g1_add, g1_mul, g2_add, g2_mul, keccak256, pairing_check};
