#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! `alt_bn128_g1_msm` reference implementation
//!
//! This crate is the proposed reference implementation of the
//! `alt_bn128_g1_msm` SIMD: Σᵢ scalarsᵢ · pointsᵢ over BN254 G1, computed
//! by a Pippenger window-NAF multi-scalar multiplication. It is `no_std`-
//! compatible so the same code path can run on host (for off-chain
//! verifiers) and inside agave's syscall bridge.
//!
//! Two entrypoints:
//!
//! * [`alt_bn128_g1_msm_be`] — proposed syscall surface. Takes the wire
//!   byte layout `[n: u32 LE | scalar₀ | point₀ | scalar₁ | point₁ | …]`
//!   and returns 64-byte BE G1Affine.
//! * [`naive_msm_be`] — same surface, but implemented as `n` sequential
//!   scalar multiplications + additions. Serves as the *baseline* for
//!   benchmarks: it is what an on-chain verifier ends up doing today
//!   when it can only call `alt_bn128_g1_multiplication_be` per point.
//!
//! Both functions reject identity points + zero scalars consistently
//! (skipping their contribution rather than erroring), to match the
//! existing `alt_bn128_*` syscalls' semantics on the empty/identity
//! input edge cases.

extern crate alloc;

use alloc::vec::Vec;
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

// ---------------------------------------------------------------------------
// Public surface — the two implementations under comparison.
// ---------------------------------------------------------------------------

/// Wire-format error code matching the existing `alt_bn128_*` syscalls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsmError {
    /// Input length is not `4 + n * 96` for some n ≥ 0.
    InvalidInputLayout,
    /// A scalar is not in canonical Fr form (rejected to match groth16-solana).
    NonCanonicalScalar,
    /// A G1 point fails the curve equation check.
    NotOnCurve,
}

/// Wire format expected by the proposed `alt_bn128_g1_msm_be` syscall.
///
/// ```text
/// [0..4]            : n (u32 little-endian) — number of (scalar, point) pairs
/// [4..4+n*32]       : scalars      , each 32-byte BE Fr (one after another)
/// [4+n*32..4+n*96]  : G1 points    , each 64-byte BE G1Affine (x ‖ y)
/// ```
///
/// **Note on layout choice**: scalars and points are *grouped* (all scalars
/// then all points) rather than *interleaved*. The grouped layout matches
/// arkworks's `VariableBaseMSM::msm` API directly and avoids a reorder copy
/// inside the syscall implementation. EIP-2537 took the interleaved approach;
/// we deliberately diverge for ergonomics (and to follow the Solana SIMD-0284
/// little-endian-friendly conventions that downstream programs already use).
///
/// Returns the 64-byte BE G1Affine encoding of `Σᵢ scalarsᵢ · pointsᵢ`, or
/// the zero G1 element (64 zero bytes) if the result is the curve identity.
pub fn alt_bn128_g1_msm_be(input: &[u8]) -> Result<[u8; 64], MsmError> {
    let (scalars, points) = parse_msm_input(input)?;
    let result_proj: G1Projective = pippenger_msm(&scalars, &points);
    Ok(serialise_g1_be(result_proj.into_affine()))
}

/// Baseline: sequential `Σᵢ scalarᵢ · pointᵢ` via per-point scalar mul + add.
///
/// This is the verifier's *current* on-chain code path when it has only
/// `alt_bn128_g1_multiplication_be` + `alt_bn128_g1_addition_be` available.
/// We expose it here so the benchmark grid is apples-to-apples: same wire
/// format on the same byte input, two different inner algorithms.
pub fn naive_msm_be(input: &[u8]) -> Result<[u8; 64], MsmError> {
    let (scalars, points) = parse_msm_input(input)?;
    let mut acc = G1Projective::zero();
    for (s, p) in scalars.iter().zip(points.iter()) {
        if s.is_zero() || p.is_zero() {
            continue;
        }
        // Same arithmetic as the existing alt_bn128_g1_multiplication_be syscall:
        // produce s·P, then add into the running accumulator.
        acc += *p * *s;
    }
    Ok(serialise_g1_be(acc.into_affine()))
}

// ---------------------------------------------------------------------------
// Pippenger MSM — pure-Rust reference. Identical strategy to halo2curves's
// `multiexp_serial`, but using arkworks types so the surface matches the
// rest of the verifier crate.
// ---------------------------------------------------------------------------

/// Pippenger window-NAF MSM over BN254 G1.
///
/// **Algorithm** (Pippenger, with window size c chosen as a function of n):
/// 1. For each window of `c` bits across the 254-bit Fr, build `2^c − 1`
///    buckets indexed by the partial scalar value.
/// 2. Add each `pointᵢ` into bucket `(scalarᵢ shifted >> window)` for that
///    window's contribution.
/// 3. Sum the buckets weighted by their index → window contribution.
/// 4. Combine windows by `(c · k)`-bit doublings + additions.
///
/// Window `c` is picked from a heuristic that minimises the total operation
/// count `n + (2^c − 1) + ⌈254/c⌉ · 2^c` for each bench-grid n. This matches
/// the constant table inside arkworks `VariableBaseMSM::msm`.
fn pippenger_msm(scalars: &[Fr], points: &[G1Affine]) -> G1Projective {
    let n = scalars.len();
    debug_assert_eq!(points.len(), n);
    if n == 0 {
        return G1Projective::zero();
    }

    let c = ln_without_floats(n) + 2;

    // Repr is little-endian limbs; convert each scalar to a u64 array we can
    // window-slice. BigInt::to_bits_le() returns the bits LSB-first.
    let scalars_bits: Vec<Vec<bool>> = scalars
        .iter()
        .map(|s| s.into_bigint().to_bits_le())
        .collect();

    let num_bits = Fr::MODULUS_BIT_SIZE as usize;
    let num_windows = (num_bits + c - 1) / c;

    let mut window_sums = Vec::with_capacity(num_windows);
    for w in 0..num_windows {
        let bit_start = w * c;
        let bit_end = (bit_start + c).min(num_bits);

        let bucket_count = 1usize << c;
        let mut buckets = alloc::vec![G1Projective::zero(); bucket_count];

        for (s_bits, p) in scalars_bits.iter().zip(points.iter()) {
            // Read this window's c bits (treated as an unsigned integer).
            let mut idx: usize = 0;
            for b in (bit_start..bit_end).rev() {
                idx <<= 1;
                if *s_bits.get(b).unwrap_or(&false) {
                    idx |= 1;
                }
            }
            if idx > 0 && !p.is_zero() {
                buckets[idx] += p;
            }
        }

        // Bucket-sum weighted by index: out = Σ_{k=1..bucket_count-1} k · buckets[k]
        // Computed by a running prefix sum from k = N-1 down to k = 1.
        // Iterating to bucket[0] would double-count the lower buckets, so we
        // skip index 0 (which is always identity anyway since the input loop
        // never writes to it).
        let mut running = G1Projective::zero();
        let mut window_sum = G1Projective::zero();
        for bucket in buckets[1..].iter().rev() {
            running += bucket;
            window_sum += running;
        }
        window_sums.push(window_sum);
    }

    // Combine windows: lower windows contribute first, then we double `c`
    // times and add the next window. Walking from highest to lowest is
    // equivalent and matches the standard exposition.
    let mut total = G1Projective::zero();
    for &window_sum in window_sums.iter().rev() {
        for _ in 0..c {
            total.double_in_place();
        }
        total += window_sum;
    }
    total
}

#[inline]
fn ln_without_floats(n: usize) -> usize {
    // Same heuristic as arkworks: `log2(max(1, n))` rounded toward zero.
    if n <= 1 {
        return 1;
    }
    let mut v = n;
    let mut r = 0;
    while v > 1 {
        v >>= 1;
        r += 1;
    }
    r
}

// ---------------------------------------------------------------------------
// Wire-format parsing (shared by both entry points).
// ---------------------------------------------------------------------------

fn parse_msm_input(input: &[u8]) -> Result<(Vec<Fr>, Vec<G1Affine>), MsmError> {
    if input.len() < 4 {
        return Err(MsmError::InvalidInputLayout);
    }
    let n = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
    let body = &input[4..];
    let want = n.checked_mul(96).ok_or(MsmError::InvalidInputLayout)?;
    if body.len() != want {
        return Err(MsmError::InvalidInputLayout);
    }

    let mut scalars = Vec::with_capacity(n);
    let mut points = Vec::with_capacity(n);

    let scalars_end = n * 32;
    let scalars_raw = &body[..scalars_end];
    let points_raw  = &body[scalars_end..];

    for i in 0..n {
        let mut be = [0u8; 32];
        be.copy_from_slice(&scalars_raw[i * 32..(i + 1) * 32]);
        scalars.push(parse_scalar_be(&be)?);
    }
    for i in 0..n {
        let mut be = [0u8; 64];
        be.copy_from_slice(&points_raw[i * 64..(i + 1) * 64]);
        points.push(parse_g1_be(&be)?);
    }
    Ok((scalars, points))
}

fn parse_scalar_be(bytes: &[u8; 32]) -> Result<Fr, MsmError> {
    // Big-endian → little-endian, then the canonical-bound check inside
    // Fr::from_le_bytes_mod_order is reduce-mod-p (lossy). For strict
    // canonical-form rejection (matching groth16-solana / our verifier),
    // try CanonicalDeserialize::deserialize_compressed which fails on
    // non-canonical encodings.
    let mut le = *bytes;
    le.reverse();
    Fr::deserialize_compressed(&le[..]).map_err(|_| MsmError::NonCanonicalScalar)
}

fn parse_g1_be(bytes: &[u8; 64]) -> Result<G1Affine, MsmError> {
    if bytes == &[0u8; 64] {
        return Ok(G1Affine::zero()); // identity
    }
    let mut le = [0u8; 64];
    for i in 0..32 {
        le[i] = bytes[31 - i];
        le[32 + i] = bytes[63 - i];
    }
    G1Affine::deserialize_with_mode(&le[..], Compress::No, Validate::Yes)
        .map_err(|_| MsmError::NotOnCurve)
}

fn serialise_g1_be(p: G1Affine) -> [u8; 64] {
    if p.is_zero() {
        return [0u8; 64];
    }
    let (x, y) = p.xy().expect("non-identity G1 point must have coordinates");
    let mut out = [0u8; 64];
    let mut x_le = [0u8; 32];
    let mut y_le = [0u8; 32];
    x.serialize_with_mode(&mut x_le[..], Compress::No).expect("Fq serialisation");
    y.serialize_with_mode(&mut y_le[..], Compress::No).expect("Fq serialisation");
    for i in 0..32 {
        out[i] = x_le[31 - i];
        out[32 + i] = y_le[31 - i];
    }
    out
}

// ---------------------------------------------------------------------------
// Tests: round-trip naive == pippenger across n = {0, 1, 2, 4, 8, 16, 32}.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_std::UniformRand;

    fn build_input(scalars: &[Fr], points: &[G1Affine]) -> Vec<u8> {
        let n = scalars.len();
        assert_eq!(points.len(), n);
        let mut buf = Vec::with_capacity(4 + n * 96);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        for s in scalars {
            let mut le = [0u8; 32];
            s.serialize_with_mode(&mut le[..], Compress::No).unwrap();
            let mut be = le;
            be.reverse();
            buf.extend_from_slice(&be);
        }
        for p in points {
            buf.extend_from_slice(&serialise_g1_be(*p));
        }
        buf
    }

    fn rand_scalar_point_pair(rng: &mut impl ark_std::rand::Rng) -> (Fr, G1Affine) {
        let g = G1Projective::generator();
        let r = Fr::rand(rng);
        let p: G1Affine = (g * r).into_affine();
        let s = Fr::rand(rng);
        (s, p)
    }

    fn cross_check_n(n: usize, seed: u64) {
        use ark_std::rand::SeedableRng;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
        let (mut scalars, mut points) = (Vec::new(), Vec::new());
        for _ in 0..n {
            let (s, p) = rand_scalar_point_pair(&mut rng);
            scalars.push(s);
            points.push(p);
        }
        let input = build_input(&scalars, &points);

        let naive = naive_msm_be(&input).unwrap();
        let pipp  = alt_bn128_g1_msm_be(&input).unwrap();
        assert_eq!(naive, pipp,
            "naive vs pippenger disagree at n={n}\nnaive  = 0x{}\npipp   = 0x{}",
            hex::encode(naive), hex::encode(pipp));
    }

    #[test] fn n0_returns_identity() {
        let input = (0u32).to_le_bytes().to_vec();
        let r = alt_bn128_g1_msm_be(&input).unwrap();
        assert_eq!(r, [0u8; 64]);
    }

    #[test] fn n1_matches_scalar_mul()    { cross_check_n(1,  1); }
    #[test] fn n2()                        { cross_check_n(2,  2); }
    #[test] fn n4()                        { cross_check_n(4,  4); }
    #[test] fn n8()                        { cross_check_n(8,  8); }
    #[test] fn n16()                       { cross_check_n(16, 16); }
    #[test] fn n32()                       { cross_check_n(32, 32); }
    #[test] fn n64()                       { cross_check_n(64, 64); }

    #[test] fn rejects_invalid_layout() {
        let input = (1u32).to_le_bytes().to_vec(); // claims n=1 but no body
        assert_eq!(alt_bn128_g1_msm_be(&input).unwrap_err(), MsmError::InvalidInputLayout);
    }

    #[test] fn skips_zero_scalar() {
        use ark_std::rand::SeedableRng;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(99);
        let (_, p) = rand_scalar_point_pair(&mut rng);
        let scalars = vec![Fr::ZERO];
        let points  = vec![p];
        let input = build_input(&scalars, &points);
        let r = alt_bn128_g1_msm_be(&input).unwrap();
        assert_eq!(r, [0u8; 64], "0·P should be identity");
    }

    #[test] fn skips_identity_point() {
        let scalars = vec![Fr::from(7u64)];
        let points  = vec![G1Affine::zero()];
        let input = build_input(&scalars, &points);
        let r = alt_bn128_g1_msm_be(&input).unwrap();
        assert_eq!(r, [0u8; 64], "s·O should be identity");
    }
}
