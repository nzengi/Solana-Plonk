//! SHPLONK / BDFG21 batched multi-opening verifier (BN254-concrete).
//!
//! Reference: `halo2_proofs/src/poly/kzg/multiopen/shplonk/verifier.rs` and
//! `vendor/snark-verifier/.../pcs/kzg/multiopen/bdfg21.rs` (the algorithmic
//! shape is identical; we specialise to BN254 + arkworks Fr).
//!
//! Algorithm (BDFG21 / SHPLONK):
//! Given queries `(Cᵢ, zᵢ, vᵢ)` ("commitment Cᵢ opens to value vᵢ at point zᵢ")
//! and an opening proof `(h₁, h₂)`, the verifier:
//!
//!   1. Groups commitments by *rotation set* — the set of points each
//!      commitment is queried at. Defines `super_point_set = ∪ᵢ {zᵢ}`.
//!   2. Squeezes challenges `y` (combine polys within a rotation set),
//!      `v` (combine rotation sets), `u` (evaluation point).
//!   3. For each rotation set Rₖ with points Pₖ ⊂ super_point_set:
//!         z_diff_k  = Π_{p ∈ super_point_set ∖ Pₖ}  (u − p)
//!         z_0       = Π_{p ∈ P₀}  (u − p)         (only computed for k=0)
//!         normalise diff_k by z_0_diff_inverse so diff_0 = 1.
//!         For each Cⱼ ∈ Rₖ.commitments:
//!             rⱼ(X) = lagrange_interpolate(Pₖ, [evaluations of Cⱼ at Pₖ])
//!             r_evalⱼ = y^j · rⱼ(u)
//!             inner_msm += y^j · Cⱼ
//!         outer_msm  += v^k · z_diff_k · inner_msm
//!         r_outer    += v^k · z_diff_k · Σⱼ r_evalⱼ
//!   4. outer_msm += −r_outer·[1]₁  −  z_0·h₁  +  u·h₂
//!   5. Final pairing equation:  e(h₂, [τ]₂)  =  e(outer_msm, [1]₂)
//!      → returns pairing pairs `[(h₂, [τ]₂), (−outer_msm, [1]₂)]`.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, Zero};

use crate::{
    curve::{G1, G2},
    field::fr_to_bytes_be,
    kzg::KzgVk,
    Error,
};

/// One opening claim: commitment `c` opens to `eval` at point `point`.
///
/// `commit_id` is the unique identifier of the *commitment slot* this query
/// references — NOT the bytes of the commitment. Halo2's reference verifier
/// uses pointer-equality (`std::ptr::eq`) on `CommitmentReference`, which
/// keeps byte-equal-but-distinct commitments (e.g. multiple fixed columns
/// that happen to share the same low-degree polynomial) as SEPARATE entries
/// in `construct_intermediate_sets`. We mirror this by assigning an
/// explicit id when the query is built.
#[derive(Clone, Debug)]
pub struct VerifierQuery {
    pub commit_id: usize,
    pub commitment: G1,
    pub point:      Fr,
    pub eval:       Fr,
}

/// Output of SHPLONK opening verification: `(G1, G2)` pairs whose pairing
/// product must equal one. Caller feeds these to one `alt_bn128_pairing` call.
#[derive(Clone, Debug)]
pub struct PairingInput(pub Vec<(G1, G2)>);

// ---------------------------------------------------------------------------
// Polynomial helpers (Fr-only, no G1 ops — runs in pure BPF arithmetic).
// ---------------------------------------------------------------------------

/// Returns `[1, x, x², …, x^(n-1)]`.
pub fn powers(x: Fr, n: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Fr::ONE;
    for _ in 0..n {
        out.push(acc);
        acc *= x;
    }
    out
}

/// Evaluate `Π (x − pᵢ)` for the given points. Empty product = 1.
pub fn evaluate_vanishing_polynomial(points: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ONE;
    for p in points {
        acc *= x - *p;
    }
    acc
}

/// Evaluate a polynomial in coefficient form (low-degree first) via Horner's.
pub fn eval_polynomial(coeffs: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Lagrange-interpolate the polynomial passing through `(points[i], values[i])`.
/// Returns coefficients (low-degree first) so `eval_polynomial(out, p[i]) ≡ v[i]`.
///
/// O(n²) — acceptable for n ≤ 8 (typical max rotation set size in halo2).
/// `#[inline(never)]`: keeps `verify_opening`'s frame inside the BPF budget.
#[inline(never)]
pub fn lagrange_interpolate(points: &[Fr], values: &[Fr]) -> Result<Vec<Fr>, Error> {
    if points.len() != values.len() {
        return Err(Error::Protocol("lagrange_interpolate: length mismatch"));
    }
    let n = points.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    // Result: Σⱼ vⱼ · Π_{i≠j} (X − xᵢ) / Π_{i≠j} (xⱼ − xᵢ)
    let mut result = alloc::vec![Fr::ZERO; n];

    for j in 0..n {
        // Numerator: polynomial Π_{i≠j} (X − xᵢ). Build coefficients.
        let mut num = alloc::vec![Fr::ZERO; n]; // length n, last coeff is 1
        num[0] = Fr::ONE;
        let mut deg = 1usize;
        for i in 0..n {
            if i == j { continue; }
            // multiply current `num[..deg]` by (X − points[i])
            let xi = points[i];
            // shift up + sub xi*current
            let mut new_num = alloc::vec![Fr::ZERO; deg + 1];
            for k in 0..deg {
                new_num[k]     -= num[k] * xi;
                new_num[k + 1] += num[k];
            }
            for k in 0..deg + 1 {
                num[k] = new_num[k];
            }
            deg += 1;
        }

        // Denominator: Π_{i≠j} (xⱼ − xᵢ).
        let mut denom = Fr::ONE;
        for i in 0..n {
            if i == j { continue; }
            let d = points[j] - points[i];
            if d.is_zero() {
                return Err(Error::Protocol("lagrange_interpolate: duplicate points"));
            }
            denom *= d;
        }
        let denom_inv = denom.inverse()
            .ok_or(Error::Protocol("lagrange_interpolate: zero denominator"))?;

        let scale = values[j] * denom_inv;
        for k in 0..n {
            result[k] += num[k] * scale;
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Lagrange basis helpers — split from `lagrange_interpolate` so the
// numerator polys + un-inverted denoms can be computed once per rotation
// set and the inverses batched across all sets with Montgomery's trick.
// ---------------------------------------------------------------------------

/// Compute the per-`j` numerator polynomial Π_{i≠j} (X − xᵢ) and the
/// un-inverted denominator scalar Π_{i≠j} (xⱼ − xᵢ) for each `j ∈ 0..n`.
/// The numerators are reusable across any interpolation on this `points`
/// set; the denoms are passed through `batch_inverse_fr` collectively
/// across all rotation sets before being consumed by `interpolate_with_basis`.
#[inline(never)]
pub(crate) fn lagrange_basis_compute(points: &[Fr])
    -> Result<(Vec<Vec<Fr>>, Vec<Fr>), Error>
{
    let n = points.len();
    let mut nums:   Vec<Vec<Fr>> = Vec::with_capacity(n);
    let mut denoms: Vec<Fr>      = Vec::with_capacity(n);

    for j in 0..n {
        // Numerator polynomial Π_{i≠j} (X − xᵢ). Same build as
        // `lagrange_interpolate`'s inner loop.
        let mut num = alloc::vec![Fr::ZERO; n];
        num[0] = Fr::ONE;
        let mut deg = 1usize;
        for i in 0..n {
            if i == j { continue; }
            let xi = points[i];
            let mut new_num = alloc::vec![Fr::ZERO; deg + 1];
            for k in 0..deg {
                new_num[k]     -= num[k] * xi;
                new_num[k + 1] += num[k];
            }
            for k in 0..deg + 1 { num[k] = new_num[k]; }
            deg += 1;
        }

        // Denominator (un-inverted; batched later).
        let mut denom = Fr::ONE;
        for i in 0..n {
            if i == j { continue; }
            let d = points[j] - points[i];
            if d.is_zero() {
                return Err(Error::Protocol("lagrange: duplicate points"));
            }
            denom *= d;
        }

        nums.push(num);
        denoms.push(denom);
    }
    Ok((nums, denoms))
}

/// Evaluate the Lagrange interpolant at the eval set `values`, given a
/// pre-computed basis (`nums`, already-inverted `denom_invs`). Pure dot-
/// product — no inverses, no syscalls. ~n² Fr muls.
#[inline(never)]
pub(crate) fn interpolate_with_basis(
    nums: &[Vec<Fr>],
    denom_invs: &[Fr],
    values: &[Fr],
) -> Vec<Fr> {
    let n = values.len();
    let mut result = alloc::vec![Fr::ZERO; n];
    for j in 0..n {
        let scale = values[j] * denom_invs[j];
        for k in 0..n {
            result[k] += nums[j][k] * scale;
        }
    }
    result
}

/// Montgomery batch inverse: replace each `xs[i]` with `1 / xs[i]` using
/// a single Fermat inverse + 3·(n−1) Fr muls. Rejects if any element is
/// zero (the full product would be zero, no inverse exists).
///
/// Saving on BPF: each Fermat inverse costs ~16k CU; each Fr mul ~3k CU.
/// For `n` inverses, this is `1·16k + 3·(n−1)·3k = 16k + 9k·(n−1)` vs
/// `n·16k`, breaking even at `n=3` and saving ~7k CU per element after.
/// On Fibonacci-shape phase 1 (~60 inverses) this saves ~400k CU.
#[inline(never)]
pub(crate) fn batch_inverse_fr(xs: &mut [Fr]) -> Result<(), Error> {
    let n = xs.len();
    if n == 0 { return Ok(()); }
    if n == 1 {
        let inv = xs[0].inverse()
            .ok_or(Error::Protocol("batch_inverse: zero element"))?;
        xs[0] = inv;
        return Ok(());
    }

    // Save originals so the backward pass can multiply by them.
    let originals: Vec<Fr> = xs.iter().copied().collect();

    // Forward pass: prefix[i] = x[0] * … * x[i].
    let mut prefix: Vec<Fr> = Vec::with_capacity(n);
    prefix.push(originals[0]);
    for i in 1..n {
        prefix.push(prefix[i - 1] * originals[i]);
    }

    if prefix[n - 1].is_zero() {
        return Err(Error::Protocol("batch_inverse: zero in batch"));
    }

    // Single Fermat inverse of the full product.
    let mut acc = prefix[n - 1].inverse()
        .ok_or(Error::Protocol("batch_inverse: inverse fail"))?;
    // Loop invariant after iteration i (going high → low):
    //   acc = 1 / (x[0] * … * x[i-1])
    //   xs[i] = 1 / x[i]
    for i in (1..n).rev() {
        xs[i] = prefix[i - 1] * acc;
        acc *= originals[i];
    }
    xs[0] = acc;

    Ok(())
}

// ---------------------------------------------------------------------------
// Rotation set construction.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct RotationSet {
    /// Distinct points this set's commitments are queried at, in deterministic
    /// order. Order matches halo2's `BTreeSet` insertion ordering by Fr value
    /// — but on-chain we use an arbitrary stable order (insertion order
    /// from prover); soundness only depends on bilinearity, not ordering.
    pub points: Vec<Fr>,
    /// `(commitment, evaluations_per_point)` — one Fr per element of `points`.
    pub commitments_with_evals: Vec<(G1, Vec<Fr>)>,
}

#[derive(Clone, Debug)]
pub(crate) struct IntermediateSets {
    pub rotation_sets:   Vec<RotationSet>,
    pub super_point_set: Vec<Fr>,
}

/// Group queries into rotation sets. Two queries share a rotation set
/// iff their `commit_id`s are equal (same logical commitment slot).
///
/// **Crucial**: grouping is by `commit_id`, NOT by commitment bytes. This
/// matches halo2's `CommitmentReference::PartialEq` which uses
/// `std::ptr::eq`. Byte-equal commitments at different slots (e.g. when
/// q_a, q_b, q_c, q_ab all happen to commit to the same L_0 polynomial)
/// remain SEPARATE — each contributes its own y^j coefficient inside
/// the SHPLONK inner_msm, mirroring halo2's algorithm exactly.
#[inline(never)]
pub(crate) fn construct_intermediate_sets(queries: &[VerifierQuery]) -> IntermediateSets {
    // Stable ordering: super_point_set is in the order points first appeared.
    let mut super_point_set: Vec<Fr> = Vec::new();
    for q in queries {
        if !super_point_set.contains(&q.point) {
            super_point_set.push(q.point);
        }
    }

    // For each commitment slot (by `commit_id`), collect the set of points it
    // is queried at + a (point → eval) map.
    #[derive(Clone)]
    struct PerCommitment {
        commit_id: usize,
        commitment: G1,
        points: Vec<Fr>,
        evals_by_point: Vec<(Fr, Fr)>,
    }
    let mut per_commitment: Vec<PerCommitment> = Vec::new();
    for q in queries {
        if let Some(pc) = per_commitment.iter_mut().find(|pc| pc.commit_id == q.commit_id) {
            if !pc.points.contains(&q.point) {
                pc.points.push(q.point);
                pc.evals_by_point.push((q.point, q.eval));
            }
        } else {
            per_commitment.push(PerCommitment {
                commit_id: q.commit_id,
                commitment: q.commitment,
                points: alloc::vec![q.point],
                evals_by_point: alloc::vec![(q.point, q.eval)],
            });
        }
    }

    // Group commitments by point-set equality (Vec equality on insertion-ordered points).
    let mut rotation_sets: Vec<RotationSet> = Vec::new();
    for pc in per_commitment {
        let evals_in_point_order: Vec<Fr> = pc.points
            .iter()
            .map(|p| pc.evals_by_point.iter().find(|(pp, _)| pp == p).map(|(_, e)| *e).unwrap())
            .collect();

        if let Some(existing) = rotation_sets.iter_mut()
            .find(|rs| rs.points == pc.points)
        {
            existing.commitments_with_evals.push((pc.commitment, evals_in_point_order));
        } else {
            rotation_sets.push(RotationSet {
                points: pc.points,
                commitments_with_evals: alloc::vec![(pc.commitment, evals_in_point_order)],
            });
        }
    }

    IntermediateSets { rotation_sets, super_point_set }
}

// ---------------------------------------------------------------------------
// Main SHPLONK verifier reduction.
// ---------------------------------------------------------------------------

/// Verify a SHPLONK opening proof `(h1, h2)` for the given queries.
/// `#[inline(never)]`: keeps this out of the caller's SBF stack frame.
///
/// Inputs:
///   * `queries`:    list of `(commitment, point, eval)` triples
///   * `h1`, `h2`:   the SHPLONK opening proof's two G1 commitments
///   * `y, v, u`:    the three SHPLONK challenges
///   * `kzg_vk`:     trimmed verifying SRS — `g1_one`, `g2_one`, `g2_tau`
///
/// Returns the `PairingInput` that, fed to `pairing_check`, reduces to
/// the soundness bit of the SHPLONK opening.
#[inline(never)]
pub fn verify_opening(
    queries: &[VerifierQuery],
    h1: G1,
    h2: G1,
    y: Fr,
    v: Fr,
    u: Fr,
    kzg_vk: &KzgVk,
) -> Result<PairingInput, Error> {
    // 1-tx / 2-tx callers compose the same two phases the 3-tx split uses
    // separately. Both phases share the batched-inverse fast path, so the
    // 1-tx flow inherits the same ~600k CU saving on Fibonacci-shape
    // circuits as the 3-tx split's stage 2a.
    let msm_terms = build_shplonk_msm_terms(
        queries, h1, h2, y, v, u, kzg_vk.g1_one,
    )?;
    finalize_shplonk_pairs(&msm_terms, h2, kzg_vk)
}

// ---------------------------------------------------------------------------
// Rotation-set helpers — split out so each gets its own BPF stack frame.
// ---------------------------------------------------------------------------

/// Compute `z_diff_i` for rotation set `i`. For `i == 0`, also seeds `z_0`
/// and `z_0_diff_inverse`; for `i > 0`, normalises by `z_0_diff_inverse`.
#[inline(never)]
fn compute_z_diff_i(
    i: usize,
    super_point_set: &[Fr],
    points: &[Fr],
    u: Fr,
    z_0: &mut Fr,
    z_0_diff_inverse: &mut Fr,
) -> Result<Fr, Error> {
    let diffs: Vec<Fr> = super_point_set.iter()
        .filter(|p| !points.contains(p))
        .copied()
        .collect();
    let mut z_diff_i = evaluate_vanishing_polynomial(&diffs, u);
    if i == 0 {
        *z_0 = evaluate_vanishing_polynomial(points, u);
        *z_0_diff_inverse = z_diff_i.inverse()
            .ok_or(Error::Protocol("shplonk: z_0_diff zero"))?;
        z_diff_i = Fr::ONE;
    } else {
        z_diff_i *= *z_0_diff_inverse;
    }
    Ok(z_diff_i)
}

// `process_rotation_set_inner` (per-commit Fermat-inverse lagrange) is
// superseded by `process_rotation_set_with_basis` below — kept out of the
// build to avoid CU-budget regressions if a caller mis-uses it.

// ---------------------------------------------------------------------------
// G1 MSM + negation helpers.
// ---------------------------------------------------------------------------

/// Compute Σ scalar_i · point_i. Skips zero scalars and identity points.
/// Sequential — no Pippenger in v1; that's the SIMD-0XXX target.
#[inline(never)]
fn msm_g1(terms: &[(Fr, G1)]) -> Result<G1, Error> {
    let mut acc: Option<G1> = None;
    for (scalar, point) in terms {
        if scalar.is_zero() || point == &G1::IDENTITY {
            continue;
        }
        let s = fr_to_bytes_be(scalar);
        let term = point.scalar_mul(&s)?;
        acc = Some(match acc {
            None => term,
            Some(a) => a.add(&term)?,
        });
    }
    Ok(acc.unwrap_or(G1::IDENTITY))
}

/// Negate a G1 point: (x, y) → (x, q − y). On BN254, this is cheap (no syscall).
/// `q` is the BN254 base-field modulus.
#[inline(never)]
fn neg_g1(p: &G1) -> Result<G1, Error> {
    if p == &G1::IDENTITY {
        return Ok(G1::IDENTITY);
    }
    const Q_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
        0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&p.0[..32]); // x unchanged
    // y' = q − y, BE big-num subtraction.
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let y = p.0[32 + i] as i32;
        let q = Q_BE[i] as i32;
        let mut d = q - y - borrow;
        if d < 0 { d += 256; borrow = 1; } else { borrow = 0; }
        out[32 + i] = d as u8;
    }
    Ok(G1(out))
}

// ---------------------------------------------------------------------------
// 3-tx split helpers: phase1 builds the SHPLONK outer-MSM term Vec (Fr math
// only, no G1 syscalls); phase2 reduces the terms via a single G1 MSM and
// returns the PairingInput. The 1-tx / 2-tx `verify_opening` above is the
// composition of these two phases — kept untouched for backward compat.
// ---------------------------------------------------------------------------

/// Phase 1 of SHPLONK opening: build the complete `Vec<(Fr, G1)>` of MSM
/// terms (queries are processed per rotation set, all finalization terms
/// `-r_outer·[1]₁ + -z_0·h1 + u·h2` already appended). Returns this Vec
/// alongside the `h2 = opening_proof_w_prime` carried through to phase 2
/// (caller passes it in already, so the return is just the terms).
///
/// CU cost on BPF scales with the number of rotation sets and queries —
/// purely Fr math + lagrange_interpolate, no alt_bn128 syscalls. For a
/// Fibonacci-shape circuit this runs in ~600–800k CU.
#[inline(never)]
pub fn build_shplonk_msm_terms(
    queries: &[VerifierQuery],
    h1: G1,            // opening_proof_w
    h2: G1,            // opening_proof_w_prime
    y: Fr,
    v: Fr,
    u: Fr,
    kzg_g1_one: G1,
) -> Result<Vec<(Fr, G1)>, Error> {
    if queries.is_empty() {
        return Err(Error::Protocol("build_shplonk_msm_terms: empty queries"));
    }

    let sets = construct_intermediate_sets(queries);
    let rotation_sets = &sets.rotation_sets;
    let super_point_set = &sets.super_point_set;

    let max_inner = rotation_sets.iter()
        .map(|rs| rs.commitments_with_evals.len())
        .max().unwrap_or(0);
    let y_powers = powers(y, max_inner);
    let v_powers = powers(v, rotation_sets.len());

    // ── Pass 1: build the Lagrange basis (numerator polys + un-inverted
    // denoms) for every rotation set. All denoms collect into one flat
    // vector so we can do ONE Fermat inverse for all of them via
    // Montgomery's trick instead of one inverse per `j` per set. On
    // Fibonacci-shape phase 1 this turns ~60 Fermats into 1 + ~180 muls.
    let mut per_set_nums:  Vec<Vec<Vec<Fr>>> = Vec::with_capacity(rotation_sets.len());
    let mut denoms_flat:   Vec<Fr>           = Vec::new();
    let mut denom_offsets: Vec<usize>        = Vec::with_capacity(rotation_sets.len() + 1);
    denom_offsets.push(0);

    for rotation_set in rotation_sets {
        let (nums, denoms) = lagrange_basis_compute(&rotation_set.points)?;
        per_set_nums.push(nums);
        denoms_flat.extend(denoms);
        denom_offsets.push(denoms_flat.len());
    }

    batch_inverse_fr(&mut denoms_flat)?;

    // ── Pass 2: per rotation set, compute z_diff_i, build MSM terms with
    // the pre-cached basis + freshly batch-inverted denoms.
    let mut z_0 = Fr::ZERO;
    let mut z_0_diff_inverse = Fr::ZERO;
    let mut outer_msm_terms: Vec<(Fr, G1)> = Vec::new();
    let mut r_outer_acc = Fr::ZERO;

    for (i, rotation_set) in rotation_sets.iter().enumerate() {
        let z_diff_i = compute_z_diff_i(
            i, super_point_set, &rotation_set.points, u,
            &mut z_0, &mut z_0_diff_inverse,
        )?;

        let basis_nums = &per_set_nums[i];
        let denom_invs = &denoms_flat[denom_offsets[i]..denom_offsets[i + 1]];

        let r_inner_acc = process_rotation_set_with_basis(
            rotation_set, basis_nums, denom_invs,
            &y_powers, v_powers[i], z_diff_i, u,
            &mut outer_msm_terms,
        );
        r_outer_acc += v_powers[i] * z_diff_i * r_inner_acc;
    }

    // outer_msm  +=  −r_outer·[1]₁  −  z_0·h1  +  u·h2
    outer_msm_terms.push((-r_outer_acc, kzg_g1_one));
    outer_msm_terms.push((-z_0, h1));
    outer_msm_terms.push((u, h2));

    Ok(outer_msm_terms)
}

/// Per-rotation-set commitment processing using the pre-cached Lagrange
/// basis. Identical structure to `process_rotation_set_inner` but skips
/// re-computing the per-`j` numerators / denominators (already done in
/// pass 1 of `build_shplonk_msm_terms`).
#[inline(never)]
fn process_rotation_set_with_basis(
    rotation_set: &RotationSet,
    basis_nums: &[Vec<Fr>],
    denom_invs: &[Fr],
    y_powers: &[Fr],
    v_pow_i: Fr,
    z_diff_i: Fr,
    u: Fr,
    outer_msm_terms: &mut Vec<(Fr, G1)>,
) -> Fr {
    let mut r_inner_acc = Fr::ZERO;
    for (j, (commitment, evals)) in rotation_set.commitments_with_evals.iter().enumerate() {
        let r_x = interpolate_with_basis(basis_nums, denom_invs, evals);
        let r_eval = y_powers[j] * eval_polynomial(&r_x, u);
        let coeff = v_pow_i * z_diff_i * y_powers[j];
        outer_msm_terms.push((coeff, *commitment));
        r_inner_acc += r_eval;
    }
    r_inner_acc
}

/// Phase 2 of SHPLONK opening: take the MSM terms produced by phase 1 plus
/// the second-pairing point `h2 = opening_proof_w_prime`, run the single
/// G1 MSM and build the two `(G1, G2)` pairs whose pairing product must
/// equal 1.
///
/// CU cost dominated by `msm_g1` (one syscall per term, ~30k CU each).
#[inline(never)]
pub fn finalize_shplonk_pairs(
    msm_terms: &[(Fr, G1)],
    h2: G1,
    kzg_vk: &crate::kzg::KzgVk,
) -> Result<PairingInput, Error> {
    let outer_msm = msm_g1(msm_terms)?;
    let neg_outer = neg_g1(&outer_msm)?;
    Ok(PairingInput(alloc::vec![
        (h2, kzg_vk.g2_tau),
        (neg_outer, kzg_vk.g2_one),
    ]))
}

// ---------------------------------------------------------------------------
// Debug-trace helpers (feature-gated; unused in production builds).
// ---------------------------------------------------------------------------

#[cfg(feature = "debug-trace")]
fn _shp_fr_hex(f: &Fr) -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write;
    let be = crate::field::fr_to_bytes_be(f);
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in &be { write!(s, "{b:02x}").unwrap(); }
    s
}

#[cfg(feature = "debug-trace")]
fn _shp_hex(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { write!(s, "{b:02x}").unwrap(); }
    s
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn powers_basic() {
        let x = Fr::from(3u64);
        let p = powers(x, 4);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], Fr::ONE);
        assert_eq!(p[1], Fr::from(3u64));
        assert_eq!(p[2], Fr::from(9u64));
        assert_eq!(p[3], Fr::from(27u64));
    }

    #[test]
    fn powers_zero_length() {
        assert!(powers(Fr::from(7u64), 0).is_empty());
    }

    #[test]
    fn vanishing_poly_empty_is_one() {
        assert_eq!(evaluate_vanishing_polynomial(&[], Fr::from(42u64)), Fr::ONE);
    }

    #[test]
    fn vanishing_poly_single_point() {
        // Π (x − pᵢ) = (x − p) for a single point.
        let p = Fr::from(5u64);
        let x = Fr::from(7u64);
        assert_eq!(evaluate_vanishing_polynomial(&[p], x), Fr::from(2u64));
    }

    #[test]
    fn vanishing_poly_zero_at_root() {
        let p = Fr::from(5u64);
        assert_eq!(evaluate_vanishing_polynomial(&[p], p), Fr::ZERO);
    }

    #[test]
    fn eval_polynomial_constant() {
        assert_eq!(eval_polynomial(&[Fr::from(7u64)], Fr::from(99u64)), Fr::from(7u64));
    }

    #[test]
    fn eval_polynomial_linear() {
        // p(x) = 2 + 3x  ⇒  p(5) = 17
        let coeffs = alloc::vec![Fr::from(2u64), Fr::from(3u64)];
        assert_eq!(eval_polynomial(&coeffs, Fr::from(5u64)), Fr::from(17u64));
    }

    #[test]
    fn eval_polynomial_quadratic() {
        // p(x) = 1 + 2x + 3x²  ⇒  p(4) = 1 + 8 + 48 = 57
        let coeffs = alloc::vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        assert_eq!(eval_polynomial(&coeffs, Fr::from(4u64)), Fr::from(57u64));
    }

    #[test]
    fn lagrange_constant() {
        // 1 point → constant polynomial = the value at that point.
        let pts = alloc::vec![Fr::from(7u64)];
        let vals = alloc::vec![Fr::from(99u64)];
        let coeffs = lagrange_interpolate(&pts, &vals).unwrap();
        assert_eq!(coeffs, alloc::vec![Fr::from(99u64)]);
    }

    #[test]
    fn lagrange_linear_interpolation() {
        // Points (1, 10), (2, 20). Interpolated polynomial is 10X (x=1→10, x=2→20).
        // Wait: at x=1, 10·1 = 10 ✓; at x=2, 10·2 = 20 ✓. So poly = 10X (= 0 + 10·X).
        let pts = alloc::vec![Fr::from(1u64), Fr::from(2u64)];
        let vals = alloc::vec![Fr::from(10u64), Fr::from(20u64)];
        let coeffs = lagrange_interpolate(&pts, &vals).unwrap();
        // Confirm via evaluation at both points:
        assert_eq!(eval_polynomial(&coeffs, Fr::from(1u64)), Fr::from(10u64));
        assert_eq!(eval_polynomial(&coeffs, Fr::from(2u64)), Fr::from(20u64));
    }

    #[test]
    fn lagrange_recovers_polynomial_at_third_point() {
        // p(x) = 2 + 3x + 5x²  ⇒  p(1)=10, p(2)=28, p(3)=56, p(4)=94
        let pts  = alloc::vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let vals = alloc::vec![Fr::from(10u64), Fr::from(28u64), Fr::from(56u64)];
        let coeffs = lagrange_interpolate(&pts, &vals).unwrap();

        for (p, v) in pts.iter().zip(vals.iter()) {
            assert_eq!(eval_polynomial(&coeffs, *p), *v);
        }
        assert_eq!(eval_polynomial(&coeffs, Fr::from(4u64)), Fr::from(94u64));
    }

    #[test]
    fn lagrange_rejects_duplicate_points() {
        let pts = alloc::vec![Fr::from(1u64), Fr::from(1u64)];
        let vals = alloc::vec![Fr::from(10u64), Fr::from(20u64)];
        assert!(lagrange_interpolate(&pts, &vals).is_err());
    }

    #[test]
    fn lagrange_rejects_length_mismatch() {
        let pts = alloc::vec![Fr::from(1u64)];
        let vals: Vec<Fr> = alloc::vec![];
        assert!(lagrange_interpolate(&pts, &vals).is_err());
    }

    // ---- intermediate set construction ------------------------------------

    fn synth_g1(tag: u8) -> G1 {
        let mut b = [0u8; 64];
        b[0] = tag; // distinct dummy bytes; no on-curve check in this layer
        G1(b)
    }

    #[test]
    fn intermediate_single_query_one_set() {
        let q = VerifierQuery {
            commit_id: 0,
            commitment: synth_g1(1),
            point: Fr::from(7u64),
            eval: Fr::from(42u64),
        };
        let sets = construct_intermediate_sets(&[q]);
        assert_eq!(sets.super_point_set, alloc::vec![Fr::from(7u64)]);
        assert_eq!(sets.rotation_sets.len(), 1);
        assert_eq!(sets.rotation_sets[0].points, alloc::vec![Fr::from(7u64)]);
        assert_eq!(sets.rotation_sets[0].commitments_with_evals.len(), 1);
    }

    #[test]
    fn intermediate_two_commitments_same_point_grouped_in_one_set() {
        let qs = alloc::vec![
            VerifierQuery { commit_id: 0, commitment: synth_g1(1), point: Fr::from(7u64), eval: Fr::from(10u64) },
            VerifierQuery { commit_id: 1, commitment: synth_g1(2), point: Fr::from(7u64), eval: Fr::from(20u64) },
        ];
        let sets = construct_intermediate_sets(&qs);
        assert_eq!(sets.rotation_sets.len(), 1);
        assert_eq!(sets.rotation_sets[0].commitments_with_evals.len(), 2);
        // Both commitments share rotation_set.points = [7].
        assert_eq!(sets.rotation_sets[0].points, alloc::vec![Fr::from(7u64)]);
    }

    #[test]
    fn intermediate_distinct_point_sets_make_distinct_rotation_sets() {
        let qs = alloc::vec![
            // C1 (id=0) queried at {7}
            VerifierQuery { commit_id: 0, commitment: synth_g1(1), point: Fr::from(7u64), eval: Fr::from(10u64) },
            // C2 (id=1) queried at {7, 8} — different rotation set
            VerifierQuery { commit_id: 1, commitment: synth_g1(2), point: Fr::from(7u64), eval: Fr::from(20u64) },
            VerifierQuery { commit_id: 1, commitment: synth_g1(2), point: Fr::from(8u64), eval: Fr::from(30u64) },
        ];
        let sets = construct_intermediate_sets(&qs);
        assert_eq!(sets.rotation_sets.len(), 2);
        // super_point_set in insertion order: [7, 8]
        assert_eq!(sets.super_point_set, alloc::vec![Fr::from(7u64), Fr::from(8u64)]);
    }

    /// Halo2 pointer-equality semantics: byte-equal commits at distinct
    /// commit_ids stay SEPARATE — each gets its own y^j coefficient slot.
    #[test]
    fn intermediate_byte_equal_distinct_ids_stay_separate() {
        let same_bytes = synth_g1(1);
        let qs = alloc::vec![
            VerifierQuery { commit_id: 0, commitment: same_bytes, point: Fr::from(7u64), eval: Fr::from(10u64) },
            VerifierQuery { commit_id: 1, commitment: same_bytes, point: Fr::from(7u64), eval: Fr::from(20u64) },
            VerifierQuery { commit_id: 2, commitment: same_bytes, point: Fr::from(7u64), eval: Fr::from(30u64) },
        ];
        let sets = construct_intermediate_sets(&qs);
        // All 3 share point set {7} → one rotation set, but THREE entries inside it.
        assert_eq!(sets.rotation_sets.len(), 1);
        assert_eq!(sets.rotation_sets[0].commitments_with_evals.len(), 3);
    }

    // ---- neg_g1 -----------------------------------------------------------

    #[test]
    fn neg_g1_identity_is_identity() {
        let r = neg_g1(&G1::IDENTITY).unwrap();
        assert_eq!(r, G1::IDENTITY);
    }

    #[test]
    fn neg_g1_generator() {
        // BN254 generator (1, 2). Negation flips y to q − 2.
        let mut g = [0u8; 64]; g[31] = 1; g[63] = 2;
        let r = neg_g1(&G1(g)).unwrap();
        // Expected y = q − 2:
        //   q   = 0x3064...fd47
        //   q-2 = 0x3064...fd45
        let mut expected = [0u8; 64];
        expected[31] = 1;
        expected[32..].copy_from_slice(&[
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
            0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x45,
        ]);
        assert_eq!(r.0, expected);
    }

    // ----- batch_inverse_fr tests -----

    #[test]
    fn batch_inverse_empty_is_noop() {
        let mut xs: Vec<Fr> = Vec::new();
        batch_inverse_fr(&mut xs).unwrap();
        assert!(xs.is_empty());
    }

    #[test]
    fn batch_inverse_single_matches_fermat() {
        let mut xs = alloc::vec![Fr::from(7u64)];
        batch_inverse_fr(&mut xs).unwrap();
        let expected = Fr::from(7u64).inverse().unwrap();
        assert_eq!(xs[0], expected);
    }

    /// Batched inverse must produce the same result as a sequence of
    /// per-element Fermat inverses (Montgomery's trick is exact, not
    /// approximate).
    #[test]
    fn batch_inverse_matches_per_element_inverses() {
        let xs_orig: Vec<Fr> = (2u64..=12u64).map(Fr::from).collect();
        let mut xs = xs_orig.clone();
        batch_inverse_fr(&mut xs).unwrap();
        for (i, x) in xs_orig.iter().enumerate() {
            assert_eq!(xs[i], x.inverse().unwrap(), "mismatch at index {i}");
        }
    }

    /// A zero element in the batch must reject (the full product is zero,
    /// hence has no inverse). Soundness-critical: silently accepting would
    /// produce wrong basis denoms downstream.
    #[test]
    fn batch_inverse_zero_element_rejects() {
        let mut xs = alloc::vec![Fr::from(3u64), Fr::ZERO, Fr::from(5u64)];
        let r = batch_inverse_fr(&mut xs);
        assert!(matches!(r, Err(Error::Protocol(_))));
    }

    // ----- lagrange_basis_compute / interpolate_with_basis tests -----

    /// Composing `lagrange_basis_compute` + `batch_inverse_fr` +
    /// `interpolate_with_basis` must yield the same polynomial as the
    /// existing `lagrange_interpolate` on the same `(points, values)` pair.
    #[test]
    fn cached_basis_matches_legacy_lagrange() {
        let points: Vec<Fr> = [1u64, 2u64, 5u64, 11u64].into_iter().map(Fr::from).collect();
        let values: Vec<Fr> = [7u64, 14u64, 35u64, 88u64].into_iter().map(Fr::from).collect();

        let legacy = lagrange_interpolate(&points, &values).unwrap();

        let (nums, mut denoms) = lagrange_basis_compute(&points).unwrap();
        batch_inverse_fr(&mut denoms).unwrap();
        let cached = interpolate_with_basis(&nums, &denoms, &values);

        assert_eq!(cached, legacy);
    }

    /// Single-point case (n=1): basis numerator is the constant polynomial
    /// `1` and denominator is `1`. Interpolant should be the constant
    /// `values[0]`.
    #[test]
    fn cached_basis_single_point() {
        let points = alloc::vec![Fr::from(42u64)];
        let values = alloc::vec![Fr::from(99u64)];

        let (nums, mut denoms) = lagrange_basis_compute(&points).unwrap();
        batch_inverse_fr(&mut denoms).unwrap();
        let p = interpolate_with_basis(&nums, &denoms, &values);
        assert_eq!(p, alloc::vec![Fr::from(99u64)]);
    }
}
