//! Independent computation of the verifier's intermediate values using
//! halo2curves Fr arithmetic, mirroring halo2's own algorithm. Compared
//! against our `halo2_solana_verifier`'s `debug-trace` output to localise
//! algebraic divergence.
//!
//! All Fr values are printed as 32-byte BE hex so they line up with the
//! verifier's prints (which use `field::fr_to_bytes_be`).

use halo2_proofs::{
    plonk::VerifyingKey,
    transcript::TranscriptReadBuffer,
};
use halo2curves::{
    bn256::{Bn256, Fr, G1, G1Affine, G2Affine, G2Prepared},
    ff::PrimeField,
    group::{Curve, prime::PrimeCurveAffine, Group},
    pairing::{MillerLoopResult, MultiMillerLoop},
};

use crate::keccak_be_transcript::KeccakBeRead;

fn fr_be_hex(f: &Fr) -> String {
    let mut le = f.to_repr();
    le.reverse(); // → BE
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in &le { s.push_str(&format!("{b:02x}")); }
    s
}

fn pow_u64(mut base: Fr, mut exp: u64) -> Fr {
    let mut acc = Fr::one();
    while exp != 0 {
        if exp & 1 == 1 { acc *= base; }
        base = base.square();
        exp >>= 1;
    }
    acc
}

/// Re-read proof bytes via the same KeccakBeRead, dump same intermediate
/// quantities our Solana verifier prints. Halo2curves Fr arithmetic is
/// canonical (same field as arkworks bn254 Fr), so any divergence indicates
/// an algorithmic bug in our verifier.
pub fn shadow_dump(
    vk: &VerifyingKey<G1Affine>,
    proof_bytes: &[u8],
    g2_one: G2Affine,
    g2_tau: G2Affine,
) -> anyhow::Result<()> {
    use halo2_proofs::transcript::Transcript;

    let mut t: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes);

    // Initial absorb: vk.transcript_repr.
    t.common_scalar(vk.transcript_repr())?;

    let cs = vk.cs();
    let num_advice = cs.num_advice_columns();
    let num_fixed  = cs.num_fixed_columns();
    let num_advice_q = cs.advice_queries().len();
    let num_fixed_q  = cs.fixed_queries().len();
    let cs_degree    = cs.degree();
    let blinding     = cs.blinding_factors();
    let chunk_len    = cs_degree.saturating_sub(2).max(1);
    let num_perm_cols = vk.permutation().commitments().len();
    let num_perm_chunks = if num_perm_cols == 0 { 0 } else { (num_perm_cols + chunk_len - 1) / chunk_len };

    eprintln!("[shadow]   k=? num_advice={num_advice} num_fixed={num_fixed} cs_degree={cs_degree} blinding={blinding} num_perm_chunks={num_perm_chunks} chunk_len={chunk_len}");

    // Read advice commits.
    let mut advice_commits: Vec<G1Affine> = Vec::with_capacity(num_advice);
    for _ in 0..num_advice {
        advice_commits.push(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_point(&mut t)?);
    }
    let theta = t.squeeze_challenge_scalar::<()>();
    let beta  = t.squeeze_challenge_scalar::<()>();
    let gamma = t.squeeze_challenge_scalar::<()>();
    eprintln!("[shadow]   theta = {}", fr_be_hex(&*theta));
    eprintln!("[shadow]   beta  = {}", fr_be_hex(&*beta));
    eprintln!("[shadow]   gamma = {}", fr_be_hex(&*gamma));

    // Permutation product commits + random_poly commit.
    let mut perm_prod_commits: Vec<G1Affine> = Vec::with_capacity(num_perm_chunks);
    for _ in 0..num_perm_chunks {
        perm_prod_commits.push(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_point(&mut t)?);
    }
    let random_poly_commit = <KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_point(&mut t)?;

    let y = t.squeeze_challenge_scalar::<()>();
    eprintln!("[shadow]   y     = {}", fr_be_hex(&*y));

    // h pieces.
    let h_count = cs_degree.saturating_sub(1);
    let mut h_pieces: Vec<G1Affine> = Vec::with_capacity(h_count);
    for _ in 0..h_count {
        h_pieces.push(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_point(&mut t)?);
    }
    let x = t.squeeze_challenge_scalar::<()>();
    eprintln!("[shadow]   x     = {}", fr_be_hex(&*x));

    let mut advice_evals = Vec::with_capacity(num_advice_q);
    for _ in 0..num_advice_q {
        advice_evals.push(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?);
    }
    let mut fixed_evals = Vec::with_capacity(num_fixed_q);
    for _ in 0..num_fixed_q {
        fixed_evals.push(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?);
    }
    let random_poly_eval = <KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?;

    // Permutation common evals (one per perm column).
    let mut perm_common = Vec::with_capacity(num_perm_cols);
    for _ in 0..num_perm_cols {
        perm_common.push(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?);
    }
    // Permutation product evals: 3 per chunk, last chunk omits z_last.
    let mut perm_prod: Vec<(Fr, Fr, Option<Fr>)> = Vec::with_capacity(num_perm_chunks);
    for i in 0..num_perm_chunks {
        let z       = <KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?;
        let z_omega = <KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?;
        let z_last  = if i + 1 < num_perm_chunks {
            Some(<KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_scalar(&mut t)?)
        } else { None };
        perm_prod.push((z, z_omega, z_last));
    }

    // ── Now compute Lagrange evaluations using halo2curves Fr ───────────────
    // We need k. Halo2 stores it in domain (private). But we can read it from
    // the prover's params. For our test, k=4 is hard-coded.
    let k: u32 = 4;
    let n_u64: u64 = 1u64 << k;
    let xn = pow_u64(*x, n_u64);
    let n_inv = Fr::from(n_u64).invert().unwrap();
    let factor = (xn - Fr::one()) * n_inv;

    // omega = ROOT_OF_UNITY^(2^(S-k))
    let s = Fr::S;
    let mut omega = Fr::ROOT_OF_UNITY;
    for _ in 0..(s - k) { omega = omega.square(); }
    let omega_inv = omega.invert().unwrap();

    let l_0 = factor * (*x - Fr::one()).invert().unwrap();
    let mut omega_inv_pow = Fr::one();
    let mut l_blind = Fr::zero();
    for _ in 1..=blinding {
        omega_inv_pow *= omega_inv;
        let denom = (*x - omega_inv_pow).invert().unwrap();
        l_blind += omega_inv_pow * factor * denom;
    }
    omega_inv_pow *= omega_inv;
    let l_last = omega_inv_pow * factor * (*x - omega_inv_pow).invert().unwrap();

    eprintln!("[shadow]   xn      = {}", fr_be_hex(&xn));
    eprintln!("[shadow]   l_0     = {}", fr_be_hex(&l_0));
    eprintln!("[shadow]   l_last  = {}", fr_be_hex(&l_last));
    eprintln!("[shadow]   l_blind = {}", fr_be_hex(&l_blind));

    // ── Gate expression (StandardPlonk) ─────────────────────────────────────
    let q_a   = fixed_evals[0];
    let q_b   = fixed_evals[1];
    let q_c   = fixed_evals[2];
    let q_ab  = fixed_evals[3];
    let q_const = fixed_evals[4];
    let a = advice_evals[0];
    let b = advice_evals[1];
    let c = advice_evals[2];
    let gate = q_a * a + q_b * b + q_c * c + q_ab * a * b + q_const;
    eprintln!("[shadow]   gate_expr   = {}", fr_be_hex(&gate));

    // ── Permutation expressions (mirror halo2's algorithm) ──────────────────
    let mut perm_exprs: Vec<Fr> = Vec::new();
    let z_first = perm_prod[0].0;
    perm_exprs.push(l_0 * (Fr::one() - z_first));
    let z_l = perm_prod[num_perm_chunks - 1].0;
    perm_exprs.push(l_last * (z_l.square() - z_l));
    for i in 1..num_perm_chunks {
        let z_i  = perm_prod[i].0;
        let z_im1_last = perm_prod[i - 1].2.unwrap();
        perm_exprs.push(l_0 * (z_i - z_im1_last));
    }
    let active = Fr::one() - l_last - l_blind;
    // halo2curves DELTA — same constant we hard-coded in our verifier.
    let delta = Fr::DELTA;
    for i in 0..num_perm_chunks {
        let (z, z_omega, _) = perm_prod[i];
        let col_start = i * chunk_len;
        let col_end   = (col_start + chunk_len).min(num_perm_cols);

        let mut left = z_omega;
        for j in col_start..col_end {
            left *= advice_evals[j] + *beta * perm_common[j] + *gamma;
        }
        let mut current_delta = pow_u64(delta, (i * chunk_len) as u64) * *beta * *x;
        let mut right = z;
        for j in col_start..col_end {
            right *= advice_evals[j] + current_delta + *gamma;
            current_delta *= delta;
        }
        perm_exprs.push(active * (left - right));
    }
    for (i, e) in perm_exprs.iter().enumerate() {
        eprintln!("[shadow]   perm_expr[{i}] = {}", fr_be_hex(e));
    }

    // ── Fold + expected_h_eval ──────────────────────────────────────────────
    let mut all = vec![gate];
    all.extend(perm_exprs);
    let folded = all.iter().fold(Fr::zero(), |acc, e| acc * *y + e);
    let xn_inv = (xn - Fr::one()).invert().unwrap();
    let expected_h_eval = folded * xn_inv;
    eprintln!("[shadow]   folded         = {}", fr_be_hex(&folded));
    eprintln!("[shadow]   expected_h_eval = {}", fr_be_hex(&expected_h_eval));

    // ── SHPLONK challenges ──────────────────────────────────────────────────
    let shplonk_y = t.squeeze_challenge_scalar::<()>();
    let shplonk_v = t.squeeze_challenge_scalar::<()>();
    let h1 = <KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_point(&mut t)?;
    let shplonk_u = t.squeeze_challenge_scalar::<()>();
    let h2 = <KeccakBeRead<_, _, _> as halo2_proofs::transcript::TranscriptRead<G1Affine, _>>::read_point(&mut t)?;

    // ── Compute h_commitment = Σ xn^i · h_pieces[i] ─────────────────────────
    let mut h_commitment = G1::identity();
    let mut xn_pow = Fr::one();
    for hp in &h_pieces {
        h_commitment += G1::from(*hp) * xn_pow;
        xn_pow *= xn;
    }
    let h_commitment_aff: G1Affine = h_commitment.to_affine();
    eprintln!("[shadow]   h_commitment = {}", g1_be_hex(&h_commitment_aff));

    // ── omega_last = ω^(n - blinding - 1) ──────────────────────────────────
    let n_u64 = 1u64 << k;
    let last_pow = n_u64.saturating_sub(blinding as u64 + 1);
    let omega_last = pow_u64(omega, last_pow);
    let x_next = *x * omega;
    let x_last = *x * omega_last;

    // ── Build queries (same order as crates/verifier::build_queries) ────────
    let fixed_commits = vk.fixed_commitments();
    let perm_common_commits = vk.permutation().commitments();
    // Each query carries an explicit `commit_id: usize` so that byte-equal
    // commitments at different identity slots stay SEPARATE — mirroring
    // halo2's pointer-equality on `CommitmentReference`.
    let mut queries: Vec<(usize, G1Affine, Fr, Fr)> = Vec::new();
    let mut next_id: usize = 0;
    let mut new_id = || { let id = next_id; next_id += 1; id };

    // Each commit gets a stable id matching its slot in the list it came from.
    let advice_ids: Vec<usize> = advice_commits.iter().map(|_| new_id()).collect();
    let perm_prod_ids: Vec<usize> = perm_prod_commits.iter().map(|_| new_id()).collect();
    let fixed_ids: Vec<usize> = fixed_commits.iter().map(|_| new_id()).collect();
    let perm_common_ids: Vec<usize> = perm_common_commits.iter().map(|_| new_id()).collect();
    let h_id = new_id();
    let random_id = new_id();

    // (1) advice at x
    for ((id, c), e) in advice_ids.iter().zip(advice_commits.iter()).zip(advice_evals.iter()) {
        queries.push((*id, *c, *x, *e));
    }
    // (2) perm_prod (z, z_omega) per chunk
    for ((id, c), evs) in perm_prod_ids.iter().zip(perm_prod_commits.iter()).zip(perm_prod.iter()) {
        queries.push((*id, *c, *x, evs.0));
        queries.push((*id, *c, x_next, evs.1));
    }
    // z_last queries in rev order, skipping last chunk
    let last_idx = num_perm_chunks.saturating_sub(1);
    for i in (0..last_idx).rev() {
        let (_z, _zw, zl) = perm_prod[i];
        queries.push((perm_prod_ids[i], perm_prod_commits[i], x_last, zl.unwrap()));
    }
    // (3) fixed at x
    for ((id, c), e) in fixed_ids.iter().zip(fixed_commits.iter()).zip(fixed_evals.iter()) {
        queries.push((*id, *c, *x, *e));
    }
    // (4) perm_common at x
    for ((id, c), e) in perm_common_ids.iter().zip(perm_common_commits.iter()).zip(perm_common.iter()) {
        queries.push((*id, *c, *x, *e));
    }
    // (5) h + random
    queries.push((h_id, h_commitment_aff, *x, expected_h_eval));
    queries.push((random_id, random_poly_commit, *x, random_poly_eval));

    eprintln!("[shadow-shplonk] # queries = {}", queries.len());

    // ── construct_intermediate_sets (HALO2 EXACT) ───────────────────────────
    // Halo2 source uses BTreeSet<Fr> for super_point_set + per-commitment
    // rotation set, AND `std::ptr::eq` on CommitmentReference for grouping
    // commitments — i.e., byte-equal commits at different slots stay
    // SEPARATE. We mirror this with explicit `commit_id`s instead of
    // pointer comparison, since pointer-eq isn't available in our context.
    use std::collections::BTreeSet;

    let mut super_pts_set: BTreeSet<Fr> = BTreeSet::new();
    for q in &queries { super_pts_set.insert(q.2); }
    let super_pts: Vec<Fr> = super_pts_set.iter().copied().collect();

    // per_commitment keyed by `commit_id` (NOT bytes): this is what gives
    // byte-equal-but-distinct commits separate inner_msm slots.
    let mut per: Vec<(usize, G1Affine, BTreeSet<Fr>)> = Vec::new();
    for q in &queries {
        if let Some(slot) = per.iter_mut().find(|s| s.0 == q.0) {
            slot.2.insert(q.2);
        } else {
            let mut s = BTreeSet::new();
            s.insert(q.2);
            per.push((q.0, q.1, s));
        }
    }
    let get_eval = |id: usize, pt: Fr| -> Fr {
        queries.iter().find(|q| q.0 == id && q.2 == pt).map(|q| q.3).unwrap()
    };
    let mut rsets: Vec<(Vec<Fr>, Vec<(G1Affine, Vec<Fr>)>)> = Vec::new();
    for (id, c, rotation_set) in per {
        let pts: Vec<Fr> = rotation_set.iter().copied().collect();
        let evals: Vec<Fr> = pts.iter().map(|p| get_eval(id, *p)).collect();
        if let Some(rs) = rsets.iter_mut().find(|rs| rs.0 == pts) {
            rs.1.push((c, evals));
        } else {
            rsets.push((pts, vec![(c, evals)]));
        }
    }
    eprintln!("[shadow-shplonk] # rotation_sets = {}", rsets.len());
    for (i, rs) in rsets.iter().enumerate() {
        eprintln!("[shadow-shplonk] rs[{i}] points={} commits={}", rs.0.len(), rs.1.len());
    }

    // ── SHPLONK reduction in halo2curves ────────────────────────────────────
    let mut z_0 = Fr::zero();
    let mut z_0_inv = Fr::zero();
    let mut outer_msm = G1::identity();
    let mut r_outer = Fr::zero();
    let mut v_pow = Fr::one();

    for (i, (pts, commits)) in rsets.iter().enumerate() {
        // diffs = super ∖ pts
        let diffs: Vec<Fr> = super_pts.iter().filter(|p| !pts.contains(p)).copied().collect();
        let mut z_diff = diffs.iter().fold(Fr::one(), |acc, p| acc * (*shplonk_u - *p));
        if i == 0 {
            z_0 = pts.iter().fold(Fr::one(), |acc, p| acc * (*shplonk_u - *p));
            z_0_inv = z_diff.invert().unwrap();
            z_diff = Fr::one();
        } else {
            z_diff *= z_0_inv;
        }
        eprintln!("[shadow-shplonk] rs[{i}] z_diff = {}", fr_be_hex(&z_diff));

        let mut inner_msm = G1::identity();
        let mut r_inner = Fr::zero();
        let mut y_pow = Fr::one();
        for (c, evals) in commits {
            // r_x(X) interpolation, evaluated at u
            let r_x = lagrange_interp(pts, evals);
            let r_eval = y_pow * eval_poly(&r_x, *shplonk_u);
            inner_msm += G1::from(*c) * y_pow;
            r_inner += r_eval;
            y_pow *= *shplonk_y;
        }
        let scale = v_pow * z_diff;
        outer_msm += inner_msm * scale;
        r_outer += scale * r_inner;
        v_pow *= *shplonk_v;
    }

    // outer += -r_outer * [1]_1
    let g1_one = G1Affine::generator();
    outer_msm += G1::from(g1_one) * (-r_outer);
    // outer += -z_0 * h1
    outer_msm += G1::from(h1) * (-z_0);
    // outer += u * h2
    outer_msm += G1::from(h2) * *shplonk_u;

    let outer_aff: G1Affine = outer_msm.to_affine();
    eprintln!("[shadow-shplonk] z_0          = {}", fr_be_hex(&z_0));
    eprintln!("[shadow-shplonk] r_outer      = {}", fr_be_hex(&r_outer));
    eprintln!("[shadow-shplonk] outer_msm    = {}", g1_be_hex(&outer_aff));
    eprintln!("[shadow-shplonk] h1           = {}", g1_be_hex(&h1));
    eprintln!("[shadow-shplonk] h2           = {}", g1_be_hex(&h2));

    // ── halo2curves pairing test ────────────────────────────────────────────
    // Equation (halo2's DualMSM::check):
    //   e(left, [τ]_2) · e(right, -[1]_2) = 1
    // with left = h2, right = outer_msm.
    let neg_g2_one_aff: G2Affine = (-g2_one).into();
    let g2_tau_prep: G2Prepared = g2_tau.into();
    let g2_one_prep: G2Prepared = g2_one.into();
    let neg_g2_one_prep: G2Prepared = neg_g2_one_aff.into();

    // Variant A: halo2's exact form  e(h2, g2_tau) · e(outer, -g2_one)
    let pa = Bn256::multi_miller_loop(&[
        (&h2, &g2_tau_prep),
        (&outer_aff, &neg_g2_one_prep),
    ]).final_exponentiation();
    let a_ok: bool = bool::from(pa.is_identity());
    eprintln!("[shadow-pairing] (h2,τ)·(outer,−1) = {}", if a_ok { "1 ✓" } else { "≠1 ✗" });

    // Variant B: our verifier's form  e(h2, g2_tau) · e(-outer, g2_one)
    let neg_outer: G1Affine = (-G1::from(outer_aff)).to_affine();
    let pb = Bn256::multi_miller_loop(&[
        (&h2, &g2_tau_prep),
        (&neg_outer, &g2_one_prep),
    ]).final_exponentiation();
    let b_ok: bool = bool::from(pb.is_identity());
    eprintln!("[shadow-pairing] (h2,τ)·(−outer,1) = {}", if b_ok { "1 ✓" } else { "≠1 ✗" });
    eprintln!("[shadow-pairing] neg_outer (halo2curves) = {}", g1_be_hex(&neg_outer));

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────────────────

fn g1_be_hex(p: &G1Affine) -> String {
    if bool::from(p.is_identity()) {
        return format!("0x{}", "00".repeat(64));
    }
    let mut x = p.x.to_repr(); x.as_mut().reverse();
    let mut y = p.y.to_repr(); y.as_mut().reverse();
    let mut s = String::with_capacity(2 + 128);
    s.push_str("0x");
    for b in x.as_ref() { s.push_str(&format!("{b:02x}")); }
    for b in y.as_ref() { s.push_str(&format!("{b:02x}")); }
    s
}

fn lagrange_interp(pts: &[Fr], vals: &[Fr]) -> Vec<Fr> {
    let n = pts.len();
    let mut result = vec![Fr::zero(); n];
    for j in 0..n {
        // numerator: Π_{i≠j} (X − pts[i])
        let mut num = vec![Fr::zero(); n];
        num[0] = Fr::one();
        let mut deg = 1usize;
        for i in 0..n {
            if i == j { continue; }
            let xi = pts[i];
            let mut new_num = vec![Fr::zero(); deg + 1];
            for k in 0..deg {
                new_num[k] -= num[k] * xi;
                new_num[k + 1] += num[k];
            }
            for k in 0..deg + 1 { num[k] = new_num[k]; }
            deg += 1;
        }
        let mut denom = Fr::one();
        for i in 0..n {
            if i == j { continue; }
            denom *= pts[j] - pts[i];
        }
        let scale = vals[j] * denom.invert().unwrap();
        for k in 0..n { result[k] += num[k] * scale; }
    }
    result
}

fn eval_poly(coeffs: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::zero();
    for c in coeffs.iter().rev() { acc = acc * x + *c; }
    acc
}
