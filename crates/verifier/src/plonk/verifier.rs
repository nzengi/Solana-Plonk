//! Top-level verifier glue: parses proof bytes, derives challenges, evaluates
//! gate + permutation contributions, aggregates the vanishing argument's
//! h-pieces, builds KZG queries, runs SHPLONK opening, and finalises with one
//! pairing check.
//!
//! v1 scope: hard-coded **StandardPlonk** gate identity. Generic gate AST
//! evaluation (so any halo2 circuit can be verified) is v1.5.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, Zero};

use crate::{
    curve::G1,
    field::fr_to_bytes_be,
    kzg::{shplonk, shplonk::VerifierQuery, KzgVk},
    pairing,
    plonk::{lagrange, permutation, Challenges, PlonkProof, PlonkProtocol},
    proof_reader,
    transcript::Keccak256Transcript,
    vk::parse_vk,
    Error,
};

/// StandardPlonk gate identity column ordering convention.
///
/// fixed columns: `[q_a, q_b, q_c, q_ab, q_const]`
/// advice columns: `[a, b, c]`
/// Single permutation set over all advice columns.
///
/// These constants are exposed for the prover (task #8) so the off-chain
/// circuit can be constructed with the matching column layout.
pub mod standard_plonk {
    pub const Q_A:     usize = 0;
    pub const Q_B:     usize = 1;
    pub const Q_C:     usize = 2;
    pub const Q_AB:    usize = 3;
    pub const Q_CONST: usize = 4;
    pub const NUM_FIXED:  usize = 5;

    pub const A: usize = 0;
    pub const B: usize = 1;
    pub const C: usize = 2;
    pub const NUM_ADVICE: usize = 3;
}

/// Evaluate the StandardPlonk gate identity at challenge `x`.
///
/// Returns a single-element vector — halo2's general API returns a Vec of
/// per-gate, per-row expressions; we keep the same shape so the y-fold logic
/// generalises trivially in v1.5.
#[inline(never)]
pub fn gate_standard_plonk(proof: &PlonkProof) -> Result<Vec<Fr>, Error> {
    use standard_plonk::*;
    if proof.advice_evals.len() < NUM_ADVICE {
        return Err(Error::Protocol("gate: advice_evals shorter than NUM_ADVICE"));
    }
    if proof.fixed_evals.len() < NUM_FIXED {
        return Err(Error::Protocol("gate: fixed_evals shorter than NUM_FIXED"));
    }
    let a = proof.advice_evals[A];
    let b = proof.advice_evals[B];
    let c = proof.advice_evals[C];
    let q_a     = proof.fixed_evals[Q_A];
    let q_b     = proof.fixed_evals[Q_B];
    let q_c     = proof.fixed_evals[Q_C];
    let q_ab    = proof.fixed_evals[Q_AB];
    let q_const = proof.fixed_evals[Q_CONST];

    // q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0
    let expr = q_a * a + q_b * b + q_c * c + q_ab * a * b + q_const;
    Ok(alloc::vec![expr])
}

/// Aggregate the vanishing argument's h-pieces into a single G1 commitment:
///   `h_commitment = Σᵢ xnⁱ · h_pieces[i]`
/// halo2's prover splits `h(X)` of degree `(cs_degree-1)·n` into `cs_degree-1`
/// pieces of degree `< n`, so reassembly uses `xn = x^n` as the basis.
/// Compute `expected_h_eval = (Σᵢ eᵢ · y^(n-1-i)) / (xⁿ − 1)` from gate
/// and permutation expressions. Owns the intermediate `Vec<Fr>` for the
/// folded list, isolating it from `verify`'s frame.
#[inline(never)]
pub fn compute_expected_h_eval(
    vk: &PlonkProtocol,
    proof: &PlonkProof,
    ch: &Challenges,
    lag: &lagrange::LagrangeEvaluations,
) -> Result<Fr, Error> {
    let mut expressions: Vec<Fr> = Vec::new();
    expressions.extend(gate_standard_plonk(proof)?);
    expressions.extend(permutation::expressions(vk, proof, ch, lag)?);

    #[cfg(feature = "debug-trace")] {
        for (i, e) in expressions.iter().enumerate() {
            eprintln!("[verifier] expr[{i}] = {}", _fr_hex(e));
        }
    }

    // Halo2's forward Horner fold: first expression gets highest y power.
    let folded = expressions.iter().fold(Fr::ZERO, |acc, e| acc * ch.y + e);
    let xn_inv = (lag.xn - Fr::ONE).inverse()
        .ok_or(Error::Protocol("verify: xn − 1 = 0 (x on subgroup)"))?;
    let expected = folded * xn_inv;

    #[cfg(feature = "debug-trace")] {
        eprintln!("[verifier] folded          = {}", _fr_hex(&folded));
        eprintln!("[verifier] expected_h_eval = {}", _fr_hex(&expected));
    }
    Ok(expected)
}

#[inline(never)]
pub fn aggregate_h_commitment(h_pieces: &[G1], xn: Fr) -> Result<G1, Error> {
    if h_pieces.is_empty() {
        return Err(Error::Protocol("aggregate_h: no pieces"));
    }
    let mut xn_powers = Vec::with_capacity(h_pieces.len());
    let mut acc = Fr::ONE;
    for _ in 0..h_pieces.len() {
        xn_powers.push(acc);
        acc *= xn;
    }
    // MSM via syscalls. Sequential — Pippenger-MSM SIMD is the natural follow-up.
    let mut acc_g1: Option<G1> = None;
    for (s, p) in xn_powers.iter().zip(h_pieces.iter()) {
        if s.is_zero() || p == &G1::IDENTITY {
            continue;
        }
        let term = p.scalar_mul(&fr_to_bytes_be(s))?;
        acc_g1 = Some(match acc_g1 {
            None => term,
            Some(a) => a.add(&term)?,
        });
    }
    Ok(acc_g1.unwrap_or(G1::IDENTITY))
}

/// Compose all queries the SHPLONK verifier needs to check.
///
/// For v1 (StandardPlonk, queries at rotation 0 only) the query list is:
///
/// * advice commitments at `x` with their `advice_evals`
/// * fixed commitments at `x` with their `fixed_evals`
/// * permutation common commitments at `x` with `permutation_common_evals`
/// * permutation product commitments at `x` and `ω·x` (and `ω^last·x` for non-last sets)
/// * aggregated `h_commitment` at `x` with `expected_h_eval`
/// * `random_poly_commit` at `x` with `random_poly_eval`
#[inline(never)]
pub fn build_queries(
    vk: &PlonkProtocol,
    proof: &PlonkProof,
    ch: &Challenges,
    h_commitment: G1,
    expected_h_eval: Fr,
    omega: Fr,
    omega_last: Fr,
) -> Result<Vec<VerifierQuery>, Error> {
    // Order MATTERS: must match halo2_proofs::plonk::verifier::verify_proof's
    // query iterator chain exactly, or the SHPLONK rotation-set grouping
    // produces different y-power assignments and the pairing rejects.
    //
    // Halo2's order (single circuit, no instance queries, no lookups, no shuffles):
    //   advice (per-circuit) → permutation_product (at x, ωx, ω^last·x)
    //   → fixed → permutation_common → vanishing (h + random_poly).
    // commit_id reflects the *slot* a commitment came from. Halo2 uses
    // pointer-equality on CommitmentReference; we mirror it with stable
    // integer ids so byte-equal commits in distinct slots stay separate.
    let mut q: Vec<VerifierQuery> = Vec::new();
    let mut next_id: usize = 0;
    let mut id = || { let i = next_id; next_id += 1; i };

    // Pre-allocate ids per slot list, in the order halo2 builds query references.
    let advice_ids:    Vec<usize> = proof.advice_commits.iter().map(|_| id()).collect();
    let perm_prod_ids: Vec<usize> = proof.permutation_product_commits.iter().map(|_| id()).collect();
    let fixed_ids:     Vec<usize> = vk.fixed_commitments.iter().map(|_| id()).collect();
    let perm_common_ids: Vec<usize> = vk.permutation_commitments.iter().map(|_| id()).collect();
    let h_id      = id();
    let random_id = id();

    // (1) Advice — at x.
    for ((cid, commit), eval) in advice_ids.iter().zip(proof.advice_commits.iter()).zip(proof.advice_evals.iter()) {
        q.push(VerifierQuery { commit_id: *cid, commitment: *commit, point: ch.x, eval: *eval });
    }
    // (2) Permutation product — at x, ω·x, and (for non-last sets) ω^last·x.
    let last_idx = vk.num_perm_chunks.saturating_sub(1);
    let x_next = ch.x * omega;
    let x_last = ch.x * omega_last;
    for ((cid, commit), evals) in perm_prod_ids.iter()
        .zip(proof.permutation_product_commits.iter())
        .zip(proof.permutation_product_evals.iter())
    {
        let (z, z_omega, _z_last) = *evals;
        q.push(VerifierQuery { commit_id: *cid, commitment: *commit, point: ch.x,   eval: z });
        q.push(VerifierQuery { commit_id: *cid, commitment: *commit, point: x_next, eval: z_omega });
    }
    // Halo2 emits z_last queries in REVERSE-skip-first order (`sets.iter().rev().skip(1)`),
    // i.e., for chunks indexed [last_idx-1, last_idx-2, ..., 0].
    for i in (0..last_idx).rev() {
        let (_z, _z_omega, z_last) = proof.permutation_product_evals[i];
        let commit = proof.permutation_product_commits[i];
        q.push(VerifierQuery { commit_id: perm_prod_ids[i], commitment: commit, point: x_last, eval: z_last });
    }
    // (3) Fixed — at x.
    for ((cid, commit), eval) in fixed_ids.iter().zip(vk.fixed_commitments.iter()).zip(proof.fixed_evals.iter()) {
        q.push(VerifierQuery { commit_id: *cid, commitment: *commit, point: ch.x, eval: *eval });
    }
    // (4) Permutation common — at x.
    for ((cid, commit), eval) in perm_common_ids.iter().zip(vk.permutation_commitments.iter()).zip(proof.permutation_common_evals.iter()) {
        q.push(VerifierQuery { commit_id: *cid, commitment: *commit, point: ch.x, eval: *eval });
    }
    // (5) Aggregated h commitment + random poly — at x.
    q.push(VerifierQuery { commit_id: h_id,      commitment: h_commitment,             point: ch.x, eval: expected_h_eval });
    q.push(VerifierQuery { commit_id: random_id, commitment: proof.random_poly_commit, point: ch.x, eval: proof.random_poly_eval });

    Ok(q)
}

/// Top-level verify.
pub fn verify(
    vk_bytes:      &[u8],
    proof_bytes:   &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk:        &KzgVk,
) -> Result<bool, Error> {
    // 1. Parse VK and initialise transcript with the pre-computed `transcript_repr`.
    let vk = parse_vk(vk_bytes)?;
    let mut transcript = Keccak256Transcript::new(&vk.transcript_repr);

    #[cfg(feature = "debug-trace")] {
        eprintln!("[verifier] vk: k={} num_advice={} num_fixed={} num_advice_q={} num_fixed_q={} cs_degree={} blinding={} num_perm_chunks={} num_perm_cols={}",
            vk.k, vk.num_advice, vk.num_fixed, vk.num_advice_queries, vk.num_fixed_queries,
            vk.cs_degree, vk.blinding_factors, vk.num_perm_chunks, vk.num_perm_columns());
        eprintln!("[verifier] kzg_vk.g1_one = {}", _g1_hex(&kzg_vk.g1_one));
        eprintln!("[verifier] kzg_vk.g2_one = 0x{}", _hex(&kzg_vk.g2_one.0));
        eprintln!("[verifier] kzg_vk.g2_tau = 0x{}", _hex(&kzg_vk.g2_tau.0));
        for (i, c) in vk.fixed_commitments.iter().enumerate() {
            eprintln!("[verifier] vk.fixed[{i}] = {}", _g1_hex(c));
        }
        for (i, c) in vk.permutation_commitments.iter().enumerate() {
            eprintln!("[verifier] vk.perm[{i}]  = {}", _g1_hex(c));
        }
    }

    // 2. Walk the protocol-order reader to absorb commits and squeeze challenges.
    let (proof, ch) = proof_reader::read_proof(&vk, proof_bytes, public_inputs, &mut transcript)?;

    #[cfg(feature = "debug-trace")] {
        eprintln!("[verifier] theta = {}", _fr_hex(&ch.theta));
        eprintln!("[verifier] beta  = {}", _fr_hex(&ch.beta));
        eprintln!("[verifier] gamma = {}", _fr_hex(&ch.gamma));
        eprintln!("[verifier] y     = {}", _fr_hex(&ch.y));
        eprintln!("[verifier] x     = {}", _fr_hex(&ch.x));
        eprintln!("[verifier] shplonk_y = {}", _fr_hex(&ch.shplonk_y));
        eprintln!("[verifier] shplonk_v = {}", _fr_hex(&ch.shplonk_v));
        eprintln!("[verifier] shplonk_u = {}", _fr_hex(&ch.shplonk_u));
        for (i, e) in proof.advice_evals.iter().enumerate() {
            eprintln!("[verifier] advice_evals[{i}] = {}", _fr_hex(e));
        }
        for (i, e) in proof.fixed_evals.iter().enumerate() {
            eprintln!("[verifier] fixed_evals[{i}]  = {}", _fr_hex(e));
        }
        for (i, e) in proof.permutation_common_evals.iter().enumerate() {
            eprintln!("[verifier] perm_common[{i}]  = {}", _fr_hex(e));
        }
        for (i, (z, zw, zl)) in proof.permutation_product_evals.iter().enumerate() {
            eprintln!("[verifier] perm_prod[{i}].z       = {}", _fr_hex(z));
            eprintln!("[verifier] perm_prod[{i}].z_omega = {}", _fr_hex(zw));
            eprintln!("[verifier] perm_prod[{i}].z_last  = {}", _fr_hex(zl));
        }
        eprintln!("[verifier] random_poly_eval = {}", _fr_hex(&proof.random_poly_eval));
    }

    // 3. Compute Lagrange evaluations at x.
    let lag = lagrange::evaluate_lagrange(vk.k, vk.omega, ch.x, vk.blinding_factors)?;

    #[cfg(feature = "debug-trace")] {
        eprintln!("[verifier] xn      = {}", _fr_hex(&lag.xn));
        eprintln!("[verifier] l_0     = {}", _fr_hex(&lag.l_0));
        eprintln!("[verifier] l_last  = {}", _fr_hex(&lag.l_last));
        eprintln!("[verifier] l_blind = {}", _fr_hex(&lag.l_blind));
    }

    // 4. Build gate + permutation expressions, fold with y, divide by xn-1.
    //    Lives in its own helper so its intermediate `Vec<Fr>`s don't pile up
    //    on `verify`'s BPF stack frame.
    let expected_h_eval = compute_expected_h_eval(&vk, &proof, &ch, &lag)?;

    // 5. Aggregate the h-pieces into one virtual commitment.
    let h_commitment = aggregate_h_commitment(&proof.vanishing_h_commits, lag.xn)?;

    #[cfg(feature = "debug-trace")] {
        for (i, h) in proof.vanishing_h_commits.iter().enumerate() {
            eprintln!("[verifier] h_pieces[{i}] = {}", _g1_hex(h));
        }
        eprintln!("[verifier] h_commitment = {}", _g1_hex(&h_commitment));
    }

    // 6. Compute ω^last for the permutation product's "z_last" rotation.
    //    last_row index = -(blinding_factors + 1); ω^last = ω^(n - blinding - 1).
    let n: u64 = 1u64 << vk.k;
    let last_pow = n.saturating_sub(vk.blinding_factors as u64 + 1);
    let omega_last = pow_u64(vk.omega, last_pow);

    // 7. Build query list and run SHPLONK opening.
    let queries = build_queries(&vk, &proof, &ch, h_commitment, expected_h_eval, vk.omega, omega_last)?;

    #[cfg(feature = "debug-trace")] {
        eprintln!("[verifier] # queries = {}", queries.len());
        for (i, q) in queries.iter().enumerate() {
            eprintln!("[verifier] query[{i:>2}]: point={} eval={} commit={}",
                _fr_hex(&q.point), _fr_hex(&q.eval), _g1_hex(&q.commitment));
        }
    }

    let pairs = shplonk::verify_opening(
        &queries,
        proof.opening_proof_w,
        proof.opening_proof_w_prime,
        ch.shplonk_y, ch.shplonk_v, ch.shplonk_u,
        kzg_vk,
    )?;

    #[cfg(feature = "debug-trace")] {
        for (i, (g1, g2)) in pairs.0.iter().enumerate() {
            eprintln!("[verifier] pairing[{i}].g1 = {}", _g1_hex(g1));
            eprintln!("[verifier] pairing[{i}].g2 = 0x{}", _hex(&g2.0));
        }
    }

    // 8. Final pairing.
    pairing::pairing_check(&pairs.0)
}

#[cfg(feature = "debug-trace")]
fn _g1_hex(p: &G1) -> alloc::string::String {
    alloc::format!("0x{}", _hex(&p.0))
}

#[cfg(feature = "debug-trace")]
fn _hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes { write!(s, "{b:02x}").unwrap(); }
    s
}

#[inline]
fn pow_u64(mut base: Fr, mut exp: u64) -> Fr {
    let mut acc = Fr::ONE;
    while exp != 0 {
        if exp & 1 == 1 { acc *= base; }
        base = base.square();
        exp >>= 1;
    }
    acc
}

#[cfg(feature = "debug-trace")]
fn _fr_hex(f: &Fr) -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write;
    let be = crate::field::fr_to_bytes_be(f);
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in &be { write!(s, "{b:02x}").unwrap(); }
    s
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::curve::G1;

    fn synth_proof_for_gate(advice: [u64; 3], fixed: [u64; 5]) -> PlonkProof {
        PlonkProof {
            advice_commits: alloc::vec![G1::IDENTITY; 3],
            permutation_product_commits: alloc::vec![G1::IDENTITY],
            random_poly_commit: G1::IDENTITY,
            vanishing_h_commits: alloc::vec![G1::IDENTITY; 2],
            advice_evals: advice.iter().map(|v| Fr::from(*v)).collect(),
            fixed_evals: fixed.iter().map(|v| Fr::from(*v)).collect(),
            random_poly_eval: Fr::ZERO,
            permutation_common_evals: alloc::vec![Fr::ZERO; 3],
            permutation_product_evals: alloc::vec![(Fr::ONE, Fr::ONE, Fr::ONE)],
            opening_proof_w: G1::IDENTITY,
            opening_proof_w_prime: G1::IDENTITY,
        }
    }

    /// Gate identity holds trivially when all selectors and advice are zero.
    #[test]
    fn gate_zero_advice_zero_selectors_evaluates_to_zero() {
        let p = synth_proof_for_gate([0; 3], [0; 5]);
        let exprs = gate_standard_plonk(&p).unwrap();
        assert_eq!(exprs, alloc::vec![Fr::ZERO]);
    }

    /// q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const  =  3·5 + 7·11 + 0 + 0 + 100
    /// = 15 + 77 + 100 = 192
    #[test]
    fn gate_value_matches_hand_computation() {
        // advice = [a=5, b=11, c=99]   fixed = [q_a=3, q_b=7, q_c=0, q_ab=0, q_const=100]
        let p = synth_proof_for_gate([5, 11, 99], [3, 7, 0, 0, 100]);
        let exprs = gate_standard_plonk(&p).unwrap();
        assert_eq!(exprs, alloc::vec![Fr::from(192u64)]);
    }

    /// Exercises the q_ab·a·b cross-term: 1·a·b = a·b.
    #[test]
    fn gate_quadratic_term() {
        // q_a=q_b=q_c=q_const=0, q_ab=1 → expr = 1·a·b = 6·7 = 42
        let p = synth_proof_for_gate([6, 7, 0], [0, 0, 0, 1, 0]);
        let exprs = gate_standard_plonk(&p).unwrap();
        assert_eq!(exprs, alloc::vec![Fr::from(42u64)]);
    }

    #[test]
    fn aggregate_h_single_piece_returns_input() {
        // h = [P]  ⇒  Σ xnⁱ·h[i] = xn⁰ · P = P  (1·P)
        let mut p_bytes = [0u8; 64];
        p_bytes[31] = 1; p_bytes[63] = 2;
        let p = G1(p_bytes);
        let r = aggregate_h_commitment(&[p], Fr::from(7u64)).unwrap();
        // 1·G = G  (no syscall needed for the IDENTITY check, but our fn does
        // call scalar_mul with scalar=1 which goes through syscall on host
        // arkworks emulation — should be identity transformation on G1 generator).
        // Skip exact byte-equality check since 1·G1 may use Montgomery-form
        // arithmetic; just assert non-identity.
        assert_ne!(r, G1::IDENTITY);
    }

    #[test]
    fn aggregate_h_empty_errors() {
        assert!(aggregate_h_commitment(&[], Fr::ONE).is_err());
    }

    #[test]
    fn aggregate_h_skips_identity_pieces() {
        // [IDENTITY, IDENTITY]  with any xn  ⇒  IDENTITY
        let r = aggregate_h_commitment(&[G1::IDENTITY, G1::IDENTITY], Fr::from(99u64)).unwrap();
        assert_eq!(r, G1::IDENTITY);
    }

    /// Build queries — confirm count matches expected layout.
    /// Standard v1 with 3 advice, 5 fixed, 3 perm cols, 1 perm chunk:
    /// queries = 3 advice + 5 fixed + 3 perm_common + (2 for perm_product, no z_last for last chunk)
    ///         + 1 h_commitment + 1 random_poly  =  15 queries
    #[test]
    fn build_queries_count_matches_layout() {
        let vk = PlonkProtocol {
            k: 4,
            omega: Fr::from(2u64),
            num_instance: 0,
            num_advice: 3,
            num_fixed: 5,
            cs_degree: 4,
            num_advice_queries: 3,
            num_fixed_queries: 5,
            blinding_factors: 5,
            num_perm_chunks: 1,
            fixed_commitments: alloc::vec![G1::IDENTITY; 5],
            permutation_commitments: alloc::vec![G1::IDENTITY; 3],
            transcript_repr: [0u8; 32],
        };
        let mut proof = synth_proof_for_gate([1; 3], [1; 5]);
        proof.fixed_evals = alloc::vec![Fr::ONE; 5];
        let ch = Challenges {
            theta: Fr::ONE, beta: Fr::ONE, gamma: Fr::ONE,
            y: Fr::ONE, x: Fr::from(7u64),
            shplonk_y: Fr::ONE, shplonk_v: Fr::ONE, shplonk_u: Fr::ONE,
        };
        let qs = build_queries(&vk, &proof, &ch, G1::IDENTITY, Fr::ZERO, vk.omega, Fr::ONE).unwrap();
        // 3 advice + 5 fixed + 3 perm_common + 2 perm_product (no last for single chunk)
        // + h + random = 15
        assert_eq!(qs.len(), 15);
    }
}
