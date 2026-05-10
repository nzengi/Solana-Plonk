//! Differential soundness audit for the v2.0 lookup verifier.
//!
//! Runs **two** verifiers on the same proof:
//!   * Our `halo2_solana_verifier::verify` — the BPF-target code path
//!   * `halo2_proofs::plonk::verify_proof` — the reference implementation
//!
//! On a valid proof both must accept. On a malformed proof both must
//! reject. The shadow walks targeted byte positions in the proof —
//! one in an advice eval, one in a lookup commit, one in a lookup eval —
//! flips one byte each, and asserts symmetric rejection. This catches
//! soundness drift: any case where our verifier accepts strictly more
//! than halo2 indicates an algorithmic bug.
//!
//! What this shadow does NOT do (deferred):
//!  * Bit-equal compare of intermediate Fr/G1 values (would require
//!    extending the verifier's debug-trace to log lookup compressions and
//!    expression values, then re-deriving them in halo2curves).
//!  * Cross-validation of Plookup-specific expression order (theta-fold
//!    direction is locked by `lookup::tests::compress_two_expressions_horner`).

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::TranscriptReadBuffer,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

use halo2_solana_verifier::kzg::KzgVk;
use standard_plonk_circuit::keccak_be_transcript::KeccakBeRead;

use crate::prover::RcTestVector;

/// Verdict from one side of the differential test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    Accept,
    Reject,
}

fn run_halo2(
    params: &ParamsKZG<Bn256>,
    vk:     &VerifyingKey<G1Affine>,
    proof:  &[u8],
) -> Verdict {
    let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof);
    let strategy = SingleStrategy::new(&pv);
    let instances: &[&[Fr]] = &[];
    match verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        &pv, vk, strategy, &[instances], &mut tr,
    ) {
        Ok(_)  => Verdict::Accept,
        Err(_) => Verdict::Reject,
    }
}

fn run_ours(
    vk_bytes:    &[u8],
    proof:       &[u8],
    kzg_vk:      &KzgVk,
) -> Verdict {
    match halo2_solana_verifier::verify(vk_bytes, proof, &[], kzg_vk) {
        Ok(true)  => Verdict::Accept,
        Ok(false) => Verdict::Reject,
        Err(_)    => Verdict::Reject,
    }
}

/// Run the full differential audit. Panics with a clear message on
/// asymmetric verdict (the soundness regression we're guarding against).
pub fn audit(
    params: &ParamsKZG<Bn256>,
    v:      &RcTestVector,
) -> Result<(), anyhow::Error> {
    eprintln!("[shadow] differential audit — halo2 vs our verifier");

    // ── (1) positive case: both accept the unmodified proof.
    let h = run_halo2(params, &v.halo2_vk, &v.proof_bytes);
    let o = run_ours(&v.vk_bytes, &v.proof_bytes, &v.kzg_vk);
    eprintln!("[shadow]   valid proof   halo2={h:?} ours={o:?}");
    if h != Verdict::Accept || o != Verdict::Accept {
        return Err(anyhow::anyhow!(
            "valid proof rejected: halo2={h:?} ours={o:?}"
        ));
    }

    // ── (2) extended mutation set. 10 distinct proof regions, each
    // bit-flipped independently. Both verifiers must reject every one
    // symmetrically — asymmetric verdict ⇒ soundness bug.
    let layout = layout_offsets(&v.halo2_vk, v.proof_bytes.len());

    let mutations: &[(&str, usize)] = &[
        ("advice_commit",                 layout.advice_commit_byte),
        ("lookup_permuted_input_commit",  layout.lookup_permuted_input_commit_byte),
        ("lookup_permuted_table_commit",  layout.lookup_permuted_table_commit_byte),
        ("lookup_product_commit",         layout.lookup_product_commit_byte),
        ("random_poly_commit",            layout.random_poly_commit_byte),
        ("h_piece_commit",                layout.h_pieces_byte),
        ("advice_eval",                   layout.advice_eval_byte),
        ("random_poly_eval",              layout.random_poly_eval_byte),
        ("lookup_product_eval",           layout.lookup_product_eval_byte),
        ("lookup_permuted_table_eval",    layout.lookup_permuted_table_eval_byte),
        ("opening_proof_w",               layout.opening_proof_w_byte),
    ];

    for (label, off) in mutations {
        let mut mutated = v.proof_bytes.clone();
        if *off >= mutated.len() {
            return Err(anyhow::anyhow!(
                "shadow offset {off} out of range for proof of len {}", mutated.len(),
            ));
        }
        mutated[*off] ^= 0x01;
        let h = run_halo2(params, &v.halo2_vk, &mutated);
        let o = run_ours(&v.vk_bytes, &mutated, &v.kzg_vk);
        eprintln!("[shadow]   mutate {label:32} (off {off:4}) halo2={h:?} ours={o:?}");
        if h != o {
            return Err(anyhow::anyhow!(
                "soundness asymmetry on {label}: halo2={h:?} ours={o:?}",
            ));
        }
        if h != Verdict::Reject {
            return Err(anyhow::anyhow!(
                "halo2 unexpectedly accepted mutated proof at {label}",
            ));
        }
    }

    eprintln!("[shadow] ✓ all 11 lookup mutations rejected symmetrically by both verifiers");
    Ok(())
}

/// Byte offsets into the proof for each region we mutate.
#[allow(dead_code)]
struct ProofLayout {
    advice_commit_byte:                  usize,
    lookup_permuted_input_commit_byte:   usize,
    lookup_permuted_table_commit_byte:   usize,
    lookup_product_commit_byte:          usize,
    random_poly_commit_byte:             usize,
    h_pieces_byte:                       usize,
    advice_eval_byte:                    usize,
    random_poly_eval_byte:               usize,
    lookup_product_eval_byte:            usize,
    lookup_permuted_table_eval_byte:     usize,
    opening_proof_w_byte:                usize,
}

/// Compute the byte offsets we mutate. Mirrors the read order in
/// `halo2_solana_verifier::proof_reader::read_proof` for the v2.0 layout.
fn layout_offsets(vk: &VerifyingKey<G1Affine>, proof_len: usize) -> ProofLayout {
    const G1_LEN: usize = 64;
    const FR_LEN: usize = 32;

    let cs = vk.cs();
    let num_advice    = cs.num_advice_columns();
    let num_lookups   = cs.lookups().len();
    let num_perm_cols = vk.permutation().commitments().len();
    let cs_degree     = cs.degree();
    let chunk_len     = cs_degree.saturating_sub(2).max(1);
    let num_perm_chunks = if num_perm_cols == 0 { 0 } else { (num_perm_cols + chunk_len - 1) / chunk_len };
    let num_advice_q  = cs.advice_queries().len();
    let num_fixed_q   = cs.fixed_queries().len();

    // G1 region — sequential reads in proof_reader.rs::read_proof:
    let advice_commit_byte = 0;
    let lookup_permuted_input_commit_byte = num_advice * G1_LEN;
    let lookup_permuted_table_commit_byte = lookup_permuted_input_commit_byte + G1_LEN;
    let off_perm_product_commits =
        lookup_permuted_input_commit_byte + 2 * num_lookups * G1_LEN;
    let lookup_product_commit_byte = off_perm_product_commits + num_perm_chunks * G1_LEN;
    let random_poly_commit_byte = lookup_product_commit_byte + num_lookups * G1_LEN;
    let h_pieces_byte = random_poly_commit_byte + G1_LEN;

    // Fr region begins after all G1 commits + h pieces.
    let g1_count_through_h =
        num_advice
        + 2 * num_lookups
        + num_perm_chunks
        + num_lookups
        + 1
        + cs_degree.saturating_sub(1);
    let fr_region_start = g1_count_through_h * G1_LEN;

    let advice_eval_byte = fr_region_start;
    let off_random_poly_eval =
        fr_region_start + (num_advice_q + num_fixed_q) * FR_LEN;
    let random_poly_eval_byte = off_random_poly_eval;

    let perm_prod_evals_count = if num_perm_chunks == 0 { 0 } else { 3 * (num_perm_chunks - 1) + 2 };
    let lookup_product_eval_byte =
        off_random_poly_eval
        + (1 + num_perm_cols + perm_prod_evals_count) * FR_LEN;
    // 5 evals per lookup in order:
    //   product_eval, product_next_eval, permuted_input_eval,
    //   permuted_input_inv_eval, permuted_table_eval
    let lookup_permuted_table_eval_byte = lookup_product_eval_byte + 4 * FR_LEN;

    let opening_proof_w_byte = proof_len - 2 * G1_LEN;

    ProofLayout {
        advice_commit_byte,
        lookup_permuted_input_commit_byte,
        lookup_permuted_table_commit_byte,
        lookup_product_commit_byte,
        random_poly_commit_byte,
        h_pieces_byte,
        advice_eval_byte,
        random_poly_eval_byte,
        lookup_product_eval_byte,
        lookup_permuted_table_eval_byte,
        opening_proof_w_byte,
    }
}
