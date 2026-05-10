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

    // ── (2) targeted mutations. We pick offsets that land inside three
    //   distinct proof-section types so each is exercised end-to-end:
    //     a) advice commit byte   (G1 byte)
    //     b) lookup permuted_input commit byte
    //     c) lookup product_eval byte (Fr byte)
    //   Exact byte offsets depend on the proof layout but are stable for
    //   a fixed VK. We compute them from the v2.0 wire layout knowledge.
    let layout = layout_offsets(&v.halo2_vk);
    eprintln!(
        "[shadow]   layout: advice@{}  lookup_pi_commit@{}  lookup_product_eval@{}",
        layout.advice_commit_byte,
        layout.lookup_permuted_input_commit_byte,
        layout.lookup_product_eval_byte,
    );

    for (label, off) in [
        ("advice_commit",                 layout.advice_commit_byte),
        ("lookup_permuted_input_commit",  layout.lookup_permuted_input_commit_byte),
        ("lookup_product_eval",           layout.lookup_product_eval_byte),
    ] {
        let mut mutated = v.proof_bytes.clone();
        if off >= mutated.len() {
            return Err(anyhow::anyhow!(
                "shadow offset {off} out of range for proof of len {}", mutated.len(),
            ));
        }
        mutated[off] ^= 0x01; // single-bit flip

        let h = run_halo2(params, &v.halo2_vk, &mutated);
        let o = run_ours(&v.vk_bytes, &mutated, &v.kzg_vk);
        eprintln!("[shadow]   mutate {label:35} halo2={h:?} ours={o:?}");

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

    eprintln!("[shadow] ✓ all mutations rejected by both verifiers");
    Ok(())
}

/// Byte offsets into the proof for each kind of value we mutate.
struct ProofLayout {
    advice_commit_byte:                  usize,
    lookup_permuted_input_commit_byte:   usize,
    lookup_product_eval_byte:            usize,
}

/// Compute the byte offsets we mutate. Mirrors the read order in
/// `halo2_solana_verifier::proof_reader::read_proof` for the v2.0 layout.
fn layout_offsets(vk: &VerifyingKey<G1Affine>) -> ProofLayout {
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

    // Wire layout (lookup-only circuit, no shuffles, no instance):
    //   advice_commits           : num_advice                G1
    //   lookup permuted_*_commits: 2 · num_lookups            G1
    //   perm_product commits     : num_perm_chunks            G1
    //   lookup product_commits   : num_lookups                G1
    //   random_poly commit       : 1                          G1
    //   vanishing h pieces       : cs_degree − 1              G1
    //   advice_evals             : num_advice_q               Fr
    //   fixed_evals              : num_fixed_q                Fr
    //   random_poly_eval         : 1                          Fr
    //   perm_common_evals        : num_perm_cols              Fr
    //   perm_product_evals       : 3·(chunks-1) + 2           Fr
    //   lookup_evals             : 5 · num_lookups            Fr
    //   shuffle_evals            : 0                          Fr
    //   opening_proof_w          : 1                          G1
    //   opening_proof_w_prime    : 1                          G1
    let advice_commit_byte = 0; // very first byte of advice_commits[0]
    let lookup_permuted_input_commit_byte = num_advice * G1_LEN;
    let g1_count_before_lookup_evals =
        num_advice
        + 2 * num_lookups
        + num_perm_chunks
        + num_lookups
        + 1
        + cs_degree.saturating_sub(1);
    let perm_prod_evals_count = if num_perm_chunks == 0 { 0 } else { 3 * (num_perm_chunks - 1) + 2 };
    let fr_count_before_lookup_evals =
        num_advice_q
        + num_fixed_q
        + 1
        + num_perm_cols
        + perm_prod_evals_count;
    let lookup_product_eval_byte =
        g1_count_before_lookup_evals * G1_LEN
      + fr_count_before_lookup_evals * FR_LEN;

    ProofLayout {
        advice_commit_byte,
        lookup_permuted_input_commit_byte,
        lookup_product_eval_byte,
    }
}
