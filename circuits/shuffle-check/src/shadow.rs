//! Differential soundness audit for the v2.0 shuffle verifier.
//! Same shape as `range-check-circuit::shadow` — runs both halo2's
//! `verify_proof` and our `halo2_solana_verifier::verify` on the proof
//! bytes, asserts they agree (Accept/Accept on the valid proof,
//! Reject/Reject on three byte-mutation positions).

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

use crate::prover::ShTestVector;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict { Accept, Reject }

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

fn run_ours(vk_bytes: &[u8], proof: &[u8], kzg_vk: &KzgVk) -> Verdict {
    match halo2_solana_verifier::verify(vk_bytes, proof, &[], kzg_vk) {
        Ok(true)  => Verdict::Accept,
        Ok(false) => Verdict::Reject,
        Err(_)    => Verdict::Reject,
    }
}

pub fn audit(params: &ParamsKZG<Bn256>, v: &ShTestVector) -> Result<(), anyhow::Error> {
    eprintln!("[shadow] differential audit — halo2 vs our verifier (shuffle)");

    let h = run_halo2(params, &v.halo2_vk, &v.proof_bytes);
    let o = run_ours(&v.vk_bytes, &v.proof_bytes, &v.kzg_vk);
    eprintln!("[shadow]   valid proof   halo2={h:?} ours={o:?}");
    if h != Verdict::Accept || o != Verdict::Accept {
        return Err(anyhow::anyhow!("valid proof rejected: halo2={h:?} ours={o:?}"));
    }

    let layout = layout_offsets(&v.halo2_vk, v.proof_bytes.len());

    // 8 mutation positions covering every distinct proof region.
    // For each: bit-0 flip, BOTH verifiers must reject symmetrically.
    let mutations: &[(&str, usize)] = &[
        ("advice_commit",          layout.advice_commit_byte),
        ("shuffle_product_commit", layout.shuffle_product_commit_byte),
        ("random_poly_commit",     layout.random_poly_commit_byte),
        ("h_piece_commit",         layout.h_pieces_byte),
        ("advice_eval",            layout.advice_eval_byte),
        ("random_poly_eval",       layout.random_poly_eval_byte),
        ("shuffle_product_eval",   layout.shuffle_product_eval_byte),
        ("opening_proof_w",        layout.opening_proof_w_byte),
    ];

    for (label, off) in mutations {
        let mut mutated = v.proof_bytes.clone();
        if *off >= mutated.len() {
            return Err(anyhow::anyhow!(
                "shadow offset {off} out of range (proof len {})", mutated.len()
            ));
        }
        mutated[*off] ^= 0x01;
        let h = run_halo2(params, &v.halo2_vk, &mutated);
        let o = run_ours(&v.vk_bytes, &mutated, &v.kzg_vk);
        eprintln!("[shadow]   mutate {label:25} (off {off:4}) halo2={h:?} ours={o:?}");
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

    eprintln!(
        "[shadow] ✓ all 8 shuffle mutations rejected symmetrically by both verifiers",
    );
    Ok(())
}

#[allow(dead_code)]
struct ProofLayout {
    advice_commit_byte:           usize,
    shuffle_product_commit_byte:  usize,
    random_poly_commit_byte:      usize,
    h_pieces_byte:                usize,
    advice_eval_byte:             usize,
    random_poly_eval_byte:        usize,
    shuffle_product_eval_byte:    usize,
    opening_proof_w_byte:         usize,
}

fn layout_offsets(vk: &VerifyingKey<G1Affine>, proof_len: usize) -> ProofLayout {
    const G1_LEN: usize = 64;
    const FR_LEN: usize = 32;

    let cs = vk.cs();
    let num_advice    = cs.num_advice_columns();
    let num_lookups   = cs.lookups().len();
    let num_shuffles  = cs.shuffles().len();
    let num_perm_cols = vk.permutation().commitments().len();
    let cs_degree     = cs.degree();
    let chunk_len     = cs_degree.saturating_sub(2).max(1);
    let num_perm_chunks = if num_perm_cols == 0 { 0 } else { (num_perm_cols + chunk_len - 1) / chunk_len };
    let num_advice_q  = cs.advice_queries().len();
    let num_fixed_q   = cs.fixed_queries().len();

    // G1 region — sequential reads in proof_reader.rs::read_proof:
    let advice_commit_byte = 0;
    let off_lookup_perm_commits = num_advice * G1_LEN;
    let off_perm_product_commits = off_lookup_perm_commits + 2 * num_lookups * G1_LEN;
    let off_lookup_product_commits =
        off_perm_product_commits + num_perm_chunks * G1_LEN;
    let shuffle_product_commit_byte =
        off_lookup_product_commits + num_lookups * G1_LEN;
    let random_poly_commit_byte =
        shuffle_product_commit_byte + num_shuffles * G1_LEN;
    let h_pieces_byte = random_poly_commit_byte + G1_LEN;

    // Fr region begins after all G1 commits + h pieces.
    let g1_count_through_h =
        num_advice
        + 2 * num_lookups
        + num_perm_chunks
        + num_lookups
        + num_shuffles
        + 1
        + cs_degree.saturating_sub(1);
    let fr_region_start = g1_count_through_h * G1_LEN;

    let advice_eval_byte = fr_region_start; // first Fr eval read is advice[0]
    let off_random_poly_eval =
        fr_region_start + (num_advice_q + num_fixed_q) * FR_LEN;
    let random_poly_eval_byte = off_random_poly_eval;

    let perm_prod_evals_count = if num_perm_chunks == 0 { 0 } else { 3 * (num_perm_chunks - 1) + 2 };
    let off_lookup_evals =
        off_random_poly_eval
        + (1 + num_perm_cols + perm_prod_evals_count) * FR_LEN;
    let lookup_evals_count = 5 * num_lookups;
    let shuffle_product_eval_byte =
        off_lookup_evals + lookup_evals_count * FR_LEN;

    // Opening proofs are the last two G1 in the proof.
    let opening_proof_w_byte = proof_len - 2 * G1_LEN;

    ProofLayout {
        advice_commit_byte,
        shuffle_product_commit_byte,
        random_poly_commit_byte,
        h_pieces_byte,
        advice_eval_byte,
        random_poly_eval_byte,
        shuffle_product_eval_byte,
        opening_proof_w_byte,
    }
}
