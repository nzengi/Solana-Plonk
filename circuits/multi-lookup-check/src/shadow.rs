//! Differential audit for the 2-lookup circuit. Same pattern as
//! `range-check-circuit::shadow`, but with mutations targeting BOTH
//! lookups' specific regions to confirm the verifier's lookup loop
//! correctly distinguishes lookup_0 from lookup_1 (no off-by-one in
//! `proof.lookup_evals[i]`).

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

use crate::prover::MlTestVector;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict { Accept, Reject }

fn run_halo2(params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, proof: &[u8]) -> Verdict {
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

pub fn audit(params: &ParamsKZG<Bn256>, v: &MlTestVector) -> Result<(), anyhow::Error> {
    eprintln!("[shadow] differential audit — multi-lookup (2 Plookup args)");

    let h = run_halo2(params, &v.halo2_vk, &v.proof_bytes);
    let o = run_ours(&v.vk_bytes, &v.proof_bytes, &v.kzg_vk);
    eprintln!("[shadow]   valid proof   halo2={h:?} ours={o:?}");
    if h != Verdict::Accept || o != Verdict::Accept {
        return Err(anyhow::anyhow!("valid 2-lookup proof rejected: halo2={h:?} ours={o:?}"));
    }

    let layout = layout_offsets(&v.halo2_vk, v.proof_bytes.len());

    // Targeted mutations: one in EACH lookup's region. If our verifier's
    // lookup loop has an off-by-one (e.g., reads lookup_0's evals at index 1),
    // mutating lookup_1's eval byte would either:
    //  - leave both verifiers in agreement (asymmetric is impossible) but
    //    not actually exercise lookup_1's eval → invisible bug
    //  - cause halo2 to reject and ours to accept → asymmetric verdict (caught)
    let mutations: &[(&str, usize)] = &[
        ("lookup_0.permuted_input_commit", layout.lookup_permuted_input_commit_byte),
        ("lookup_1.permuted_input_commit", layout.lookup_permuted_input_commit_byte + 64 * 2), // 1 lookup later
        ("lookup_0.product_eval",          layout.lookup_product_eval_byte),
        ("lookup_1.product_eval",          layout.lookup_product_eval_byte + 5 * 32), // 1 lookup later
        ("opening_proof_w",                layout.opening_proof_w_byte),
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
        eprintln!("[shadow]   mutate {label:35} (off {off:4}) halo2={h:?} ours={o:?}");
        if h != o {
            return Err(anyhow::anyhow!(
                "soundness asymmetry on {label}: halo2={h:?} ours={o:?}"
            ));
        }
        if h != Verdict::Reject {
            return Err(anyhow::anyhow!("halo2 unexpectedly accepted mutated proof at {label}"));
        }
    }

    eprintln!("[shadow] ✓ all 5 multi-lookup mutations rejected symmetrically");
    Ok(())
}

#[allow(dead_code)]
struct ProofLayout {
    lookup_permuted_input_commit_byte:   usize,
    lookup_product_eval_byte:            usize,
    opening_proof_w_byte:                usize,
}

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

    let lookup_permuted_input_commit_byte = num_advice * G1_LEN;
    let g1_count_through_h =
        num_advice + 2 * num_lookups + num_perm_chunks + num_lookups + 1
        + cs_degree.saturating_sub(1);
    let perm_prod_evals_count = if num_perm_chunks == 0 { 0 } else { 3 * (num_perm_chunks - 1) + 2 };
    let fr_before_lookup_evals =
        num_advice_q + num_fixed_q + 1 + num_perm_cols + perm_prod_evals_count;
    let lookup_product_eval_byte =
        g1_count_through_h * G1_LEN + fr_before_lookup_evals * FR_LEN;
    let opening_proof_w_byte = proof_len - 2 * G1_LEN;

    ProofLayout {
        lookup_permuted_input_commit_byte,
        lookup_product_eval_byte,
        opening_proof_w_byte,
    }
}
