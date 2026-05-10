//! Differential audit for the bound-range-check circuit. Same pattern as
//! `range-check-circuit::shadow` — runs both halo2's reference verifier
//! and our `halo2_solana_verifier::verify`, asserts they agree on a valid
//! proof + on byte mutations + on a substituted-claimer attempt (which
//! is the security-critical mutation for this circuit).

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

use crate::prover::BrcTestVector;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict { Accept, Reject }

fn run_halo2(
    params: &ParamsKZG<Bn256>,
    vk:     &VerifyingKey<G1Affine>,
    proof:  &[u8],
    public_inputs: &[Fr],
) -> Verdict {
    let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof);
    let strategy = SingleStrategy::new(&pv);
    let instances: &[&[Fr]] = &[public_inputs];
    match verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        &pv, vk, strategy, &[instances], &mut tr,
    ) {
        Ok(_)  => Verdict::Accept,
        Err(_) => Verdict::Reject,
    }
}

fn run_ours(
    vk_bytes: &[u8],
    proof:    &[u8],
    kzg_vk:   &KzgVk,
    public_inputs: &[[u8; 32]],
) -> Verdict {
    match halo2_solana_verifier::verify(vk_bytes, proof, public_inputs, kzg_vk) {
        Ok(true)  => Verdict::Accept,
        Ok(false) => Verdict::Reject,
        Err(_)    => Verdict::Reject,
    }
}

pub fn audit(params: &ParamsKZG<Bn256>, v: &BrcTestVector) -> Result<(), anyhow::Error> {
    eprintln!("[shadow] differential audit — bound-range-check");

    let h_pis = vec![v.claimer_hash];
    let o_pis = vec![v.claimer_hash_be];

    let h = run_halo2(params, &v.halo2_vk, &v.proof_bytes, &h_pis);
    let o = run_ours(&v.vk_bytes, &v.proof_bytes, &v.kzg_vk, &o_pis);
    eprintln!("[shadow]   valid proof   halo2={h:?} ours={o:?}");
    if h != Verdict::Accept || o != Verdict::Accept {
        return Err(anyhow::anyhow!("valid proof rejected: halo2={h:?} ours={o:?}"));
    }

    // Targeted byte mutations (advice / lookup commit / opening proof)
    // — same shape as range-check shadow, scaled to this circuit's layout.
    // Layout depends on cs.degree() and the new instance/permutation columns,
    // so we keep the offsets minimal: just the very first proof byte
    // (advice commit high byte) and the last 64 bytes (opening_proof_w').
    let proof_len = v.proof_bytes.len();
    let mutations: &[(&str, usize)] = &[
        ("advice_commit_byte_0",         0),
        ("opening_proof_w_first_byte",   proof_len - 128),
        ("opening_proof_w_prime_byte_0", proof_len - 64),
    ];
    for (label, off) in mutations {
        let mut mutated = v.proof_bytes.clone();
        if *off >= mutated.len() {
            return Err(anyhow::anyhow!("offset {off} out of range"));
        }
        mutated[*off] ^= 0x01;
        let h = run_halo2(params, &v.halo2_vk, &mutated, &h_pis);
        let o = run_ours(&v.vk_bytes, &mutated, &v.kzg_vk, &o_pis);
        eprintln!("[shadow]   mutate {label:32} (off {off:4}) halo2={h:?} ours={o:?}");
        if h != o {
            return Err(anyhow::anyhow!(
                "soundness asymmetry on {label}: halo2={h:?} ours={o:?}"
            ));
        }
        if h != Verdict::Reject {
            return Err(anyhow::anyhow!("halo2 unexpectedly accepted at {label}"));
        }
    }

    // Security-critical: claimer-substitution attack. Eve copies Alice's
    // proof verbatim and tries to claim with a DIFFERENT public_input
    // (her own pubkey hash). Both verifiers MUST reject — that's what
    // "non-transferable claim" means.
    let eve_hash = Fr::from(0xDEAD_BEEFu64);
    let eve_hash_be = {
        let mut be = [0u8; 32];
        // 0xDEAD_BEEF as Fr; encode BE.
        be[28..].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        be
    };
    let h = run_halo2(params, &v.halo2_vk, &v.proof_bytes, &[eve_hash]);
    let o = run_ours(&v.vk_bytes, &v.proof_bytes, &v.kzg_vk, &[eve_hash_be]);
    eprintln!(
        "[shadow]   substitute claimer hash         halo2={h:?} ours={o:?}",
    );
    if h != o {
        return Err(anyhow::anyhow!(
            "soundness asymmetry on claimer-substitution: halo2={h:?} ours={o:?}",
        ));
    }
    if h != Verdict::Reject {
        return Err(anyhow::anyhow!(
            "halo2 unexpectedly accepted Eve's substituted-claimer attempt — circuit is NOT bound to claimer hash",
        ));
    }

    eprintln!(
        "[shadow] ✓ all 4 mutations + claimer substitution rejected symmetrically",
    );
    Ok(())
}
