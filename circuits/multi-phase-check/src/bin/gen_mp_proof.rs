//! Tier A4 end-to-end test: multi-phase circuit through our verifier.

use multi_phase_check_circuit::generate_mp_test_vector;

fn main() -> Result<(), anyhow::Error> {
    let seed = [0x77; 32];
    let k = 4;

    eprintln!("[1/4] generating KZG params (k={k}) + multi-phase witness…");
    let v = generate_mp_test_vector(k, seed)?;

    eprintln!("[2/4] vk={} B   proof={} B", v.vk_bytes.len(), v.proof_bytes.len());

    eprintln!("[3/4] running halo2_solana_verifier::verify…");
    let public_inputs: Vec<[u8; 32]> = vec![];
    let result = halo2_solana_verifier::verify(
        &v.vk_bytes, &v.proof_bytes, &public_inputs, &v.kzg_vk,
    );
    eprintln!("[4/4] verifier returned: {result:?}");

    match &result {
        Ok(true)  => eprintln!("✓ multi-phase proof verified end-to-end"),
        Ok(false) => return Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e)    => return Err(anyhow::anyhow!("verifier error: {e}")),
    }

    // Negative test: tamper one proof byte → must reject.
    eprintln!("[5/?] negative: flipping one byte of the proof…");
    let mut tampered = v.proof_bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    let neg = halo2_solana_verifier::verify(
        &v.vk_bytes, &tampered, &public_inputs, &v.kzg_vk,
    );
    match neg {
        Ok(false) | Err(_) => eprintln!("       ✓ verifier rejected tampered proof: {neg:?}"),
        Ok(true) => return Err(anyhow::anyhow!("SOUNDNESS BUG: accepted tampered multi-phase proof")),
    }

    eprintln!();
    eprintln!("Tier A4 multi-phase test complete: VK appendix written, proof_reader");
    eprintln!("phase-interleaved loop matches halo2's protocol order.");
    Ok(())
}
