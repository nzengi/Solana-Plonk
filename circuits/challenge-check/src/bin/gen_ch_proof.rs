//! End-to-end smoke test for the challenge-check (single-phase challenge)
//! circuit through `halo2-solana-verifier`.

use challenge_check_circuit::generate_ch_test_vector;

fn main() -> Result<(), anyhow::Error> {
    let seed = [42u8; 32];
    let k = 4;

    eprintln!("[1/4] generating KZG params (k={k}) + challenge witness…");
    let v = generate_ch_test_vector(k, seed)?;

    eprintln!(
        "[2/4] outputs:  vk={} B   proof={} B",
        v.vk_bytes.len(), v.proof_bytes.len(),
    );

    eprintln!("[3/4] running halo2_solana_verifier::verify…");
    let public_inputs: Vec<[u8; 32]> = Vec::new();
    let result = halo2_solana_verifier::verify(
        &v.vk_bytes, &v.proof_bytes, &public_inputs, &v.kzg_vk,
    );
    eprintln!("[4/4] verifier returned: {result:?}");

    match result {
        Ok(true)  => { eprintln!("✓ challenge proof verified end-to-end"); Ok(()) }
        Ok(false) => Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e)    => Err(anyhow::anyhow!("verifier error: {e}")),
    }
}
