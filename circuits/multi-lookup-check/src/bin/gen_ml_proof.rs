//! End-to-end smoke test for the 2-lookup circuit through `halo2-solana-verifier`.

use multi_lookup_check_circuit::generate_ml_test_vector;
use std::path::PathBuf;

fn main() -> Result<(), anyhow::Error> {
    let seed = [42u8; 32];
    let k = 6;
    let write_golden = std::env::args().any(|a| a == "--write-golden");
    let shadow_audit = std::env::args().any(|a| a == "--shadow-audit");

    eprintln!("[1/4] generating KZG params (k={k}) + multi-lookup witness…");
    let v = generate_ml_test_vector(k, seed)?;

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

    if write_golden && matches!(result, Ok(true)) {
        write_golden_vector(&v, &public_inputs)?;
    }

    if shadow_audit && matches!(result, Ok(true)) {
        multi_lookup_check_circuit::shadow::audit(&v.params, &v)?;
    }

    match result {
        Ok(true)  => { eprintln!("✓ multi-lookup proof verified end-to-end"); Ok(()) }
        Ok(false) => Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e)    => Err(anyhow::anyhow!("verifier error: {e}")),
    }
}

fn write_golden_vector(
    v: &multi_lookup_check_circuit::prover::MlTestVector,
    public_inputs: &[[u8; 32]],
) -> Result<(), anyhow::Error> {
    use std::{fs, io::Write};
    let path = PathBuf::from("circuits/multi-lookup-check/tests/golden_v2_ml.bin");
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"GLDN0002");
    buf.extend_from_slice(&(v.vk_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&v.vk_bytes);
    buf.extend_from_slice(&(v.proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&v.proof_bytes);
    buf.extend_from_slice(&v.kzg_vk.g1_one.0);
    buf.extend_from_slice(&v.kzg_vk.g2_one.0);
    buf.extend_from_slice(&v.kzg_vk.g2_tau.0);
    buf.extend_from_slice(&(public_inputs.len() as u32).to_le_bytes());
    for raw in public_inputs {
        buf.extend_from_slice(raw);
    }
    let mut f = fs::File::create(&path)?;
    f.write_all(&buf)?;
    eprintln!("[+] wrote multi-lookup golden vector → {} ({} B)", path.display(), buf.len());
    Ok(())
}
