//! End-to-end smoke test: generate a StandardPlonk proof off-chain, run our
//! Solana verifier on it (host-side, same code path that runs on BPF).
//!
//! With `--write-golden`, also writes the `(vk, proof, kzg_vk)` byte triple
//! to `tests/golden_v1.bin` for downstream snapshot tests (Pinocchio program
//! tests in particular).

use standard_plonk_circuit::generate_test_vector;

fn main() -> Result<(), anyhow::Error> {
    let seed = [42u8; 32];
    let k = 4;
    let write_golden = std::env::args().any(|a| a == "--write-golden");

    eprintln!("[1/4] generating KZG params (k={k}) + StandardPlonk witness…");
    let v = generate_test_vector(k, seed)?;

    eprintln!(
        "[2/4] outputs:  vk={} B   proof={} B",
        v.vk_bytes.len(),
        v.proof_bytes.len()
    );

    eprintln!("[3/4] running halo2_solana_verifier::verify (host arkworks emulation of syscalls)…");
    let public_inputs: Vec<[u8; 32]> = Vec::new();
    let result = halo2_solana_verifier::verify(
        &v.vk_bytes,
        &v.proof_bytes,
        &public_inputs,
        &v.kzg_vk,
    );

    // Optional oracle-truth recomputation in halo2curves. Off by default;
    // enable with `SHADOW_DUMP=1 cargo run …` when investigating SHPLONK
    // regressions. The shadow re-derives every Fr/G1 intermediate value and
    // runs an independent halo2curves pairing test.
    if std::env::var("SHADOW_DUMP").is_ok() {
        eprintln!("[3b] shadow recomputation in halo2curves Fr (oracle truth):");
        if let Err(e) = standard_plonk_circuit::shadow::shadow_dump(&v.halo2_vk, &v.proof_bytes, v.g2_one, v.g2_tau) {
            eprintln!("    shadow dump failed: {e}");
        }
    }

    eprintln!("[4/4] verifier returned: {result:?}");

    if write_golden && matches!(result, Ok(true)) {
        write_golden_vector(&v.vk_bytes, &v.proof_bytes, &v.kzg_vk)?;
    }

    match result {
        Ok(true)  => { eprintln!("✓ proof verified end-to-end"); Ok(()) }
        Ok(false) => Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e)    => Err(anyhow::anyhow!("verifier error: {e}")),
    }
}

/// Layout: 8B magic "GLDN0001" || u32 LE vk_len || vk_bytes ||
///         u32 LE proof_len || proof_bytes || 64 g1_one || 128 g2_one || 128 g2_tau
/// Total = 12 + vk_len + 4 + proof_len + 320.
fn write_golden_vector(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    kzg_vk: &halo2_solana_verifier::kzg::KzgVk,
) -> Result<(), anyhow::Error> {
    use std::{fs, io::Write, path::Path};
    let path = Path::new("circuits/standard-plonk/tests/golden_v1.bin");
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(16 + vk_bytes.len() + proof_bytes.len() + 320);
    buf.extend_from_slice(b"GLDN0001");
    buf.extend_from_slice(&(vk_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(vk_bytes);
    buf.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(proof_bytes);
    buf.extend_from_slice(&kzg_vk.g1_one.0);
    buf.extend_from_slice(&kzg_vk.g2_one.0);
    buf.extend_from_slice(&kzg_vk.g2_tau.0);

    let mut f = fs::File::create(path)?;
    f.write_all(&buf)?;
    eprintln!("[+] wrote golden test vector → {} ({} B)", path.display(), buf.len());
    Ok(())
}
