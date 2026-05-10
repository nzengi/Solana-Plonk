//! End-to-end smoke test for the bound-range-check circuit.
//!
//! Generates a proof bound to a fixed payer pubkey (32-byte test seed),
//! runs the host-side verifier on it, optionally writes a golden vector
//! for downstream programs / Mollusk benches, optionally runs the
//! differential audit (--shadow-audit) which also exercises the
//! claimer-substitution attack.

use bound_range_check_circuit::{generate_brc_test_vector, prover::pubkey_to_claimer_hash};
use halo2_solana_verifier::field::fr_from_bytes_be;
use std::path::PathBuf;

fn main() -> Result<(), anyhow::Error> {
    let seed = [42u8; 32];
    let k = 6;

    // Default test payer pubkey: a fixed 32-byte pattern — easily spotted
    // in tx logs. The real on-chain client would substitute the actual
    // signer's Pubkey here.
    let payer_pubkey: [u8; 32] = [0xAB; 32];
    let x_value: u64 = 7; // any value in [0, 16)

    let write_golden = std::env::args().any(|a| a == "--write-golden");
    let shadow_audit = std::env::args().any(|a| a == "--shadow-audit");

    eprintln!("[1/4] generating KZG params (k={k}) + bound-range-check witness…");
    let v = generate_brc_test_vector(k, seed, &payer_pubkey, x_value)?;

    eprintln!(
        "[2/4] outputs:  vk={} B   proof={} B",
        v.vk_bytes.len(), v.proof_bytes.len(),
    );
    eprintln!("       claimer_hash (BE) = 0x{}", hex_lite(&v.claimer_hash_be));

    eprintln!("[3/4] running halo2_solana_verifier::verify…");
    let public_inputs: Vec<[u8; 32]> = vec![v.claimer_hash_be];
    let result = halo2_solana_verifier::verify(
        &v.vk_bytes, &v.proof_bytes, &public_inputs, &v.kzg_vk,
    );
    eprintln!("[4/4] verifier returned: {result:?}");

    // Sanity: re-derive claimer_hash from the same pubkey, confirm it matches
    // the public input — guards against off-by-one bugs in the binding.
    let (derived_fr, derived_be) = pubkey_to_claimer_hash(&payer_pubkey);
    if derived_be != v.claimer_hash_be {
        anyhow::bail!("claimer_hash derivation mismatch — circuit / prover diverged");
    }
    let _ = derived_fr;
    let _ = fr_from_bytes_be(&v.claimer_hash_be).expect("claimer_hash must be canonical Fr");

    if write_golden && matches!(result, Ok(true)) {
        write_golden_vector(&v, &public_inputs)?;
    }

    if shadow_audit && matches!(result, Ok(true)) {
        bound_range_check_circuit::shadow::audit(&v.params, &v)?;
    }

    match result {
        Ok(true)  => { eprintln!("✓ bound-range-check proof verified end-to-end"); Ok(()) }
        Ok(false) => Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e)    => Err(anyhow::anyhow!("verifier error: {e}")),
    }
}

fn hex_lite(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{x:02x}")); }
    s
}

fn write_golden_vector(
    v: &bound_range_check_circuit::prover::BrcTestVector,
    public_inputs: &[[u8; 32]],
) -> Result<(), anyhow::Error> {
    use std::{fs, io::Write};
    let path = PathBuf::from("circuits/bound-range-check/tests/golden_v2_brc.bin");
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
    eprintln!("[+] wrote bound-range-check golden vector → {} ({} B)", path.display(), buf.len());
    Ok(())
}
