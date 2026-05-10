//! End-to-end smoke test for the Fibonacci circuit through `halo2-solana-verifier`.

use fibonacci_circuit::generate_fib_test_vector;
use halo2_solana_verifier::field::fr_to_bytes_be;
use std::path::PathBuf;

fn main() -> Result<(), anyhow::Error> {
    let seed = [42u8; 32];
    let k = 4;
    let write_golden = std::env::args().any(|a| a == "--write-golden");

    eprintln!("[1/4] generating KZG params (k={k}) + Fibonacci witness…");
    let v = generate_fib_test_vector(k, seed)?;

    eprintln!(
        "[2/4] outputs:  vk={} B   proof={} B   target={}",
        v.vk_bytes.len(), v.proof_bytes.len(), display_fr(&v.target),
    );

    eprintln!("[3/4] running halo2_solana_verifier::verify…");
    let public_inputs: Vec<[u8; 32]> = vec![fr_to_bytes_be(&ark_target(&v.target))];
    let result = halo2_solana_verifier::verify(
        &v.vk_bytes, &v.proof_bytes, &public_inputs, &v.kzg_vk,
    );
    eprintln!("[4/4] verifier returned: {result:?}");

    if write_golden && matches!(result, Ok(true)) {
        write_golden_vector(&v, &public_inputs)?;
    }

    match result {
        Ok(true)  => { eprintln!("✓ Fibonacci proof verified end-to-end"); Ok(()) }
        Ok(false) => Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e)    => Err(anyhow::anyhow!("verifier error: {e}")),
    }
}

/// Cross-library convert: halo2curves Fr → arkworks Fr (both BN254 scalars,
/// canonical BE bytes are the bridge).
fn ark_target(t: &halo2curves::bn256::Fr) -> ark_bn254::Fr {
    use halo2curves::ff::PrimeField;
    let mut le = t.to_repr();
    le.as_mut().reverse();
    let mut be = [0u8; 32];
    be.copy_from_slice(le.as_ref());
    halo2_solana_verifier::field::fr_from_bytes_be(&be)
        .expect("Fibonacci target is canonical Fr")
}

fn display_fr(t: &halo2curves::bn256::Fr) -> String {
    use halo2curves::ff::PrimeField;
    let le = t.to_repr();
    let mut be = le.clone();
    be.as_mut().reverse();
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in be.as_ref() { s.push_str(&format!("{b:02x}")); }
    s
}

fn write_golden_vector(
    v: &fibonacci_circuit::prover::FibTestVector,
    public_inputs: &[[u8; 32]],
) -> Result<(), anyhow::Error> {
    use std::{fs, io::Write, path::Path};
    let path = PathBuf::from("circuits/fibonacci/tests/golden_v15_fib.bin");
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let _ = Path::new(&path);

    // Layout: same magic-prefixed format as standard-plonk's golden_v1.bin,
    // plus a public-inputs section.
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
    eprintln!("[+] wrote Fibonacci golden vector → {} ({} B)", path.display(), buf.len());
    Ok(())
}
