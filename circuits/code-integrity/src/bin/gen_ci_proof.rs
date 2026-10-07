//! Generate a PRUV code-integrity proof, run the host verifier, optionally write
//! the GLDN0002 golden blob for the Mollusk CU bench.
//!
//!   cargo run --release -p code-integrity-circuit --bin gen-ci-proof -- \
//!     --program-id 3oCMjxiXMorGrFUrFqYUmpfwG1FMLaLBWJBh6pVRcLqJ \
//!     --hash 7172010e98852be1224a508cd2b8bd1ecd83981342d77aa52c329afcf05def3c \
//!     [--srs ~/Desktop/PRUV/srs/kzg_bn254_14.srs] [--k 10] \
//!     [--expect-commitment 37a4b69f…] [--write-golden circuits/code-integrity/tests/golden_ci.bin]
use code_integrity_circuit::{fr_to_bytes_le, generate_ci_test_vector, CiTestVector};
use std::path::PathBuf;

fn keccak(b: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(b).into()
}

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn main() -> Result<(), anyhow::Error> {
    let pid_s = arg("--program-id").unwrap_or_else(|| "3oCMjxiXMorGrFUrFqYUmpfwG1FMLaLBWJBh6pVRcLqJ".into());
    let hash_s = arg("--hash").unwrap_or_else(|| "7172010e98852be1224a508cd2b8bd1ecd83981342d77aa52c329afcf05def3c".into());
    let k: u32 = arg("--k").map(|s| s.parse()).transpose()?.unwrap_or(10);
    let srs = arg("--srs");
    let program_id: [u8; 32] = bs58::decode(&pid_s).into_vec()?.as_slice().try_into()?;
    let program_hash: [u8; 32] = hex::decode(&hash_s)?.as_slice().try_into()?;

    eprintln!("[1/4] params (k={k}, srs={}), keygen, prove…", srs.as_deref().unwrap_or("insecure setup"));
    let v: CiTestVector = generate_ci_test_vector(k, srs.as_deref(), &program_id, &program_hash)?;
    let commitment = hex::encode(fr_to_bytes_le(&v.instances[3]));
    eprintln!("[2/4] vk={} B  proof={} B  commitment(LE)={}", v.vk_bytes.len(), v.proof_bytes.len(), commitment);
    // Hashes the on-chain verifier binds to (keccak256, as compute_replay_hashes does).
    let vk_keccak = hex::encode(keccak(&v.vk_bytes));
    let proof_keccak = hex::encode(keccak(&v.proof_bytes));
    eprintln!("       vk_keccak={vk_keccak}  proof_keccak={proof_keccak}");
    if let Some(exp) = arg("--expect-commitment") {
        anyhow::ensure!(exp.eq_ignore_ascii_case(&commitment), "commitment mismatch: expected {exp}, got {commitment}");
        eprintln!("       ✓ commitment equals PRUV's native compute_poseidon_commitment");
    }

    eprintln!("[3/4] halo2_solana_verifier::verify (host)…");
    let result = halo2_solana_verifier::verify(&v.vk_bytes, &v.proof_bytes, &v.public_inputs_be, &v.kzg_vk);
    eprintln!("[4/4] verifier returned: {result:?}");

    // Negative control: a tampered public input must be rejected.
    let mut bad = v.public_inputs_be.clone();
    bad[3][31] ^= 1;
    let bad_res = halo2_solana_verifier::verify(&v.vk_bytes, &v.proof_bytes, &bad, &v.kzg_vk);
    anyhow::ensure!(!matches!(bad_res, Ok(true)), "verifier accepted a tampered commitment");
    eprintln!("       ✓ tampered commitment rejected ({bad_res:?})");

    if let Some(path) = arg("--write-golden") {
        if matches!(result, Ok(true)) {
            let path = PathBuf::from(path);
            if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
            let mut buf: Vec<u8> = Vec::new();
            buf.extend_from_slice(b"GLDN0002");
            buf.extend_from_slice(&(v.vk_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&v.vk_bytes);
            buf.extend_from_slice(&(v.proof_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&v.proof_bytes);
            buf.extend_from_slice(&v.kzg_vk.g1_one.0);
            buf.extend_from_slice(&v.kzg_vk.g2_one.0);
            buf.extend_from_slice(&v.kzg_vk.g2_tau.0);
            buf.extend_from_slice(&(v.public_inputs_be.len() as u32).to_le_bytes());
            for pi in &v.public_inputs_be { buf.extend_from_slice(pi); }
            std::fs::write(&path, &buf)?;
            eprintln!("[+] wrote golden → {} ({} B)", path.display(), buf.len());
        }
    }
    if arg("--json").is_some() || std::env::args().any(|a| a == "--json") {
        println!("{{\"vk_keccak\":\"{vk_keccak}\",\"proof_keccak\":\"{proof_keccak}\",\"commitment_le\":\"{commitment}\",\"proof_len\":{},\"vk_len\":{}}}", v.proof_bytes.len(), v.vk_bytes.len());
    }
    match result {
        Ok(true) => { eprintln!("✓ code-integrity proof verified end-to-end (host)"); Ok(()) }
        Ok(false) => Err(anyhow::anyhow!("verifier returned Ok(false)")),
        Err(e) => Err(anyhow::anyhow!("verifier error: {e}")),
    }
}
