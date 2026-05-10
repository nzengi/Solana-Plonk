//! BPF CU benchmark grid for the `alt_bn128_g1_msm` SIMD proposal.
//!
//! Two MSM strategies are exercised:
//!
//!  * **mode 2 (`syscall-seq`)** — the verifier's *actual* path today: per-
//!    point `alt_bn128_g1_multiplication_be` + `alt_bn128_g1_addition_be`
//!    syscalls.
//!  * **mode 1 (`pippenger-bpf`)** — pure-BPF Pippenger window-NAF MSM
//!    (the `g1-msm-ref` crate). Demonstrates that Pippenger in pure BPF
//!    is **not viable** without the SIMD: BPF heap is exhausted at n ≥ 8
//!    because each window allocates a 64-entry `Vec<G1Projective>`. The
//!    SIMD lands the same algorithm in native code where heap is not a
//!    limit and field arithmetic is ~1000× cheaper.
//!  * Also included: pure-BPF arkworks naive (mode 0) for comparison —
//!    same result as Pippenger BPF: scales linearly off-chain but eats
//!    50M+ CU on BPF, useless on mainnet.
//!
//! For n > 4 the Pippenger and naive BPF modes either blow the heap or
//! the per-tx CU cap; we mark those rows accordingly. Mode 2 is the only
//! viable on-chain path today, and that's exactly the cost the proposed
//! SIMD displaces.
//!
//! Run with:
//! ```bash
//! cargo build-sbf -- -p g1-msm-bench-program --features bpf-entrypoint
//! cargo test -p g1-msm-bench-program --test cu_grid -- --nocapture
//! ```

use ark_bn254::{Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::{rand::SeedableRng, UniformRand};

use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_account::Account;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
};

const PROGRAM_NAME: &str = "g1_msm_bench_program";
/// `n` grid: covers our verifier's actual MSM sizes (the largest rotation
/// set in our k=4 StandardPlonk has 13 commits; we extend to 64 to show
/// the asymptotic shape).
const NS: &[usize] = &[2, 4, 8, 16, 32, 64];

fn build_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    let g = G1Projective::generator();
    let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let points: Vec<_>   = scalars.iter()
        .map(|s| (g * Fr::rand(&mut rng) * s).into_affine())
        .collect();

    let mut buf = Vec::with_capacity(4 + n * 96);
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    for s in &scalars {
        let mut le = [0u8; 32];
        s.serialize_with_mode(&mut le[..], Compress::No).unwrap();
        let mut be = le; be.reverse();
        buf.extend_from_slice(&be);
    }
    for p in &points {
        let mut out = [0u8; 64];
        if !p.is_zero() {
            let (x, y) = p.xy().unwrap();
            let mut x_le = [0u8; 32]; let mut y_le = [0u8; 32];
            x.serialize_with_mode(&mut x_le[..], Compress::No).unwrap();
            y.serialize_with_mode(&mut y_le[..], Compress::No).unwrap();
            for i in 0..32 { out[i] = x_le[31 - i]; out[32 + i] = y_le[31 - i]; }
        }
        buf.extend_from_slice(&out);
    }
    buf
}

#[test]
fn cu_grid() {
    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    let data_acct = Pubkey::new_unique();
    let max_payload = 4 + 64 * 96;
    let max_total   = 1 + max_payload;
    let rent = Rent::default().minimum_balance(max_total);

    eprintln!();
    eprintln!("BPF MSM benchmark — k=4 StandardPlonk verifier's MSM range is n ≈ 2..16.");
    eprintln!("Pippenger and naive BPF modes blow the heap above small n; only the");
    eprintln!("syscall-sequential path is viable on-chain today.");
    eprintln!();
    eprintln!("|  n |       syscall-seq |    pippenger-bpf |   naive-bpf  | proposed-SIMD¹ | sysc/SIMD |");
    eprintln!("|---:|------------------:|-----------------:|-------------:|---------------:|----------:|");

    for &n in NS {
        let payload = build_payload(n, n as u64 * 1024);

        let cu_for_mode = |mode: u8| -> Option<u64> {
            let mut acct_data = Vec::with_capacity(1 + payload.len());
            acct_data.push(mode);
            acct_data.extend_from_slice(&payload);
            let acct = Account {
                lamports: rent,
                data: acct_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            };
            let ix = Instruction {
                program_id,
                accounts: vec![AccountMeta::new_readonly(data_acct, false)],
                data: vec![],
            };
            let result = mollusk.process_instruction(&ix, &[(data_acct, acct)]);
            match result.program_result {
                ProgramResult::Success => Some(result.compute_units_consumed),
                _ => None,
            }
        };

        let sysc = cu_for_mode(2);
        let pipp = cu_for_mode(1);
        let naive = cu_for_mode(0);

        // Proposed SIMD CU model (cf. SIMD draft):  base + n × per_point
        // base = 4000, per_point = 2400 (Pippenger amortised, native code).
        let proposed_simd: u64 = 4_000 + (n as u64) * 2_400;

        fn fmt(o: Option<u64>) -> String {
            match o {
                Some(v) => format!("{:>16}", v),
                None    => format!("{:>16}", "OOM/CU"),
            }
        }
        let ratio = match sysc {
            Some(v) => format!("{:>8.2}×", (v as f64) / (proposed_simd as f64)),
            None    => "      —".to_string(),
        };
        eprintln!(
            "| {:2} |  {} | {} | {} | {:>14} | {} |",
            n, fmt(sysc), fmt(pipp), fmt(naive),
            proposed_simd, ratio,
        );
    }
    eprintln!();
    eprintln!("¹ Proposed SIMD CU model: base 4,000 + n × 2,400 (Pippenger amortised");
    eprintln!("  per-point cost in native code). Cf. SIMD draft section \"Detailed");
    eprintln!("  Design > CU cost\" for derivation.");
    eprintln!();
    eprintln!("Verifier hot path (k=4 StandardPlonk):");
    eprintln!("  - shplonk::verify_opening does 13 G1 muls in the rs[0] inner loop,");
    eprintln!("    plus 3 lagrange-interp G1 ops in rs[1]/rs[2], plus 3 outer adds.");
    eprintln!("  - Total today (sequential syscall): see the cu_profile.md row.");
    eprintln!("  - With this SIMD: a single batched MSM call replaces the inner");
    eprintln!("    loop, removing per-call fixed costs and enabling the native");
    eprintln!("    Pippenger speedup that BPF can't reach.");
    eprintln!();
}
