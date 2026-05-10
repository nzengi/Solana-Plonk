# Halo2 Verifier on Solana — CU Profile & SIMD Case

**A working PSE-Halo2 BN254/KZG/SHPLONK verifier on Solana BPF, end-to-end measured, devnet-deployed, cap-bound.**

This document presents the per-stage compute-unit profile of a real Halo2 verifier running on the Solana BPF VM, the on-chain transactions that demonstrate the bottleneck, and the case for a `alt_bn128_g1_msm` SIMD as the highest-leverage cure.

The numbers are not synthetic. They come from:
- a Mollusk-driven SVM benchmark with `sol_log_compute_units_` checkpoints between every verifier stage;
- a devnet transaction that submits the same proof to a deployed `.so` and aborts at Solana's per-tx CU ceiling.

---

> Companion: [`docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md`](simd-proposals/simd-XXXX-alt-bn128-g1-msm.md) — the formal SIMD draft this profile motivates.

## 1. Executive summary

| Number | What it is |
|---|---|
| **2,710,424 CU** | Total cost to verify a k=4 StandardPlonk proof on BPF (Mollusk). |
| **1,399,644 CU** | What the on-chain devnet tx consumed before hitting the 1.4M ceiling. |
| **1,667,016 CU = 62%** | Cost of `shplonk::verify_opening` alone. |
| **533,709 CU = 20%** | Cost of `lagrange::evaluate_lagrange` (5 Fr inverses). |
| **49,546 CU = 2%** | Cost of the final `alt_bn128_pairing` syscall (already a syscall — optimal). |

The 62% chunk is **~25 sequential `alt_bn128_g1_multiplication` syscalls** inside the SHPLONK reduction. A single batched-MSM syscall would amortise the per-call overhead and is the cleanest unblocker.

---

## 2. Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Off-chain (Rust)                                                   │
│                                                                    │
│  StandardPlonk circuit  ──►  PSE-Halo2 prover  ──►  proof bytes    │
│  (halo2_proofs v0.3)         (KeccakBeWrite                        │
│                              transcript)                           │
│                                  │                                 │
│                                  ▼                                 │
│  compile_vk():  halo2 VerifyingKey  ──►  632-byte flat VK          │
│                                                                    │
│  KzgVk = (g1_one, g2_one, g2_tau)  pulled from ParamsKZG           │
└────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Devnet helper (clients/devnet-send)                                │
│                                                                    │
│  tx_create:  system_instruction::create_account(data_acct, 2312 B) │
│  tx_load×3:  program LOAD ix → memcpy chunks into data_acct.data   │
│  tx_verify:  ComputeBudget(limit=1.4M, heap=256KB) + program       │
│              VERIFY ix reading from data_acct                      │
└────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ On-chain BPF (programs/verifier-program, Pinocchio)                │
│                                                                    │
│  parse_vk → read_proof → lagrange → expected_h_eval                │
│           → h_commit → omega_last → build_queries                  │
│           → shplonk::verify_opening → alt_bn128_pairing            │
│                                                                    │
│  All Fr/G1 arithmetic via arkworks-bn254 (pure Rust BPF) +         │
│  alt_bn128 syscalls for G1/G2 add+mul and the final pairing.       │
└────────────────────────────────────────────────────────────────────┘
```

---

## 3. CU breakdown (Mollusk, per-stage)

Measured by inserting `sol_log_compute_units_` between every stage of `verify()` (`stage-trace` cargo feature). Runtime configuration: `compute_unit_limit = 1B` (artificial — to observe full cost), `heap_size = 256 * 1024` (mainnet-equivalent `request_heap_frame`).

| Stage                               |       CU |    % | Source of cost |
|-------------------------------------|---------:|-----:|---|
| entry overhead                      |      384 | <1%  | Pinocchio entrypoint deserialization |
| `parse_vk`                          |   10,168 | <1%  | 632-byte flat VK parse |
| `read_proof`                        |  258,633 | 10%  | 8 challenges × `keccak256` + Fr/G1 reads + modulus checks |
| `lagrange::evaluate_lagrange`       |  533,709 | 20%  | 5 Fr inverses, one inverse ≈ 100k CU big-int math |
| `compute_expected_h_eval`           |  156,502 |  6%  | 1 gate expr + 7 perm exprs + Horner fold + 1 inverse |
| `aggregate_h_commitment`            |   15,724 | <1%  | 2× `alt_bn128_g1_mul` + 1× `alt_bn128_g1_add` |
| `omega_last`                        |   11,531 | <1%  | Pure-BPF Fr exponentiation (`pow_u64`) |
| `build_queries`                     |    7,229 | <1%  | 21-query construction (struct copies + Fr arith) |
| **`shplonk::verify_opening`**       | **1,667,016** | **62%** | **~25× `alt_bn128_g1_mul` + 3× lagrange interp + Fr coefficient combination** |
| `alt_bn128_pairing` (2 pairs)       |   49,546 |  2%  | Single syscall, 36,364 + 12,121 CU + sha256 base + I/O |
| **TOTAL**                           | **2,710,424** | 100% |       |

### Why SHPLONK is 62%

`shplonk::verify_opening` performs the BDFG21 reduction: for each rotation set, it computes `inner_msm = Σⱼ y^j · Cⱼ` and `r_inner = Σⱼ y^j · rⱼ(u)`, then accumulates `outer_msm += v^i · z_diff_i · inner_msm` and adds `−r_outer·[1]_1 − z_0·h1 + u·h2`. For a 3-rotation-set, 13-commit case (StandardPlonk k=4 with permutation collisions) this is ~25 sequential `alt_bn128_g1_multiplication` syscalls plus their G1 additions, plus three O(n²) Lagrange interpolations.

Each `alt_bn128_g1_mul` costs 3,840 CU. 25 calls = ~96k CU **just for the syscall fixed cost**. The remaining ~1.57M is Fr coefficient computation + G1 affine handling overhead inside the verifier.

A `alt_bn128_g1_msm_be(scalars: &[Fr], points: &[G1Affine]) -> G1Affine` syscall using a Pippenger window-NAF reference implementation would collapse the 25 muls into one batched call, amortising the per-point fixed cost. Conservative estimate: **30–50% reduction on `shplonk::verify_opening`**, translating to ~500k–800k CU off the total.

### Why Lagrange is 20%

`evaluate_lagrange` computes `L_0(x)`, `L_last(x)`, `L_blind(x)` and `xⁿ`. With `blinding_factors=5`, the `L_blind` accumulator runs 5 iterations, each requiring a Fr inverse `(x − ω⁻ⁱ).invert()`. Plus the `L_0` denominator inverse. That's 6 inverses, plus `xⁿ` exponentiation (k iterations of square+multiply for k=4).

Arkworks `Fr::inverse()` is constant-time Montgomery extended-Euclidean — pure Rust 256-bit big-integer arithmetic compiled to BPF, no native syscall. Empirically each inverse costs **~100k CU** on BPF. That's the lower-hanging fruit for a `alt_bn128_fr_arith` SIMD ask.

---

## 4a. Projected impact of `alt_bn128_g1_msm` (SIMD-XXXX)

The verifier's actual MSM call count is **19 G1 muls + 15 G1 adds** across the SHPLONK reduction's three rotation sets and the final outer-msm append. Applying the cost model from the [SIMD draft](simd-proposals/simd-XXXX-alt-bn128-g1-msm.md) — `cost(n) = 4000 + n × 2400` — to a single batched-MSM call at n = 19 (or three batched calls of size 13/2/1 + 3, depending on implementation):

| Quantity | Today | With SIMD-XXXX | Δ |
|---|---:|---:|---:|
| Syscall-layer CU (just G1 muls + adds) | ~78,000 | ~50,000 | −36% |
| `shplonk::verify_opening` total | 1,667,016 | ~1,140,000* | **−32%*** |
| Verifier total | 2,710,424 | ~2,180,000* | **−20%*** |

*The shplonk-level saving is composed of (a) the syscall-layer saving above and (b) the verifier's per-iteration Fr coefficient overhead collapsing when MSM input prep is done once. (b) is implementation-dependent; the projection assumes a refactor that lifts the inner `coeff = v_powers[i] * z_diff_i * y_powers[j]` out of the per-point loop into a single MSM input-build pass. This branch is feasible — see "Layer 2 readiness" below — but not yet landed in the verifier.

The Mollusk bench grid in [`programs/g1-msm-bench`](../programs/g1-msm-bench/) confirms the syscall-layer figures: at n = 16 the sequential syscall path costs 70,180 CU, the proposed SIMD model 42,400 CU (1.66× ratio); at n = 32, 140,616 vs 80,800 (1.74× ratio).

### Layer 2 readiness

A `simd-msm` cargo feature in `crates/verifier` would route `kzg::shplonk::msm_g1` through `g1-msm-ref::alt_bn128_g1_msm_be` for host validation. On BPF, the same call would route through the syscall once activated. The on-chain verifier code path becomes:

```rust
// crates/verifier/src/syscalls.rs (proposed addition):
#[cfg(feature = "solana-syscalls")]
pub fn g1_msm_be(input: &[u8]) -> Result<[u8; 64], Error> {
    // Today: emulated by sequential g1_mul + g1_add (slow, what we have).
    // With SIMD-XXXX active: a single sol_alt_bn128_g1_msm_be() syscall.
    ...
}
```

The verifier-side change is local to `kzg::shplonk::msm_g1` and the helper above. No protocol change, no transcript change, no proof-format change.

## 5. Mainnet feasibility: today vs. with SIMDs

Solana per-tx hard cap is **1,400,000 CU**. Block-level cap is 48M. Heap can be raised to 256KB via `ComputeBudgetInstruction::request_heap_frame`, which is what the Pinocchio bump allocator needs. A heap raise itself is free at request time; rent comes from the data account.

| Configuration | Total CU | Fits in 1 tx? |
|---|---:|---|
| **As-is (today)** | 2,710,424 | ❌ aborts at 1.4M (devnet tx `3r1ZSg3D…`) |
| **+ `alt_bn128_g1_msm` SIMD (Layer 2)** | ~2.18M | ❌ closer, but still over — needs Layer 3 or 2-tx split |
| **+ `alt_bn128_fr_arith` SIMD (Layer 3)** | ~1.5M | ✅ fits with `set_compute_unit_limit(1.4M)` margin |
| **2-tx split + Layer 2 (Layer 1+2)** | 2 × <1.4M | ✅ Light-Protocol-style state-passed split |

The 2-tx split (Layer 1) is the operational fallback that needs no new SIMD. The verifier is broken into pre-shplonk (~1M CU) and shplonk-plus-pairing (~1.7M CU, still over 1.4M unless Layer 2 is also shipped). With Layer 2 alone, a single tx becomes plausible only with aggressive code trimming. With Layer 2 + Layer 3, the verifier fits in 1 tx with margin to spare.

---

## 5. Comparison with prior art

| Project | Proof system | Per-verify CU | Strategy |
|---|---|---:|---|
| `groth16-solana` (Light Protocol) | Groth16 | ~250k | Native — Groth16 is shape-light: 1 pairing, ~3 G1 ops |
| `sp1-solana` (Succinct) | STARK→Groth16 | ~250k | STARK proof wrapped in Groth16 off-chain, on-chain verifies the Groth16 |
| `risc0-solana` (RISC Zero) | STARK→Groth16 | ~250k | Same wrapper pattern as sp1-solana |
| **`halo2-solana-verifier` (this work)** | **PSE-Halo2 BN254/KZG/SHPLONK** | **2.71M** | **Native Halo2 verify (no Groth16 wrapper)** |

Halo2's higher cost is structural, not implementation slack:
- **N polynomial commits** vs. Groth16's small fixed set
- **Permutation argument** with grand-product polys (no Groth16 analogue)
- **2 opening proofs** in SHPLONK vs. 1 in Groth16
- **Lagrange evaluations** (Groth16 doesn't need them)
- **5 Fr inverses** vs. Groth16's 0

A Halo2-to-Groth16 wrapper would land at ~250k CU like sp1/risc0, but loses the property we want here: **native Halo2 verify on Solana**, no extra prover step, no off-chain Groth16 prover.

---

## 6. The SIMD proposal: `alt_bn128_g1_msm`

**Surface:**
```rust
/// Σᵢ scalarsᵢ · pointsᵢ over BN254 G1, using a Pippenger window-NAF
/// reference implementation. Scalars are 32-byte BE Fr; points are
/// 64-byte BE G1Affine (x ‖ y), identity = all-zero.
///
/// Input layout:  [n: u32 LE | scalar₀ | point₀ | scalar₁ | point₁ | …]
/// Total size:    4 + n × 96 bytes
/// Output:        64-byte BE G1Affine
fn alt_bn128_g1_msm_be(input: &[u8]) -> Result<[u8; 64], Error>;
```

**CU cost model (proposal):**
- Base: 4,000 CU (similar to existing `alt_bn128_g1_add` overhead × 2)
- Per-point: 2,400 CU (vs. 3,840 for individual `alt_bn128_g1_multiplication`)
- Window optimisation: ~30% saving over naive double-and-add at n ≥ 8

For `n = 25` (our shplonk hot path):
- Today: 25 × 3,840 + 24 × 334 (G1 add) = 104,016 CU **just syscall fixed cost**
- With MSM: 4,000 + 25 × 2,400 = 64,000 CU
- Savings on the syscall layer alone: ~40,000 CU
- The bigger win: **the verifier's per-iteration Fr coefficient computation collapses too**, because it's currently structured around per-point loops. With MSM input prep done once, ~500k CU comes off the verifier-side overhead.

**Reference implementation:** This crate's `kzg::shplonk::msm_g1` (sequential) becomes the "before" baseline. A drop-in `alt_bn128_g1_msm` Pippenger using halo2curves's `multiexp` (or `arkworks-msm`) is the "after".

**Why this is the right SIMD to land first:**
1. Highest measured leverage (62% of our verifier).
2. Universal: every BN254 ZK system on Solana uses G1 MSM (Groth16, Halo2, future Plonk variants).
3. Reference implementation already exists in halo2curves; spec is a thin wrapper around it.
4. Cost model is straightforward: linear in `n` with a small constant from window setup.

A second SIMD, `alt_bn128_fr_arith` (Fr add/mul/inverse), is the natural follow-up — it removes the lagrange + Fr-coefficient overhead, which together account for ~25% of remaining CU after Layer 2.

---

## 7. Replay instructions

Everything in this document is reproducible. The off-chain prover, BPF program, Mollusk benchmarks, and devnet artifacts all live in this repository.

### Reproduce the local Mollusk number

```bash
# 1. Generate the golden test vector (off-chain prover + verifier round-trip).
cargo run -p standard-plonk-circuit --bin gen-proof -- --write-golden

# 2. Build the BPF program.
cargo build-sbf -- -p halo2-solana-verifier-program --features bpf-entrypoint

# 3. Run Mollusk with stage-trace to get the per-stage CU breakdown.
cargo build-sbf -- -p halo2-solana-verifier-program --features bpf-entrypoint,stage-trace
cargo test -p halo2-solana-verifier-program \
  --features bpf-entrypoint,stage-trace \
  --test cu_bench -- --nocapture
```

The output prints `[stage] after …` lines from the program log alongside `Program consumption: X units remaining`, which is the Mollusk-side CU reading.

### Replay the devnet evidence

```bash
solana confirm -v 3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5 -u devnet
```

Or via explorer:
- Verify tx (1.4M cap abort): https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet
- Program: https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet
- Data account: https://explorer.solana.com/address/HvRcK2dg5LJzxHscdpozsZpHaRDhkVN6exYiwLVtgNkA?cluster=devnet

### Run a fresh devnet roundtrip

```bash
# Requires ~5 SOL devnet in your default keypair (~/.config/solana/id.json).
cargo run -p devnet-send
```

This generates a fresh data account, chunks the golden vector into LOAD txs, then submits the verify tx with `set_compute_unit_limit(1_400_000)` and `request_heap_frame(256_000)`.

---

## 8. Repo layout

| Path | What's there |
|---|---|
| `crates/verifier/`               | The verifier itself (no_std, BN254-only, ~3kLOC) |
| `crates/vk-host/`                | Off-chain helper that compiles halo2 `VerifyingKey` to flat on-chain bytes |
| `circuits/standard-plonk/`       | Test circuit + halo2 prover + golden-vector emitter |
| `programs/verifier-program/`     | Pinocchio entrypoint wrapping the verifier crate |
| `programs/verifier-program/tests/cu_bench.rs` | Mollusk-driven CU benchmark |
| `clients/devnet-send/`           | Off-chain client for the devnet roundtrip |
| `docs/cu_profile.md`             | This document |

---

## 9. Status & roadmap

| Phase | Status |
|---|---|
| ✅ v1: working Halo2 verifier (StandardPlonk-specialised gate) | Done |
| ✅ Mollusk per-stage CU profile | Done |
| ✅ Devnet deploy + verify-attempt tx | Done |
| ⏳ `alt_bn128_g1_msm` SIMD draft + benchmarks | Open |
| ⏳ v1.5: gate-AST evaluator (any halo2 circuit, not just StandardPlonk) | Open |
| ⏳ `alt_bn128_fr_arith` SIMD draft | Open |
| ⏳ Application layer: cypherpunk app on top of the verifier | Open |

---

## License

MIT OR Apache-2.0, matching the workspace.

## Author / contact

Independent applied-cryptography work. Reach out via the repo if Anza or the Solana Foundation wants to discuss the SIMD proposal or sponsor the v1.5 generalisation.
