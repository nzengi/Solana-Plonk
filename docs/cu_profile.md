# Halo2 Verifier on Solana — CU Profile, On-Chain Evidence, and SIMD Case

This document describes a PSE-Halo2 (BN254 / KZG / SHPLONK) proof
verifier running on Solana BPF: per-stage CU profile, the devnet
transactions backing each claim, the host-side audit shadow, and the
two SIMDs the cost profile still points to (with one of them now
partially addressed in software via the Path B refactor). Numbers
come from Mollusk SVM benchmarks with `sol_log_compute_units_`
checkpoints between every verifier stage and from devnet roundtrips
that submit the same proof bytes to a deployed `.so`.

Companion: [`docs/simd-proposals/`](simd-proposals/) — formal drafts
for `alt_bn128_g1_msm` (Layer 2) and `alt_bn128_fr_batch_inverse`
(Layer 3).

## The numbers (post-Path-B v2.1 binary)

| Circuit | 1-tx Mollusk CU | 1-tx fits 1.4 M? | 3-tx total | On-chain (1-tx) |
|---|---:|:---:|---:|---:|
| StandardPlonk (k=4) | 1,672,427 | no | 2,211,249 | n/a — 3-tx flow today |
| Fibonacci (k=4) | 1,653,156 | no | 2,065,296 | **2,065,128 on devnet** |
| Multi-lookup (k=6, 2 Plookup) | 1,508,493 | no | 1,960,366 | n/a — 3-tx flow today |
| Bound-range-check (k=8) | 1,609,953 | no | 2,043,545 | n/a — 3-tx flow today |
| Range-check (k=6, 1 Plookup) | **1,294,206** | **yes** | 1,629,280 | (was 1.69 M pre-Path-B) |
| **Shuffle (k=5)** | **1,123,442** | **yes** | 1,409,982 | **1,372,980 pre-Path-B v2.0** |

Two things to read off this table:

1. **Shuffle and range-check now fit in a single tx.** Shuffle was the
   1.37 M headline at v2.0 launch; range-check needed the 2-tx split.
   After Path B (Montgomery batched inverse + cached Lagrange basis in
   `kzg::shplonk`), both fit 1-tx with margin.
2. **Every other reference circuit fits the 3-tx flow.** The biggest
   single stage across all six circuits is StandardPlonk's STAGE1 at
   1.008 M — 392 k slack under the 1.4 M cap. Fibonacci is the only
   3-tx circuit currently confirmed on devnet (next section).

For the historical context — the pre-Path-B v2.0 binary numbers were
StandardPlonk 2.71 M, Fibonacci 2.28 M, multi-lookup 2.29 M, range-check
1.69 M, shuffle 1.37 M. Every reference circuit got 18–39 % cheaper
after Path B; the SHPLONK opening stage alone dropped ~50 % on
Fibonacci-shape circuits.

## Per-stage breakdown

### 3-tx flow (Fibonacci, Mollusk + on-chain)

The three transactions that make up the Fibonacci 3-tx verify, with
both Mollusk and on-chain CU. The 56-unit per-stage gap is constant
tx-dispatch overhead.

| Stage | Mollusk CU | On-chain CU | What runs |
|---|---:|---:|---|
| STAGE1   | 1,045,418 | 1,045,362 | `parse_vk + read_proof + lagrange::evaluate_lagrange + compute_expected_h_eval + aggregate_h_commitment + omega_last` → writes `Stage1Output` PDA |
| STAGE2A  |   792,662 |   792,606 | `parse_proof_no_fs + build_queries + shplonk::build_shplonk_msm_terms` (Path B phase 1, Fr-only) → writes `Stage2Output` PDA |
| STAGE3   |   227,216 |   227,160 | `shplonk::finalize_shplonk_pairs` (one G1 MSM via N × `alt_bn128_g1_multiplication_be`) + `alt_bn128_pairing` |
| **total** | **2,065,296** | **2,065,128** | replay-bound by two PDAs + three keccak hashes carried STAGE1 → STAGE2A → STAGE3 |

What's notable about STAGE3: **it does not read the data account.**
`Stage2Output` carries the persisted KZG VK G2 fields (`g2_one`,
`g2_tau`), so STAGE3 only needs the PDA + signer. Soundness is then a
function of (a) program ownership of the PDA, (b) the payer-binding
signature check, (c) the nonce match, and (d) the three hashes that
were validated at STAGE1 → STAGE2A and forwarded into Stage2Output.

### 1-tx stage-trace (range-check, post-Path-B)

For the circuits that still fit 1-tx, the `stage-trace` cargo feature
emits `sol_log_compute_units_` between every verifier stage:

| Stage | CU (post-Path-B, range-check) | Notes |
|---|---:|---|
| `parse_vk` | ~11 k | unchanged |
| `read_proof` | ~149 k | unchanged |
| `lagrange::evaluate_lagrange` | ~542 k | unchanged (top-level Lagrange is not yet in the batched-inverse path) |
| `compute_expected_h_eval` | ~96 k | unchanged |
| `aggregate_h_commitment` | ~24 k | unchanged |
| `omega_last` | ~19 k | unchanged |
| `build_queries` | ~36 k | unchanged |
| `shplonk::verify_opening` | **~370 k** | **−394 k vs pre-Path-B** (was 764 k) |
| `alt_bn128_pairing` | ~50 k | unchanged |
| **total** | **~1,294 k** | down from ~1,692 k; fits 1.4 M cap |

The Path B win is concentrated in `shplonk::verify_opening`'s
rotation-set inner loop — see the
[Where the cost lives](#where-the-cost-lives--simd-case-after-path-b)
section for the algorithmic explanation.

## Where the cost lives → SIMD case (after Path B)

Before Path B, 77 % of cost lived in two stages:
`shplonk::verify_opening` (G1 MSM + Fermat inverses) and
`lagrange::evaluate_lagrange` (5 Fermat inverses). Path B addressed
the inverse cost inside `shplonk` in software:

- `shplonk::build_shplonk_msm_terms` (Path B phase 1) computes all
  per-rotation-set denominators in one pass, batches them into a
  single Fr vector, and inverts them all with one Fermat + 3(N−1) Fr
  muls (Montgomery's trick). Numerator polynomials are cached per
  rotation set, so commitments that share a point set use the same
  basis.
- On Fibonacci this turned ~60 Fermat inverses (×16 k CU each ≈ 960 k)
  into 1 Fermat + ~180 muls ≈ 556 k.

The two SIMD drafts in this repo are still worth shipping but for
narrower wins than before:

**`alt_bn128_g1_msm` (Layer 2)** — the SHPLONK MSM is still
`N × alt_bn128_g1_multiplication_be + N × alt_bn128_g1_addition_be`
syscall calls. A batched MSM amortises the per-syscall fixed cost.
Cost-model projection: −15 to −20 % total verify CU after Path B.
Reference impl in [`crates/g1-msm-ref/`](../crates/g1-msm-ref/),
bench grid in [`programs/g1-msm-bench/`](../programs/g1-msm-bench/),
formal draft at [`docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md`](simd-proposals/simd-XXXX-alt-bn128-g1-msm.md).

| n | sequential syscall | proposed-SIMD model | ratio |
|---:|---:|---:|---:|
| 4 | 17,356 | 13,600 | 1.28× |
| 8 | 34,964 | 23,200 | 1.51× |
| 16 | 70,180 | 42,400 | 1.66× |
| 32 | 140,616 | 80,800 | 1.74× |
| 64 | 281,494 | 157,600 | 1.79× |

A pure-BPF Pippenger implementation runs out of heap at n ≥ 16 even
with `request_heap_frame(256 KB)` — each window's bucket array is
2^c entries of `G1Projective`, and ~43 windows for 254-bit scalars
already pushes past the heap budget. So if you want batched G1 MSM
on Solana, it has to be a syscall.

**`alt_bn128_fr_batch_inverse` (Layer 3)** — originally the largest
win. Now mostly captured by Path B in software (Montgomery's trick
runs entirely in pure-BPF Fr math). A native syscall would still beat
the software version because per-Fr-mul costs ~3 k CU on BPF vs the
projected `4 000 + n × 200` for the syscall. Net additional save:
~400 k CU on top of Path B on Fibonacci-shape circuits. Reference
impl in [`crates/fr-batch-inv-ref/`](../crates/fr-batch-inv-ref/) (60
lines, 7/7 tests). Formal draft at
[`docs/simd-proposals/simd-XXXX-alt-bn128-fr-batch-inverse.md`](simd-proposals/simd-XXXX-alt-bn128-fr-batch-inverse.md).

| Layer combo | StandardPlonk verifier total CU | Fits 1-tx? |
|---|---:|---|
| v2.0 (no Path B, no SIMD) | 2,710,424 | no — aborts at 1.4 M |
| **v2.1 + Path B (today)** | **1,672,427** | **no, but 3-tx fits with margin** |
| + Layer 2 (G1 MSM) | ~1,400,000 | yes, on the edge |
| + Layer 2 + Layer 3 (Fr batch inverse syscall) | ~1,200,000 | yes, with margin |

**Today's mainnet path is the 3-tx split** — needs no new SIMDs and
every reference circuit's per-stage CU is comfortable. Layer 2 +
Layer 3 SIMDs would let the larger circuits collapse back into 1-tx,
but they're optimization rather than unblock at this point.

## On-chain evidence

All artifacts on devnet, replayable via `solana confirm -v <SIG> -u devnet`.

The verifier accepts a valid proof:

| Tx | Status | CU | What it shows |
|---|---|---:|---|
| [`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet) (shuffle, 1-tx) | Ok | 1,372,980 | First Halo2 verify-tx to land on Solana (pre-Path-B v2.0 binary) |
| [`jSVJLXky…AmyJ`](https://explorer.solana.com/tx/jSVJLXkyoN8nFZxgLb1qjXfh7W29chDHmekckd6ywqh4zCmMRS9hFw6k9cBws7PfHcd8mRLnPqkAhLPZj2SAmyJ?cluster=devnet) (Fibonacci, 3-tx stage 1) | Ok | 1,045,362 | Stage 1 writes Stage1Output PDA |
| [`3EpnmTga…dBCF`](https://explorer.solana.com/tx/3EpnmTgaereVeFqKgfZppDMJYxv5w5mPFuFWzEWtvDwTSifjoysf5R5v6JCpEKkGztQYdjVWpGjfbXZTUmFtdBCF?cluster=devnet) (Fibonacci, 3-tx stage 2a) | Ok | 792,606 | Reads stage 1, writes Stage2Output PDA |
| [`43kmVsZU…2z3i`](https://explorer.solana.com/tx/43kmVsZUePXKrPWCg2iSP7eDszgU2bTAjjVCjL5ecMCBkq7fvb4Tt4GUeJrYx3tmJNknmiUE6NLMhupc8geF2z3i?cluster=devnet) (Fibonacci, 3-tx stage 3) | Ok | 227,160 | MSM + pairing, no data-account read |

The verifier rejects tampered proofs. Each row is a separate verify-tx
where one byte of the proof was flipped before submission:

| Tx | Mutation | On-chain log | CU |
|---|---|---|---:|
| [`26Tt9UqC…WCs9`](https://explorer.solana.com/tx/26Tt9UqCYQGPDhaQ2iadt4hji2rGmcJQXFPiC4GX8vCGqEotBMyC2T6y27sYo6XB2hzxLK6UgmKqmuM3v5HaWCs9?cluster=devnet) | `shuffle_product_eval` Fr byte | Custom 0x200 — pairing equation fails | 1,373,641 |
| [`2C8rCn3R…AFQr`](https://explorer.solana.com/tx/2C8rCn3R6BZYehUeeQSc7R67Xjy8WYk62WNxzPJGCFTVTxohZzXdfxB9ydEQ1KsAUR8BsH8TRAucjLJDeW19AFQr?cluster=devnet) | `shuffle_product_commit` G1 byte | Custom 0x201 — alt_bn128 syscall caught off-curve point | 1,297,511 |
| [`9iWukM7V…cu16`](https://explorer.solana.com/tx/9iWukM7V6GZUnSvJiEfAKBznyQgRnHNBHwd59GP5b7LD7sAEZUU5rsFFJ8eTro5poRwwc9gXtncBZQSKXAKcu16?cluster=devnet) | `advice_commit` G1 byte | Custom 0x201 — alt_bn128 syscall caught off-curve point | 1,274,877 |

The 0x200 row is the strongest one. 1,373,641 CU is only 661 more
than the pre-Path-B valid run — the verifier ran the entire pipeline
(read_proof, lagrange, evaluate_gates, build_queries, shplonk,
pairing) and failed the pairing equation at the end. Not a parse
error, not a curve check, not an early bailout.

Program ID:
[`KvBa8qgb…SK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet).
Latest upgrade tx (Path B + 3-tx binary):
[`5BCm5Doftr…SJhqC`](https://explorer.solana.com/tx/5BCm5DoftrgFk8QPFQCwPvcV2x5xLXv4gZc5XbSFRfrE2SXRfpNyMTdSRzoKF3eThDRcNDZ6arz2NoTd82dSJhqC?cluster=devnet).

## Soundness audit (host-side shadow)

Three of the test circuits ship with a `shadow.rs` audit that runs
both halo2's reference `verify_proof` and our verifier on the same
proof bytes:

1. Both must accept the unmodified proof.
2. The audit has a hardcoded list of byte offsets covering every
   distinct proof region. For each offset, it flips bit 0 and re-runs
   both verifiers. Both must reject. Asymmetric verdict — one accepts,
   the other rejects — panics.

| Circuit | byte-mutation positions |
|---|---:|
| range-check (1 lookup) | 11 |
| shuffle | 8 |
| multi-lookup (2 lookups) | 5 |

24 differential checks total. Every mutation rejected symmetrically
on the latest run.

The multi-lookup audit specifically targets the
`for (i, arg) in vk.lookups.iter().enumerate()` loop in
`lookup::expressions`. Mutating lookup_1's eval byte (offset =
lookup_0_eval_offset + 5 × 32) and observing both verifiers reject
confirms the per-lookup indexing has no off-by-one.

Reproduce locally:

```bash
cargo run -p range-check-circuit       --bin gen-rc-proof  -- --shadow-audit
cargo run -p shuffle-check-circuit     --bin gen-sh-proof  -- --shadow-audit
cargo run -p multi-lookup-check-circuit --bin gen-ml-proof  -- --shadow-audit
```

Each run is ~3 seconds locally because halo2's verifier is host-side.

This is on top of `cargo test --workspace`, which is **152 unit and
integration tests** covering gate RPN evaluator, lagrange basis math
(incl. the bit-equivalence proof between Path B's batched-inverse
path and the legacy `lagrange_interpolate`), permutation expressions,
lookup + shuffle expressions, SHPLONK rotation-set construction (the
pointer-eq-vs-byte-eq trap that bit v1), Stage1Output + Stage2Output
byte-format roundtrip + replay-binding, BE↔LE syscall differential
against arkworks (Tier A2), multi-phase VK appendix parser (Tier A4),
and BPF VM roundtrips for every circuit (1-tx and 3-tx).

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Off-chain (Rust)                                                   │
│                                                                    │
│  halo2 circuit  ──►  PSE-Halo2 prover  ──►  proof bytes            │
│  (halo2_proofs v0.3)  (KeccakBeWrite transcript)                   │
│                                  │                                 │
│  compile_vk():  halo2 VerifyingKey  ──►  flat on-chain VK          │
│       (+ v2.1 multi-phase appendix when num_phases > 1)            │
│                                                                    │
│  KzgVk = (g1_one, g2_one, g2_tau)  pulled from ParamsKZG           │
└────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Devnet helper (clients/devnet-send)                                │
│                                                                    │
│  1-tx flow:                                                        │
│    tx_create → tx_load×N → tx_verify (VERIFY tag)                  │
│                                                                    │
│  3-tx flow (--three-tx):                                           │
│    tx_create_data + tx_load×N                                      │
│    + tx_create_stage1_state (4 KB)                                 │
│    + tx_create_stage2_state (8 KB)                                 │
│    + STAGE1 + STAGE2A + STAGE3 (per-tx CU budget 1.4 M, heap 256K) │
└────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ On-chain BPF (programs/verifier-program, Pinocchio)                │
│                                                                    │
│  STAGE1: parse_vk + read_proof + lagrange + expected_h_eval        │
│          + h_commit + omega_last → write Stage1Output              │
│  STAGE2A: read Stage1Output + parse_proof_no_fs + build_queries    │
│           + shplonk::build_shplonk_msm_terms → write Stage2Output  │
│  STAGE3:  read Stage2Output + finalize_shplonk_pairs + pairing     │
│                                                                    │
│  Replay binding: per-payer PDA + nonce + 3 keccak hashes           │
│  (vk_bytes, proof_bytes, public_inputs) carried STAGE1 → STAGE2A;  │
│  Stage2Output is program-owned, so STAGE3 needs no data account.   │
└────────────────────────────────────────────────────────────────────┘
```

## Comparison with prior art

| Project | Proof system | Per-verify CU | Strategy |
|---|---|---:|---|
| `groth16-solana` (Light Protocol) | Groth16 | ~250 k | Native — Groth16 has 1 pairing, ~3 G1 ops |
| `sp1-solana` (Succinct) | STARK→Groth16 | ~250 k | STARK proof wrapped in Groth16 off-chain |
| `risc0-solana` (RISC Zero) | STARK→Groth16 | ~250 k | Same wrapper pattern as sp1-solana |
| this repo (1-tx, shuffle) | PSE-Halo2 BN254/KZG/SHPLONK | 1.12 M | Native Halo2 verify |
| this repo (1-tx, range-check) | PSE-Halo2 BN254/KZG/SHPLONK | 1.29 M | Native Halo2 + 1 Plookup |
| this repo (3-tx, Fibonacci) | PSE-Halo2 BN254/KZG/SHPLONK | 2.07 M (3 stages) | Native Halo2 + on-chain state passing |

Halo2's higher cost is structural rather than implementation slack:

- N polynomial commits vs Groth16's small fixed set
- a permutation argument with grand-product polynomials, no Groth16
  analogue
- 2 opening proofs in SHPLONK vs 1 in Groth16
- Lagrange evaluations (Groth16 doesn't need them)
- 5 Fr inverses in `evaluate_lagrange` (Groth16 has 0)

A Halo2-to-Groth16 wrapper would land at ~250 k CU like
sp1/risc0-solana, but loses the property the verifier here was
written for: native Halo2 on Solana, no extra prover step, no
off-chain Groth16 prover.

## Replay instructions

```bash
# 1. Generate proof bytes for every circuit and check them host-side.
cargo run -p standard-plonk-circuit       --bin gen-proof    -- --write-golden
cargo run -p fibonacci-circuit            --bin gen-fib-proof -- --write-golden
cargo run -p range-check-circuit          --bin gen-rc-proof  -- --write-golden --shadow-audit
cargo run -p shuffle-check-circuit        --bin gen-sh-proof  -- --write-golden --shadow-audit
cargo run -p multi-lookup-check-circuit   --bin gen-ml-proof  -- --write-golden --shadow-audit
cargo run -p challenge-check-circuit      --bin gen-ch-proof
cargo run -p external-sp-circuit          --bin gen-external-sp   # Tier A3 compat
cargo run -p multi-phase-check-circuit    --bin gen-mp-proof      # Tier A4
```

```bash
# 2. Build the BPF program (no stage-trace).
cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml --features bpf-entrypoint
```

```bash
# 3. Mollusk benches — every circuit goes through the same .so.
cargo test -p halo2-solana-verifier-program -- --nocapture
```

```bash
# 3b. 3-tx Mollusk benches — every circuit's STAGE1/STAGE2A/STAGE3 CU.
cargo test -p halo2-solana-verifier-program --test cu_bench_3tx_all -- --nocapture
```

```bash
# 4. Per-stage CU profile (any single circuit).
cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml \
                --features bpf-entrypoint,stage-trace
cargo test -p halo2-solana-verifier-program --test cu_bench_rc -- --nocapture
```

```bash
# 5. MSM bench grid (sequential syscall vs proposed-SIMD model).
cargo build-sbf --manifest-path programs/g1-msm-bench/Cargo.toml --features bpf-entrypoint
cargo test -p g1-msm-bench-program --test cu_grid -- --nocapture
```

```bash
# 6. Devnet roundtrip — ~3 SOL devnet on the default keypair.
cargo run -p devnet-send -- --sh                    # valid shuffle 1-tx, Status: Ok
cargo run -p devnet-send -- --sh --mutate-byte 480  # tampered Fr eval, Custom 0x200
cargo run -p devnet-send -- --sh --mutate-byte 128  # tampered G1 commit, Custom 0x201
cargo run -p devnet-send -- --rc                    # range-check 1-tx (fits after Path B)
cargo run -p devnet-send -- --rc --two-tx           # range-check 2-tx (historical)
cargo run -p devnet-send -- --fib --three-tx        # Fibonacci 3-tx — three SUCCESS txs
```

```bash
# 7. Inspect any tx individually.
solana confirm -v jSVJLXkyoN8nFZxgLb1qjXfh7W29chDHmekckd6ywqh4zCmMRS9hFw6k9cBws7PfHcd8mRLnPqkAhLPZj2SAmyJ -u devnet
```

## Repo layout

| Path | What's there |
|---|---|
| `crates/verifier/` | The verifier crate. no_std, BN254-only, generic gate AST, lookup + shuffle + single-phase + **multi-phase** challenge support, **mainnet-le** syscall wrappers. |
| `crates/vk-host/` | halo2 `VerifyingKey` → flat on-chain VK byte format compiler (with v2.1 multi-phase appendix). |
| `crates/g1-msm-ref/` | Pippenger reference impl for the G1 MSM SIMD oracle. |
| `crates/fr-batch-inv-ref/` | Montgomery batch-inverse reference for the Fr SIMD oracle. |
| `circuits/standard-plonk/` | Test circuit: hand-coded gate identity. |
| `circuits/fibonacci/` | Test circuit: rotation + instance column. |
| `circuits/range-check/` | Test circuit: 4-bit Plookup. |
| `circuits/shuffle-check/` | Test circuit: shuffle argument. |
| `circuits/multi-lookup-check/` | Test circuit: 2 Plookup arguments. |
| `circuits/challenge-check/` | Test circuit: single-phase user challenge via `OP_CHALLENGE`. |
| `circuits/bound-range-check/` | Test circuit: range-check + claimer-hash binding (used by reward-pool). |
| `circuits/external-sp/` | Tier A3 compat: snark-verifier-sdk-shape StandardPlonk with instance column. |
| `circuits/multi-phase-check/` | Tier A4: 2-phase advice + Phase-0 challenge. |
| `programs/verifier-program/` | Pinocchio BPF wrapper — VERIFY / LOAD / STAGE1 / STAGE2 / STAGE2A / STAGE3 instruction tags. |
| `programs/g1-msm-bench/` | Mollusk bench grid for the G1 MSM SIMD. |
| `programs/reward-pool/` | ZK-gated SOL escrow. |
| `clients/devnet-send/` | Off-chain client; --sh / --rc / --fib / --ml + --two-tx / --three-tx + --mutate-byte. |
| `clients/reward-pool-cli/` | end-to-end CLI (init / claim / close). |
| `docs/cu_profile.md` | This document. |
| `docs/EVIDENCE.md` | Single-page audit index. |
| `docs/compatibility.md` | External-circuit + multi-phase compat matrix. |
| `docs/2_tx_split.md` | Original 2-tx split design. |
| `docs/reward_pool.md` | ZK-gated SOL escrow lifecycle. |
| `docs/simd-proposals/` | Formal SIMD drafts. |

## Status

| Block | Status |
|---|---|
| v1 — StandardPlonk-only verifier | done |
| v1.5 — generic gate AST, multi-circuit | done |
| v2.0 — lookup + shuffle + single-phase challenges + audit | done |
| v2.1 — 2-tx split + skip-FS optimization | landed (range-check on devnet) |
| v2.1 — **3-tx split** (Stage2Output PDA, shplonk phase 1/2 split) | landed (Fibonacci on devnet) |
| v2.1 — **Path B** (Montgomery batched inverse + cached Lagrange basis) | landed (18-39 % CU saving across every circuit) |
| Tier A2 — `mainnet-le` syscall wrappers (SIMD-0284) | wrappers in tree, differential test vs arkworks ✓, end-to-end blocked on agave-syscalls runtime |
| Tier A3 — external circuit compat (snark-verifier StandardPlonk) | landed |
| Tier A4 — multi-phase circuits (v2.1 VK appendix) | landed |
| First successful on-chain Halo2 verify-tx | landed (shuffle, 1-tx) |
| First halo2 verify-tx with shplonk+pairing in a self-contained third tx | landed (Fibonacci, 3-tx) |
| Layer 2 SIMD draft + reference impl | landed |
| Layer 3 SIMD draft + reference impl | landed (Path B captured most of the software-side win) |
| Formal SIMD-XXXX PR submission | open |
| Free-able allocator (Pinocchio bump → linked-list) | open |

`cargo test --workspace` reports **152 / 152** at HEAD.

## License

MIT OR Apache-2.0, matching the workspace.

## Author / contact

Independent applied-cryptography work. Open an issue or reach out via
the repo if you want to discuss the SIMD drafts, run a circuit through
the verifier, or sponsor the mainnet-ops work.
