# Halo2 Verifier on Solana — CU Profile, On-Chain Evidence, and SIMD Case

This document describes a PSE-Halo2 (BN254 / KZG / SHPLONK) proof
verifier running on Solana BPF: per-stage CU profile, the devnet
transactions backing each claim, the host-side audit shadow, and the
two SIMDs the cost profile points to. Numbers come from a Mollusk
SVM benchmark with `sol_log_compute_units_` checkpoints between
every verifier stage and from devnet roundtrips that submit the same
proof bytes to a deployed `.so`.

Companion: [`docs/simd-proposals/`](simd-proposals/) — formal drafts
for `alt_bn128_g1_msm` (Layer 2) and `alt_bn128_fr_batch_inverse`
(Layer 3).

## The numbers

| Circuit | Mollusk CU | On-chain CU | What it stresses |
|---|---:|---:|---|
| StandardPlonk (k=4) | 2,728,844 | 1,399,644 (cap abort) | hand-coded gate, 3 advice + 5 fixed columns |
| Fibonacci (k=4) | 2,284,029 | 1,399,644 (cap abort) | rotation + instance + public input |
| Multi-lookup (k=6, 2 Plookup) | 2,286,887 | (over cap) | the lookup-iteration loop with `i ∈ {0, 1}` |
| Range-check (k=6, 1 Plookup) | 1,692,408 | 1,399,644 (cap abort) | one Plookup over a 4-bit table |
| **Shuffle (k=5)** | **1,374,962** | **1,372,980 (Status: Ok)** | shuffle argument |

The shuffle row is the headline: the on-chain run came in at
1,372,980 of Solana's 1.4 M default per-tx cap, which makes it the
first Halo2 verifier path to land successfully on Solana without a
`set_compute_unit_limit` raise or a 2-tx split. Mollusk vs runtime
delta is 0.15 % — Mollusk is a fair predictor of on-chain behaviour
within the precision of the `sol_log_compute_units_` syscall itself.

Every other circuit sits over 1.4 M and aborts at the cap. Both SIMD
drafts in this repo target where the cost lives.

## Per-stage breakdown

Captured by inserting `sol_log_compute_units_` between every stage of
`verify()` (the `stage-trace` cargo feature). `compute_unit_limit` is
set to 1 B for measurement only; `heap_size = 256 * 1024` matches a
real on-chain `request_heap_frame(256_000)`.

Range-check (k=6, 4-bit Plookup, 8 input values):

| Stage | CU | % |
|---|---:|---:|
| `parse_vk` | 11,089 | <1 |
| `read_proof` | 149,334 | 9 |
| `lagrange::evaluate_lagrange` | 542,854 | 32 |
| `compute_expected_h_eval` | 95,975 | 6 |
| `aggregate_h_commitment` | 23,600 | 1 |
| `omega_last` | 19,248 | 1 |
| `build_queries` | 35,771 | 2 |
| `shplonk::verify_opening` | 764,412 | 45 |
| `alt_bn128_pairing` | 49,546 | 3 |

Shuffle (k=5, multiset eq over 4 elements):

| Stage | CU | % |
|---|---:|---:|
| `parse_vk` | 10,910 | <1 |
| `read_proof` | 121,559 | 9 |
| `lagrange::evaluate_lagrange` | 542,361 | 39 |
| `compute_expected_h_eval` | 80,968 | 6 |
| `aggregate_h_commitment` | 15,724 | 1 |
| `omega_last` | 15,415 | 1 |
| `build_queries` | 9,809 | <1 |
| `shplonk::verify_opening` | 528,091 | 38 |
| `alt_bn128_pairing` | 49,546 | 4 |

Shape that comes out of these:

- `lagrange::evaluate_lagrange` is roughly the same on every circuit
  (~542 k). The cost is independent of the constraint system; it's a
  function of `k` and the blinding-factor count, both fixed by halo2.
  The 5 inverses inside dominate the stage at ~100 k CU each in pure
  BPF arkworks.
- `shplonk::verify_opening` shrinks with circuit size. StandardPlonk's
  3 advice columns + 4 fixed-commit collisions produce a denser
  rotation set than shuffle's 2 advice columns; that's why shuffle
  gets to 528 k while StandardPlonk stays at 1.67 M. The cost inside
  is `~25 sequential alt_bn128_g1_multiplication_be calls + Fr
  coefficient combination` for StandardPlonk; ~12 calls for shuffle.
- `alt_bn128_pairing` is constant — the pairing syscall already does
  its job well at ~50 k for two pairs.
- Everything else combined sits under 6 % on every circuit.

## Where the cost lives → SIMD case

77 % of the cost lives in two stages: `shplonk::verify_opening` and
`lagrange::evaluate_lagrange`. Both are addressable through native
syscalls that don't currently exist on Solana.

**SHPLONK is sequential G1 MSM.** `verify_opening` performs the
BDFG21 reduction: per rotation set, `inner_msm = Σⱼ y^j · Cⱼ` and
`r_inner = Σⱼ y^j · rⱼ(u)`, then `outer_msm += v^i · z_diff_i ·
inner_msm`, plus a final `−r_outer·[1]_1 − z_0·h1 + u·h2`.
The per-tx CU is dominated by the G1 multiplications and additions
running through `alt_bn128_g1_multiplication_be` and
`alt_bn128_g1_addition_be` one at a time. A batched MSM syscall
amortises both the per-call fixed cost and (with a verifier refactor)
the per-iteration Fr coefficient overhead. Reference impl in
[`crates/g1-msm-ref/`](../crates/g1-msm-ref/), bench grid in
[`programs/g1-msm-bench/`](../programs/g1-msm-bench/), formal draft
at [`docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md`](simd-proposals/simd-XXXX-alt-bn128-g1-msm.md).

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
already pushes past the heap budget. Naive scalar-mul-and-add in
pure BPF blows past the per-tx CU cap immediately. So if you want
batched G1 MSM on Solana, it has to be a syscall.

**Lagrange is Fr inverses.** `evaluate_lagrange` computes `L_0(x)`,
`L_last(x)`, `L_blind(x)`, and `xⁿ`. Five Fr inverses (one per
blinding factor + one for the L_0 denominator) run through arkworks's
constant-time Montgomery extended-Euclidean, in pure Rust compiled
to BPF. Each inverse is empirically ~100 k CU. A native batch-inverse
syscall using Montgomery's trick is `1 inverse + 3(n−1)
multiplications`, projected at `4 000 + n × 200` CU. Reference impl
in [`crates/fr-batch-inv-ref/`](../crates/fr-batch-inv-ref/) (60
lines, 7/7 tests). Formal draft at
[`docs/simd-proposals/simd-XXXX-alt-bn128-fr-batch-inverse.md`](simd-proposals/simd-XXXX-alt-bn128-fr-batch-inverse.md).

| Layer combo | Verifier total CU (StandardPlonk) | Fits in 1 tx? |
|---|---:|---|
| Today | 2,710,424 | no — aborts at 1.4 M |
| + Layer 2 (G1 MSM) | ~2,180,000 | no — closer, still over |
| + Layer 2 + Layer 3 (Fr batch inverse) | ~1,500,000 | yes, with margin |
| 2-tx split + Layer 2 (Layer 1+2) | 2 × <1,400,000 | yes — ops fallback |

The 2-tx split (Layer 1) is the operational mainnet path that needs
no new SIMDs. With Layer 2 and Layer 3 both shipped, the verifier
fits in one tx with margin to spare.

## On-chain evidence

All artifacts on devnet, replayable via `solana confirm -v <SIG> -u devnet`.

The verifier accepts a valid proof:

| Tx | Status | CU |
|---|---|---:|
| [`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet) (shuffle, valid) | Ok | 1,372,980 |

The verifier rejects tampered proofs. Each row is a separate verify-tx
where one byte of the proof was flipped before submission:

| Tx | Mutation | On-chain log | CU |
|---|---|---|---:|
| [`26Tt9UqC…WCs9`](https://explorer.solana.com/tx/26Tt9UqCYQGPDhaQ2iadt4hji2rGmcJQXFPiC4GX8vCGqEotBMyC2T6y27sYo6XB2hzxLK6UgmKqmuM3v5HaWCs9?cluster=devnet) | `shuffle_product_eval` Fr byte | Custom 0x200 — pairing equation fails | 1,373,641 |
| [`2C8rCn3R…AFQr`](https://explorer.solana.com/tx/2C8rCn3R6BZYehUeeQSc7R67Xjy8WYk62WNxzPJGCFTVTxohZzXdfxB9ydEQ1KsAUR8BsH8TRAucjLJDeW19AFQr?cluster=devnet) | `shuffle_product_commit` G1 byte | Custom 0x201 — alt_bn128 syscall caught off-curve point | 1,297,511 |
| [`9iWukM7V…cu16`](https://explorer.solana.com/tx/9iWukM7V6GZUnSvJiEfAKBznyQgRnHNBHwd59GP5b7LD7sAEZUU5rsFFJ8eTro5poRwwc9gXtncBZQSKXAKcu16?cluster=devnet) | `advice_commit` G1 byte | Custom 0x201 — alt_bn128 syscall caught off-curve point | 1,274,877 |

The 0x200 row is the strongest one. 1,373,641 CU is only 661 more
than the valid run — the verifier ran the entire pipeline (read_proof,
lagrange, evaluate_gates, build_queries, shplonk, pairing) and failed
the pairing equation at the end. Not a parse error, not a curve check,
not an early bailout. The cryptographic check fired and said no.

The two 0x201 rows are the alt_bn128 syscall rejecting off-curve
points produced by the bit-flip. Different mechanism, different point
in the pipeline, different CU.

The SIMD-bound aborts kept around as the negative case:

| Tx | Circuit | Outcome |
|---|---|---|
| [`2gMQXTfC…BDWo`](https://explorer.solana.com/tx/2gMQXTfCfdAnyRnqVz7zzoTaWzzNi5XdktZi9vjWe9sT9GcHTN2tXBYt8E1QHvdrbqrDKTQBwiRVgMJ7TYxoBDWo?cluster=devnet) | range-check (Plookup) | total 1,692,408 — 1.4 M cap exhausted mid-SHPLONK |
| [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) | StandardPlonk (v1) | total 2,710,424 — same exhaustion pattern |

Program ID:
[`KvBa8qgb…SK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet).
v2.0 upgrade tx:
[`4p3kbyirci74k3quXNpJZrc2VCUnS3oZxUUL2pM2wGWJKQ7aN6HbLKF5JQng9yXzhEPrSejPMq2d8sSuZmRbmnCq`](https://explorer.solana.com/tx/4p3kbyirci74k3quXNpJZrc2VCUnS3oZxUUL2pM2wGWJKQ7aN6HbLKF5JQng9yXzhEPrSejPMq2d8sSuZmRbmnCq?cluster=devnet).

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

24 differential checks total. The intent is to catch the
soundness-regression class of bug — our verifier accepting strictly
more than halo2's reference. Every mutation rejected symmetrically
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

This is on top of `cargo test --workspace`, which is 101 unit and
integration tests covering gate RPN evaluator, lagrange basis math,
permutation expressions, lookup + shuffle expressions, SHPLONK
rotation-set construction (including the pointer-eq-vs-byte-eq trap
that bit v1), and BPF VM roundtrips for every circuit.

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Off-chain (Rust)                                                   │
│                                                                    │
│  halo2 circuit  ──►  PSE-Halo2 prover  ──►  proof bytes            │
│  (halo2_proofs v0.3)  (KeccakBeWrite transcript)                   │
│                                  │                                 │
│  compile_vk():  halo2 VerifyingKey  ──►  flat on-chain VK          │
│                                                                    │
│  KzgVk = (g1_one, g2_one, g2_tau)  pulled from ParamsKZG           │
└────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Devnet helper (clients/devnet-send)                                │
│                                                                    │
│  tx_create:  create_account(data_acct, payload_size)               │
│  tx_load×N:  program LOAD ix → memcpy chunks into data_acct.data   │
│  tx_verify:  ComputeBudget(limit, heap=256KB) + program VERIFY ix  │
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

## Comparison with prior art

| Project | Proof system | Per-verify CU | Strategy |
|---|---|---:|---|
| `groth16-solana` (Light Protocol) | Groth16 | ~250 k | Native — Groth16 has 1 pairing, ~3 G1 ops |
| `sp1-solana` (Succinct) | STARK→Groth16 | ~250 k | STARK proof wrapped in Groth16 off-chain |
| `risc0-solana` (RISC Zero) | STARK→Groth16 | ~250 k | Same wrapper pattern as sp1-solana |
| this repo | PSE-Halo2 BN254/KZG/SHPLONK | 2.71 M (StandardPlonk) / 1.37 M (shuffle) | Native Halo2 verify |

Halo2's higher cost is structural rather than implementation slack:

- N polynomial commits vs Groth16's small fixed set
- a permutation argument with grand-product polynomials, no Groth16
  analogue
- 2 opening proofs in SHPLONK vs 1 in Groth16
- Lagrange evaluations (Groth16 doesn't need them)
- 5 Fr inverses (Groth16 has 0)

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
```

```bash
# 2. Build the BPF program (no stage-trace).
cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml --features bpf-entrypoint

# 3. Run Mollusk benches — every circuit goes through the same .so.
cargo test -p halo2-solana-verifier-program -- --nocapture
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
cargo run -p devnet-send -- --sh                    # valid shuffle, expect Status: Ok
cargo run -p devnet-send -- --sh --mutate-byte 480  # tampered Fr eval, expect Custom 0x200
cargo run -p devnet-send -- --sh --mutate-byte 128  # tampered G1 commit, expect Custom 0x201
cargo run -p devnet-send -- --rc                    # range-check, hits 1.4 M cap (expected)
```

```bash
# 7. Inspect any tx individually.
solana confirm -v 5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ -u devnet
```

## Repo layout

| Path | What's there |
|---|---|
| `crates/verifier/` | The verifier crate. no_std, BN254-only, generic gate AST, lookup + shuffle + single-phase challenge support. |
| `crates/vk-host/` | halo2 `VerifyingKey` → flat on-chain VK byte format compiler. |
| `crates/g1-msm-ref/` | Pippenger reference impl for the G1 MSM SIMD oracle. |
| `crates/fr-batch-inv-ref/` | Montgomery batch-inverse reference for the Fr SIMD oracle. |
| `circuits/standard-plonk/` | Test circuit: hand-coded gate identity. |
| `circuits/fibonacci/` | Test circuit: rotation + instance column. |
| `circuits/range-check/` | Test circuit: 4-bit Plookup. |
| `circuits/shuffle-check/` | Test circuit: shuffle argument. |
| `circuits/multi-lookup-check/` | Test circuit: 2 Plookup arguments. |
| `circuits/challenge-check/` | Test circuit: single-phase user challenge via `OP_CHALLENGE`. |
| `programs/verifier-program/` | Pinocchio BPF wrapper. |
| `programs/g1-msm-bench/` | Mollusk bench grid for the G1 MSM SIMD. |
| `clients/devnet-send/` | Off-chain client; valid + tampered proof modes. |
| `docs/cu_profile.md` | This document. |
| `docs/simd-proposals/` | Formal SIMD drafts. |

## Status

| Block | Status |
|---|---|
| v1 — StandardPlonk-only verifier | done |
| v1.5 — generic gate AST, multi-circuit | done |
| v2.0 — lookup + shuffle + single-phase challenges + audit | done |
| v2.1 — mainnet ops (2-tx split, LE format, free-able allocator) | partial; only SIMD drafts |
| First successful on-chain Halo2 verify-tx | landed (shuffle) |
| Layer 2 SIMD draft + reference impl | landed |
| Layer 3 SIMD draft + reference impl | landed |
| Formal SIMD-XXXX PR submission | open |

`cargo test --workspace` reports 101/101 at HEAD.

## License

MIT OR Apache-2.0, matching the workspace.

## Author / contact

Independent applied-cryptography work. Open an issue or reach out via
the repo if you want to discuss the SIMD drafts, run a circuit through
the verifier, or sponsor the v2.1 / mainnet-ops work.
