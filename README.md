# halo2-solana-verifier

A PSE-Halo2 (BN254 / KZG / SHPLONK) proof verifier that runs on Solana
BPF. The shuffle-circuit verify-tx
[`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet)
lands on devnet at 1,372,980 of Solana's 1.4 M default per-tx CU cap.
As far as I can tell it's the first Halo2 verifier path to land
successfully on Solana — `groth16-solana`, `sp1-solana`, and
`risc0-solana` all wrap to Groth16 first instead of verifying
PLONKish natively.

The repo is two things:

1. The verifier crate, the BPF program, six halo2 test circuits, and
   the Mollusk + devnet harness that drives them.
2. Two formal SIMD drafts and reference implementations for the
   syscalls the per-stage CU profile points to (`alt_bn128_g1_msm` and
   `alt_bn128_fr_batch_inverse`).

## What the verifier accepts

The same `.so` handles any halo2 circuit using:

- any number of advice / fixed / instance columns
- arbitrary rotation patterns (`Rotation::cur` / `next` / `prev` / `Rotation(N)`)
- multiple gates per `ConstraintSystem`, generic gate ASTs over
  `Constant / Fixed / Advice / Instance / Sum / Product / Negated /
  Scaled / Challenge`
- mixed advice / fixed / instance columns inside the permutation argument
- lookup arguments (Plookup-family)
- shuffle arguments
- single-phase user-defined challenges

Multi-phase circuits are rejected at compile-vk time. Anything else
fails closed.

Six test circuits exercise different parts of that surface:

| Circuit | What it stresses |
|---|---|
| StandardPlonk | a single hard-coded gate identity (`q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0`) |
| Fibonacci | `Rotation::next` + `Rotation(2)` advice queries, public input via instance column |
| Range-check | one Plookup argument over a 4-bit fixed table |
| Shuffle | one shuffle argument over two advice columns |
| Multi-lookup | two Plookup arguments — exercises the lookup-iteration loop |
| Challenge-check | single-phase user challenge wired into a gate via `OP_CHALLENGE` bytecode |

Each non-trivial circuit (range-check / shuffle / multi-lookup) ships
with a host-side `shadow.rs` that runs both halo2's reference
`verify_proof` and our verifier on the same proof bytes; see
[How the audit works](#how-the-audit-works) below.

## Numbers

Mollusk SVM, every circuit through the same `.so`, with
`request_heap_frame(256_000)` to match a real on-chain CU-budget tx:

| Circuit | CU |
|---|---:|
| StandardPlonk | 2,728,844 |
| Fibonacci | 2,284,029 |
| Multi-lookup (2 Plookup args) | 2,286,887 |
| Range-check (1 Plookup arg) | 1,692,408 |
| Shuffle | 1,374,962 |

Of these, only the shuffle path fits under Solana's 1.4 M default
per-tx CU cap. The on-chain run came in at 1,372,980 — Mollusk vs
runtime delta is 0.15 %, so the bench numbers track on-chain CU
reasonably well. Everything else aborts at the cap and motivates the
SIMD work in `docs/simd-proposals/`.

Per-stage breakdown for the range-check circuit, captured by
`sol_log_compute_units_` between every verifier stage (the
`stage-trace` cargo feature):

| Stage | CU | % of total |
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

SHPLONK plus Lagrange together carry 77 % of the cost. Both are
addressable through native syscalls — `shplonk::verify_opening` is
dominated by sequential G1 muls (the case for `alt_bn128_g1_msm`),
and `lagrange` by a handful of Fr inverses (the case for
`alt_bn128_fr_batch_inverse`). See `docs/cu_profile.md` for the full
profile and the per-circuit comparison.

## On-chain evidence

All artifacts on devnet, replayable via `solana confirm -v <SIG> -u devnet`.

The verifier accepts a valid proof:

| Tx | Status | CU |
|---|---|---:|
| [`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet) (shuffle, valid) | Ok | 1,372,980 |

The verifier rejects tampered proofs. Each row is a separate verify-tx
where one byte of the proof region was flipped before submitting:

| Tx | Mutation | On-chain log | CU |
|---|---|---|---:|
| [`26Tt9UqC…WCs9`](https://explorer.solana.com/tx/26Tt9UqCYQGPDhaQ2iadt4hji2rGmcJQXFPiC4GX8vCGqEotBMyC2T6y27sYo6XB2hzxLK6UgmKqmuM3v5HaWCs9?cluster=devnet) | `shuffle_product_eval` Fr byte | Custom 0x200 — pairing equation fails | 1,373,641 |
| [`2C8rCn3R…AFQr`](https://explorer.solana.com/tx/2C8rCn3R6BZYehUeeQSc7R67Xjy8WYk62WNxzPJGCFTVTxohZzXdfxB9ydEQ1KsAUR8BsH8TRAucjLJDeW19AFQr?cluster=devnet) | `shuffle_product_commit` G1 byte | Custom 0x201 — alt_bn128 syscall caught off-curve point | 1,297,511 |
| [`9iWukM7V…cu16`](https://explorer.solana.com/tx/9iWukM7V6GZUnSvJiEfAKBznyQgRnHNBHwd59GP5b7LD7sAEZUU5rsFFJ8eTro5poRwwc9gXtncBZQSKXAKcu16?cluster=devnet) | `advice_commit` G1 byte | Custom 0x201 — alt_bn128 syscall caught off-curve point | 1,274,877 |

The 0x200 row is the strongest one: the verifier ran the entire
pipeline (read_proof, lagrange, evaluate_gates, build_queries, shplonk,
pairing) against a tampered Fr eval and consumed only 661 more CU
than the valid proof before failing the pairing equation. Not a parse
error, not a curve check — the full cryptographic check fired and
said no.

The two 0x201 rows are the alt_bn128 syscall rejecting off-curve
points produced by the bit-flip, propagated back to the verifier as
`VERIFIER_ERROR`. Different reject mechanisms, different points in the
pipeline.

There are also two SIMD-bound aborts kept around as the negative case:

| Tx | Circuit | Why |
|---|---|---|
| [`2gMQXTfC…BDWo`](https://explorer.solana.com/tx/2gMQXTfCfdAnyRnqVz7zzoTaWzzNi5XdktZi9vjWe9sT9GcHTN2tXBYt8E1QHvdrbqrDKTQBwiRVgMJ7TYxoBDWo?cluster=devnet) | range-check (Plookup) | total 1,692,408 — 1.4 M cap exhausted mid-SHPLONK |
| [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) | StandardPlonk (v1) | total 2,710,424 — same exhaustion pattern |

The program ID is
[`KvBa8qgb…SK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet).
Latest upgrade tx (v2.0 binary):
[`4p3kbyirci74k3quXNpJZrc2VCUnS3oZxUUL2pM2wGWJKQ7aN6HbLKF5JQng9yXzhEPrSejPMq2d8sSuZmRbmnCq`](https://explorer.solana.com/tx/4p3kbyirci74k3quXNpJZrc2VCUnS3oZxUUL2pM2wGWJKQ7aN6HbLKF5JQng9yXzhEPrSejPMq2d8sSuZmRbmnCq?cluster=devnet).

## How the audit works

Three of the test circuits ship with a `shadow.rs` that runs **both**
halo2's reference `verify_proof` and our `halo2_solana_verifier::verify`
on the same proof bytes:

1. Both must accept the unmodified proof.
2. The shadow has a hardcoded list of byte offsets covering every
   distinct proof region (advice commits, lookup permuted_input /
   permuted_table / product commits, random_poly commit, vanishing-h
   pieces, every kind of Fr eval, both opening proofs). For each
   offset, the shadow flips bit 0 and re-runs both verifiers. Both
   must reject. Asymmetric verdict — one accepts, the other rejects —
   panics.

Coverage at the latest run:

| Circuit | byte-mutation positions |
|---|---:|
| range-check (1 lookup) | 11 |
| shuffle | 8 |
| multi-lookup (2 lookups) | 5 |

24 differential checks total. The intent is to catch the soundness-regression
class of bug, where our verifier accepts strictly more than halo2's. Every
mutation rejected symmetrically as of the latest run. Runs in ~3 seconds
locally because halo2's verifier is host-side.

This is on top of `cargo test --workspace`, which is 101 unit and
integration tests locking the per-stage algebra independently — gate
RPN evaluator, lagrange basis math, permutation expressions, lookup +
shuffle expressions, SHPLONK rotation-set construction (incl. the
pointer-eq-vs-byte-eq trap that bit us in v1), and the BPF VM
roundtrips for every circuit.

## Repo layout

```
crates/
  verifier/              no_std verifier (BN254-only, generic gate AST,
                         lookup + shuffle + single-phase challenge support)
  vk-host/               halo2 VerifyingKey → flat on-chain VK bytes
  g1-msm-ref/            Pippenger reference impl (oracle for the G1 MSM SIMD)
  fr-batch-inv-ref/      Montgomery batch-inverse reference (oracle for the Fr SIMD)

circuits/
  standard-plonk/        original gate-identity-only test circuit
  fibonacci/             rotation + instance column
  range-check/           4-bit Plookup
  shuffle-check/         multiset-eq via shuffle
  multi-lookup-check/    two Plookup arguments
  challenge-check/       single-phase user-defined challenge

programs/
  verifier-program/      Pinocchio BPF wrapper around the verifier
  g1-msm-bench/          Mollusk bench grid for the G1 MSM SIMD

clients/
  devnet-send/           off-chain devnet roundtrip; supports
                         valid-proof and tampered-proof modes

docs/
  cu_profile.md          per-stage CU profile, on-chain evidence,
                         comparison vs prior art, replay instructions
  simd-proposals/        formal SIMD drafts (alt_bn128_g1_msm,
                         alt_bn128_fr_batch_inverse)
```

## Reproduce locally

Generate proof bytes for every circuit and have the host-side verifier
check them:

```bash
cargo run -p standard-plonk-circuit       --bin gen-proof    -- --write-golden
cargo run -p fibonacci-circuit            --bin gen-fib-proof -- --write-golden
cargo run -p range-check-circuit          --bin gen-rc-proof  -- --write-golden --shadow-audit
cargo run -p shuffle-check-circuit        --bin gen-sh-proof  -- --write-golden --shadow-audit
cargo run -p multi-lookup-check-circuit   --bin gen-ml-proof  -- --write-golden --shadow-audit
cargo run -p challenge-check-circuit      --bin gen-ch-proof
```

The `--shadow-audit` flag runs the differential audit against halo2's
reference verifier and prints per-mutation `Accept`/`Reject` for both
sides.

Build the BPF program and run the Mollusk benches:

```bash
cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml --features bpf-entrypoint
cargo test -p halo2-solana-verifier-program -- --nocapture
```

The Mollusk run produces per-circuit CU numbers; with the
`stage-trace` feature it adds `[stage] after …` checkpoints and
prints remaining CU between every verifier stage.

(Optional) Devnet roundtrip; needs ~3 SOL devnet on the default
keypair for the create + load + verify txs:

```bash
cargo run -p devnet-send -- --sh                    # valid shuffle, expect Status: Ok
cargo run -p devnet-send -- --sh --mutate-byte 480  # tampered Fr eval, expect Custom 0x200
cargo run -p devnet-send -- --sh --mutate-byte 128  # tampered G1 commit, expect Custom 0x201
cargo run -p devnet-send -- --rc                    # range-check, hits 1.4 M cap (expected)
```

## SIMD case

The repo carries two formal SIMD drafts and the matching reference
implementations.

`alt_bn128_g1_msm` (Layer 2) replaces the SHPLONK rotation-set inner
loop's ~25 sequential `alt_bn128_g1_multiplication_be` calls with a
single batched syscall. Discussion thread:
[solana-improvement-documents#535](https://github.com/solana-foundation/solana-improvement-documents/discussions/535).
Bench grid in `programs/g1-msm-bench/`. Cost-model projection: −20 %
total verify CU, −32 % on the SHPLONK slice. The Pippenger reference
in `crates/g1-msm-ref/` runs out of BPF heap at n ≥ 16 even with
`request_heap_frame(256 KB)` — so the SIMD has to land natively;
pure-BPF Pippenger is not a path.

`alt_bn128_fr_batch_inverse` (Layer 3) targets the Lagrange Fr-inverse
cost — currently 32–39 % of total CU on the lookup / shuffle circuits.
Cost model `4 000 + n × 200` CU vs ~100 k per pure-BPF arkworks
inverse. Reference impl in `crates/fr-batch-inv-ref/` is 60 lines, 7/7
tests pass. Layer 2 + Layer 3 together bring every reference circuit
under 1.4 M with margin.

Neither SIMD has been filed as a formal SIMD-XXXX PR yet. Both drafts
in `docs/simd-proposals/` follow the structure of SIMD-0302
(BN254 G2 syscalls).

## Status

| Block | Status |
|---|---|
| v1 — StandardPlonk-only verifier | done |
| v1.5 — generic gate AST, multi-circuit | done |
| v2.0 — lookup + shuffle + single-phase challenges | done, audit-hardened |
| v2.1 — mainnet ops (2-tx split, LE format, free-able allocator) | partial; only SIMD drafts landed |
| First successful on-chain Halo2 verify-tx | landed (shuffle) |
| Layer 2 SIMD draft + reference impl | landed |
| Layer 3 SIMD draft + reference impl | landed |
| Formal SIMD-XXXX PR submission | open |

`cargo test --workspace` reports 101 / 101 at HEAD.

## License

MIT OR Apache-2.0.
