# halo2-solana-verifier

A PSE-Halo2 (BN254 / KZG / SHPLONK) proof verifier that runs on Solana
BPF. The Fibonacci-circuit verify lands on devnet **end-to-end via the
3-tx split** —
[stage 1](https://explorer.solana.com/tx/jSVJLXkyoN8nFZxgLb1qjXfh7W29chDHmekckd6ywqh4zCmMRS9hFw6k9cBws7PfHcd8mRLnPqkAhLPZj2SAmyJ?cluster=devnet)
1.05 M CU,
[stage 2a](https://explorer.solana.com/tx/3EpnmTgaereVeFqKgfZppDMJYxv5w5mPFuFWzEWtvDwTSifjoysf5R5v6JCpEKkGztQYdjVWpGjfbXZTUmFtdBCF?cluster=devnet)
0.79 M CU,
[stage 3](https://explorer.solana.com/tx/43kmVsZUePXKrPWCg2iSP7eDszgU2bTAjjVCjL5ecMCBkq7fvb4Tt4GUeJrYx3tmJNknmiUE6NLMhupc8geF2z3i?cluster=devnet)
0.23 M CU (every stage comfortably under the 1.4 M cap; on-chain CU
matches Mollusk to within 56 units per stage). The 1-tx
[shuffle-circuit verify](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet)
also lives on devnet at 1.37 M CU and was the first Halo2 verify path
to land on Solana inside a single transaction.

As far as I can tell this is the first Halo2 verifier path to land
end-to-end on Solana — `groth16-solana`, `sp1-solana`, and
`risc0-solana` all wrap to Groth16 first instead of verifying
PLONKish natively.

The repo is two things:

1. The verifier crate, the BPF program, eight halo2 test circuits, and
   the Mollusk + devnet harness that drives them.
2. Two formal SIMD drafts and reference implementations for the
   syscalls the per-stage CU profile points to (`alt_bn128_g1_msm`
   and `alt_bn128_fr_batch_inverse`). The Fr-batch-inverse case is now
   partially addressed in software (Montgomery batched-inverse +
   cached Lagrange basis — see "Numbers" below); the syscall would
   still cut another ~400 k CU.

If you want the short audit-trail version, every claim below is
linked on a single page: [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

| Doc | What's inside |
|---|---|
| [`docs/EVIDENCE.md`](docs/EVIDENCE.md) | Clickable per-tx evidence for every claim. |
| [`docs/cu_profile.md`](docs/cu_profile.md) | Per-stage CU profile, comparison with prior art, replay instructions. |
| [`docs/compatibility.md`](docs/compatibility.md) | External circuit / multi-phase compat matrix. |
| [`docs/2_tx_split.md`](docs/2_tx_split.md) | Original 2-tx split design (range-check on devnet). |
| [`docs/reward_pool.md`](docs/reward_pool.md) | ZK-gated SOL escrow — first working app on the verifier. |
| [`docs/simd-proposals/`](docs/simd-proposals/) | `alt_bn128_g1_msm` + `alt_bn128_fr_batch_inverse` drafts. |

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
- **multi-phase circuits** — advice columns split across phases plus
  challenges squeezed mid-protocol (`cs.challenge_usable_after(phase)`).
  VK byte format carries an optional v2.1 multi-phase appendix; single-
  phase circuits still parse with no appendix (v2.0 byte-compat).

Anything outside that surface fails closed — invalid VK, off-curve
points, mismatched query indices, etc. all return `VERIFIER_ERROR` or
`VERIFIER_REJECTED` without panicking.

Eight test circuits exercise different parts of that surface:

| Circuit | What it stresses |
|---|---|
| StandardPlonk | a single hard-coded gate identity (`q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0`) |
| Fibonacci | `Rotation::next` + `Rotation(2)` advice queries, public input via instance column |
| Range-check | one Plookup argument over a 4-bit fixed table |
| Shuffle | one shuffle argument over two advice columns |
| Multi-lookup | two Plookup arguments — exercises the lookup-iteration loop |
| Challenge-check | single-phase user challenge wired into a gate via `OP_CHALLENGE` bytecode |
| **External-SP** | snark-verifier-sdk-shape StandardPlonk with 1 instance column + gate referencing `Expression::Instance` (Tier A3 compat) |
| **Multi-phase-check** | 2-phase advice + Phase-0 challenge — exercises the v2.1 phase-interleaved Fiat–Shamir loop (Tier A4) |

Each non-trivial circuit (range-check / shuffle / multi-lookup) ships
with a host-side `shadow.rs` that runs both halo2's reference
`verify_proof` and our verifier on the same proof bytes; see
[How the audit works](#how-the-audit-works) below.

## Numbers

Mollusk SVM, every circuit through the same `.so`, with
`request_heap_frame(256_000)` to match a real on-chain CU-budget tx.
Two columns: **1-tx total** (no split), and the per-stage breakdown
for the **3-tx split path** (`STAGE1 → STAGE2A → STAGE3`). The 3-tx
total is lower than the 1-tx total because stage 3 doesn't re-parse
the data account (the `Stage2Output` PDA carries the persisted KZG
VK G2 fields).

| Circuit | 1-tx CU | STAGE1 | STAGE2A | STAGE3 | 3-tx total | Fits 1.4 M cap? |
|---|---:|---:|---:|---:|---:|---|
| Shuffle | 1,123,442 | 804,457 | 437,861 | 167,664 | 1,409,982 | **1-tx ✓** |
| Range-check (1 Plookup) | 1,294,206 | 859,779 | 572,025 | 197,476 | 1,629,280 | **1-tx ✓** |
| Multi-lookup (2 Plookup) | 1,508,493 | 954,831 | 733,579 | 271,956 | 1,960,366 | 3-tx ✓ |
| Bound-range-check | 1,609,953 | 1,089,730 | 696,767 | 257,048 | 2,043,545 | 3-tx ✓ |
| Fibonacci | 1,653,156 | 1,045,418 | 792,662 | 227,216 | 2,065,296 | 3-tx ✓ |
| StandardPlonk | 1,672,427 | 1,008,011 | 871,570 | 331,668 | 2,211,249 | 3-tx ✓ |

Every reference circuit's 3-tx flow fits comfortably under the 1.4 M
cap: the largest single stage is StandardPlonk's STAGE1 at 1.008 M
(392 k slack). Shuffle and range-check additionally fit in a single
tx today — no split required. Fibonacci's 3-tx flow is
[live on devnet](docs/EVIDENCE.md#headlines) and matches Mollusk to
within 56 CU per stage.

These numbers reflect a **Montgomery batched-inverse + cached
Lagrange basis refactor** ("Path B") shipped in `kzg::shplonk`. The
refactor replaces N independent Fermat inverses with one Fermat + 3(N−1)
Fr muls and caches the basis polynomials per rotation set; net saving
on every circuit ranges from 18 % (shuffle) to 39 % (StandardPlonk).
The old single-tx CU numbers (pre-Path-B: shuffle 1.37 M, StandardPlonk
2.71 M, …) are still on-chain as historical evidence in
`docs/EVIDENCE.md`.

Per-stage breakdown of one of the 3-tx flows (Fibonacci, captured via
Mollusk per-instruction CU readout):

| Tx | Work | CU | % of 3-tx total |
|---|---|---:|---:|
| STAGE1   | `parse_vk + read_proof + lagrange + expected_h + h_commit + omega_last` (writes Stage1Output PDA) | 1,045,418 | 51 |
| STAGE2A  | `parse_proof_no_fs + build_queries + shplonk phase 1` (Fr-only, writes Stage2Output PDA) | 792,662 | 38 |
| STAGE3   | `msm_g1 + alt_bn128_pairing` (no data-account read) | 227,216 | 11 |

The 3-tx split is governed by a per-payer PDA + nonce + three keccak
replay hashes — design notes in [`docs/EVIDENCE.md`](docs/EVIDENCE.md)
and [`docs/2_tx_split.md`](docs/2_tx_split.md) (the 2-tx
predecessor, kept around because range-check still ships with a
working 2-tx devnet record).

## On-chain evidence

All artifacts on devnet, replayable via `solana confirm -v <SIG> -u devnet`.

The verifier accepts a valid proof:

| Tx | Status | CU | What it shows |
|---|---|---:|---|
| [`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet) (shuffle, **1-tx**) | Ok | 1,372,980 | End-to-end Halo2 verify in a single tx (pre-Path-B binary). |
| [`jSVJLXky…AmyJ`](https://explorer.solana.com/tx/jSVJLXkyoN8nFZxgLb1qjXfh7W29chDHmekckd6ywqh4zCmMRS9hFw6k9cBws7PfHcd8mRLnPqkAhLPZj2SAmyJ?cluster=devnet) (Fibonacci, **3-tx stage 1**) | Ok | 1,045,362 | Stage 1 writes the Stage1Output PDA. |
| [`3EpnmTga…dBCF`](https://explorer.solana.com/tx/3EpnmTgaereVeFqKgfZppDMJYxv5w5mPFuFWzEWtvDwTSifjoysf5R5v6JCpEKkGztQYdjVWpGjfbXZTUmFtdBCF?cluster=devnet) (Fibonacci, **3-tx stage 2a**) | Ok | 792,606 | Reads stage 1, writes Stage2Output PDA. |
| [`43kmVsZU…2z3i`](https://explorer.solana.com/tx/43kmVsZUePXKrPWCg2iSP7eDszgU2bTAjjVCjL5ecMCBkq7fvb4Tt4GUeJrYx3tmJNknmiUE6NLMhupc8geF2z3i?cluster=devnet) (Fibonacci, **3-tx stage 3**) | Ok | 227,160 | Pairing-only; no data-account access. |

The verifier rejects tampered proofs. Each row below is a separate
verify-tx where one byte of the proof region was flipped before
submitting:

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

The program ID is
[`KvBa8qgb…SK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet).
Latest upgrade tx (Path B + 3-tx binary):
[`5BCm5Doftr…SJhqC`](https://explorer.solana.com/tx/5BCm5DoftrgFk8QPFQCwPvcV2x5xLXv4gZc5XbSFRfrE2SXRfpNyMTdSRzoKF3eThDRcNDZ6arz2NoTd82dSJhqC?cluster=devnet).

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

This is on top of `cargo test --workspace`, which is **152 unit and
integration tests** locking the per-stage algebra independently — gate
RPN evaluator, lagrange basis math (including the Path B batched-inverse
proof of bit-equivalence with the legacy single-inverse path),
permutation expressions, lookup + shuffle expressions, SHPLONK
rotation-set construction (incl. the pointer-eq-vs-byte-eq trap that
bit us in v1), 3-tx state-PDA roundtrips, multi-phase VK appendix
parser, BE↔LE syscall differential against arkworks, and the BPF VM
roundtrips for every circuit (1-tx and 3-tx).

## Repo layout

```
crates/
  verifier/              no_std verifier (BN254-only, generic gate AST,
                         lookup + shuffle + single + multi-phase challenge
                         support; mainnet-le syscall wrappers ready)
  vk-host/               halo2 VerifyingKey → flat on-chain VK bytes
                         (v2.1 multi-phase appendix when num_phases > 1)
  g1-msm-ref/            Pippenger reference impl (oracle for the G1 MSM SIMD)
  fr-batch-inv-ref/      Montgomery batch-inverse reference (oracle for the Fr SIMD)

circuits/
  standard-plonk/        original gate-identity-only test circuit
  fibonacci/             rotation + instance column
  range-check/           4-bit Plookup
  shuffle-check/         multiset-eq via shuffle
  multi-lookup-check/    two Plookup arguments
  challenge-check/       single-phase user-defined challenge
  bound-range-check/     range-check + claimer-hash binding (reward-pool)
  external-sp/           snark-verifier-sdk-shape StandardPlonk (Tier A3
                         compat — gate references `Expression::Instance`)
  multi-phase-check/     2-phase advice + Phase-0 challenge (Tier A4)

programs/
  verifier-program/      Pinocchio BPF wrapper — instruction tags:
                         VERIFY / LOAD / STAGE1 / STAGE2 (2-tx) /
                         STAGE2A / STAGE3 (3-tx)
  g1-msm-bench/          Mollusk bench grid for the G1 MSM SIMD
  reward-pool/           ZK-gated SOL escrow — CPI's verifier, releases reward

clients/
  devnet-send/           off-chain devnet roundtrip; --sh / --rc / --fib /
                         --ml + --two-tx / --three-tx + --mutate-byte
  reward-pool-cli/       end-to-end demo CLI (init / claim / close)

docs/
  EVIDENCE.md            single-page audit index, every claim linked
  cu_profile.md          per-stage CU profile + comparison vs prior art
  compatibility.md       external-circuit + multi-phase test matrix
  2_tx_split.md          original 2-tx split design (range-check on devnet)
  reward_pool.md         ZK-gated SOL escrow lifecycle + replay-protection
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
cargo run -p external-sp-circuit          --bin gen-external-sp   # Tier A3 compat
cargo run -p multi-phase-check-circuit    --bin gen-mp-proof      # Tier A4
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
prints remaining CU between every verifier stage. The dedicated
3-tx benchmark suite runs every reference circuit through
`STAGE1 → STAGE2A → STAGE3` and prints the per-stage CU:

```bash
cargo test -p halo2-solana-verifier-program --test cu_bench_3tx_all -- --nocapture
```

(Optional) Devnet roundtrip; needs ~3 SOL devnet on the default
keypair for the create + load + verify txs:

```bash
cargo run -p devnet-send -- --sh                    # valid shuffle, 1-tx, Status: Ok
cargo run -p devnet-send -- --sh --mutate-byte 480  # tampered Fr eval, expect Custom 0x200
cargo run -p devnet-send -- --sh --mutate-byte 128  # tampered G1 commit, expect Custom 0x201
cargo run -p devnet-send -- --rc                    # range-check 1-tx (now fits, post-Path-B)
cargo run -p devnet-send -- --rc --two-tx           # range-check 2-tx (historical path)
cargo run -p devnet-send -- --fib --three-tx        # Fibonacci 3-tx — three SUCCESS txs
```

## SIMD case

The repo carries two formal SIMD drafts and the matching reference
implementations. After the Path B refactor both drafts remain on the
table but are no longer strictly required for any reference circuit:

`alt_bn128_g1_msm` (Layer 2) replaces the SHPLONK rotation-set inner
loop's sequential `alt_bn128_g1_multiplication_be` calls with a
single batched syscall. Discussion thread:
[solana-improvement-documents#535](https://github.com/solana-foundation/solana-improvement-documents/discussions/535).
Bench grid in `programs/g1-msm-bench/`. Cost-model projection: still
worth −15 to −20 % total verify CU even after Path B because the MSM
itself is N alt_bn128_g1_multiplication_be syscalls.

`alt_bn128_fr_batch_inverse` (Layer 3) originally targeted Lagrange
inverses. **Path B implemented Montgomery batch inversion in software**
inside `kzg::shplonk` (one Fermat inverse + 3(n−1) Fr muls), which
captured most of the win without a syscall. A native syscall would
still save ~400 k CU (cost-model `4 000 + n × 200` vs the software
`16 k + 9 k·(n−1)`), but the software fix made every reference
circuit fit under the cap today, so this is no longer a
production blocker.

Neither SIMD has been filed as a formal SIMD-XXXX PR yet. Both drafts
in `docs/simd-proposals/` follow the structure of SIMD-0302
(BN254 G2 syscalls).

## Status

| Block | Status |
|---|---|
| v1 — StandardPlonk-only verifier | done |
| v1.5 — generic gate AST, multi-circuit | done |
| v2.0 — lookup + shuffle + single-phase challenges | done, audit-hardened |
| v2.1 — 2-tx split + skip-FS optimization | landed; range-check (Plookup) end-to-end on devnet |
| v2.1 — **3-tx split** (Stage2Output PDA, shplonk phase 1/2 split) | **landed; Fibonacci end-to-end on devnet, ±56 CU on-chain vs Mollusk** |
| v2.1 — **Path B (Montgomery batched inverse + cached Lagrange basis)** | **landed; 18-39 % CU saving across every circuit** |
| Tier A2 — `mainnet-le` syscall wrappers (SIMD-0284) | wrappers in tree, differential test vs arkworks ✓, end-to-end Mollusk blocked on agave-syscalls runtime |
| Tier A3 — external circuit compat (snark-verifier StandardPlonk) | landed; first `Expression::Instance` in gate AST verified |
| Tier A4 — **multi-phase circuits** (v2.1 VK appendix + phase-interleaved FS) | **landed; 2-phase circuit verifies, 6 single-phase circuits unaffected** |
| Phase 2 — `reward-pool` ZK-gated SOL escrow + CLI | landed; full claim flow on devnet, 1.06 M CU under cap |
| First successful on-chain Halo2 verify-tx (1-tx) | landed (shuffle, 1.37 M CU) |
| First lookup-using verifier on-chain (2-tx) | landed (range-check, 860 k + 1,063 k CU) |
| First halo2 verify-tx with **shplonk + pairing in a self-contained third tx** | landed (Fibonacci 3-tx) |
| First working application built on the verifier | landed (reward-pool, atomic ZK→SOL transfer) |
| Layer 2 SIMD draft + reference impl | landed |
| Layer 3 SIMD draft + reference impl | landed (largely captured by Path B in software) |
| Formal SIMD-XXXX PR submission | open |
| Free-able allocator (Pinocchio bump → linked-list) | open |

`cargo test --workspace` reports **152 / 152** at HEAD.

## License

MIT OR Apache-2.0.
