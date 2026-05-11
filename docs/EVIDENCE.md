# Evidence

Every claim in this repo is backed by a clickable artifact. This page
is the index. Open `docs/cu_profile.md` for the long-form context;
this is the audit page.

## Headlines

1. The shuffle-circuit verify-tx
   [`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet)
   lands on devnet at **1,372,980 of Solana's 1.4 M default per-tx CU
   cap**. First Halo2 verify path on Solana that fits in a single tx.
   Mollusk vs on-chain delta: 0.15 %.

2. The range-check (Plookup) circuit lands end-to-end via the **2-tx
   split path**:
   stage 1 [`4TrEPtG2…8jYn`](https://explorer.solana.com/tx/4TrEPtG21v4EZHeiNYEDy4T4HRQUJWdAcWDFn9p1rGDsThUSk8xu6zG41jEER7aeFn842s9KZLbPwEbW4oKi8jYn?cluster=devnet)
   → 859,721 CU,
   stage 2 [`64HeT7V1…t1BC`](https://explorer.solana.com/tx/64HeT7V16TFwRRGPVN3yTR5WXpbmC2eJhLyHFvGujCvH6omivnStAEL9wtkPKe933dG83CJcVUHDyYJw12pbt1BC?cluster=devnet)
   → 1,063,172 CU. **First lookup-using verifier on Solana** —
   the 1-tx attempt aborts at 1.4 M.

3. **First working application built on the verifier** — `reward-pool`
   program (deployed at
   [`13AspyxT…Qh4q`](https://explorer.solana.com/address/13AspyxTTyVs5PE6mApQDuspMDD5tmuWrBuV2278Qh4q?cluster=devnet))
   locks SOL behind a halo2 proof and releases it on verify success.
   The CLAIM tx
   [`2EbQHB17…ME47`](https://explorer.solana.com/tx/2EbQHB17RVvYsVqBKbmA5c3kSUovrGXZzUo6iLcqU2r4wV8R8kdAFvLeyHj2Heg2Abub6FbAzqDZEFnZLeqBME47?cluster=devnet)
   CPI's into `verifier::STAGE2` (1,060,790 CU consumed inside the
   inner ix) and on success transfers **0.1 SOL** atomically — total
   1,065,591 CU, well under the 1.4 M cap.

4. **Fibonacci lands end-to-end via the 3-tx split path** with
   Montgomery batch-inverse refactor (Path B). All three stages
   comfortably under 1.4 M cap:
   stage 1 [`jSVJLXky…AmyJ`](https://explorer.solana.com/tx/jSVJLXkyoN8nFZxgLb1qjXfh7W29chDHmekckd6ywqh4zCmMRS9hFw6k9cBws7PfHcd8mRLnPqkAhLPZj2SAmyJ?cluster=devnet)
   → 1,045,362 CU,
   stage 2a [`3EpnmTga…dBCF`](https://explorer.solana.com/tx/3EpnmTgaereVeFqKgfZppDMJYxv5w5mPFuFWzEWtvDwTSifjoysf5R5v6JCpEKkGztQYdjVWpGjfbXZTUmFtdBCF?cluster=devnet)
   → 792,606 CU,
   stage 3 [`43kmVsZU…2z3i`](https://explorer.solana.com/tx/43kmVsZUePXKrPWCg2iSP7eDszgU2bTAjjVCjL5ecMCBkq7fvb4Tt4GUeJrYx3tmJNknmiUE6NLMhupc8geF2z3i?cluster=devnet)
   → 227,160 CU.
   **First halo2 verify path on Solana with shplonk + pairing fully
   split into a self-contained third tx** (`Stage2Output` PDA carries
   the persisted KZG VK G2 fields → stage 3 needs no data account).
   The 1-tx Fibonacci attempt overshoots 1.4 M (1.65 M post-Path-B).
   On-chain CU matches Mollusk to within 56 units per stage.

## Live on-chain artifacts (devnet)

| What | Address / signature |
|---|---|
| Verifier program | [`KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet) |
| v2.0 binary upgrade tx | [`4p3kbyirci74k3quXNpJZrc2VCUnS3oZxUUL2pM2wGWJKQ7aN6HbLKF5JQng9yXzhEPrSejPMq2d8sSuZmRbmnCq`](https://explorer.solana.com/tx/4p3kbyirci74k3quXNpJZrc2VCUnS3oZxUUL2pM2wGWJKQ7aN6HbLKF5JQng9yXzhEPrSejPMq2d8sSuZmRbmnCq?cluster=devnet) |
| Shuffle data account | [`Hp4W8mShhmQ2nPC9X9LUyJvjiq4wgRC22R48mEnPGVyi`](https://explorer.solana.com/address/Hp4W8mShhmQ2nPC9X9LUyJvjiq4wgRC22R48mEnPGVyi?cluster=devnet) |
| Range-check data account | [`5zUiaRP3ZWaqgbrg17GuQgkNHP5tzjcgZmkY86qRMPEw`](https://explorer.solana.com/address/5zUiaRP3ZWaqgbrg17GuQgkNHP5tzjcgZmkY86qRMPEw?cluster=devnet) |

## Verifier accepts a valid proof

| Tx | Status | CU | Proves |
|---|---|---:|---|
| [`5DSF3xKZ…dpZ`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet) (shuffle, 1-tx) | Ok | 1,372,980 | end-to-end Halo2 verify lands on Solana under the 1.4 M cap |

**Lookup-class circuits via 2-tx split** (range-check, the first
Plookup-using verifier to land end-to-end):

| Stage | Tx | Status | CU |
|---|---|---|---:|
| range-check stage 1 | [`4TrEPtG2…8jYn`](https://explorer.solana.com/tx/4TrEPtG21v4EZHeiNYEDy4T4HRQUJWdAcWDFn9p1rGDsThUSk8xu6zG41jEER7aeFn842s9KZLbPwEbW4oKi8jYn?cluster=devnet) | Ok | 859,721 |
| range-check stage 2 | [`64HeT7V1…t1BC`](https://explorer.solana.com/tx/64HeT7V16TFwRRGPVN3yTR5WXpbmC2eJhLyHFvGujCvH6omivnStAEL9wtkPKe933dG83CJcVUHDyYJw12pbt1BC?cluster=devnet) | Ok | 1,063,172 |

Combined: 1,922,893 CU across two transactions, replay-bound by a
per-payer PDA. See [`docs/2_tx_split.md`](2_tx_split.md) for the
design + replay-protection mechanism.

**Larger circuits via 3-tx split** (Fibonacci, the first halo2 verify
to land with `shplonk + pairing` in a self-contained third tx):

| Stage | Tx | Status | CU |
|---|---|---|---:|
| Fibonacci stage 1   | [`jSVJLXky…AmyJ`](https://explorer.solana.com/tx/jSVJLXkyoN8nFZxgLb1qjXfh7W29chDHmekckd6ywqh4zCmMRS9hFw6k9cBws7PfHcd8mRLnPqkAhLPZj2SAmyJ?cluster=devnet) | Ok | 1,045,362 |
| Fibonacci stage 2a  | [`3EpnmTga…dBCF`](https://explorer.solana.com/tx/3EpnmTgaereVeFqKgfZppDMJYxv5w5mPFuFWzEWtvDwTSifjoysf5R5v6JCpEKkGztQYdjVWpGjfbXZTUmFtdBCF?cluster=devnet) | Ok |   792,606 |
| Fibonacci stage 3   | [`43kmVsZU…2z3i`](https://explorer.solana.com/tx/43kmVsZUePXKrPWCg2iSP7eDszgU2bTAjjVCjL5ecMCBkq7fvb4Tt4GUeJrYx3tmJNknmiUE6NLMhupc8geF2z3i?cluster=devnet) | Ok |   227,160 |

Combined: 2,065,128 CU across three transactions; replay-bound by
two per-payer PDAs (stage1_state → stage2_state) and a shared nonce.
The split point puts `shplonk_phase1` (rotation-set Fr math + batched
Montgomery inverse) in stage 2a and `msm_g1 + alt_bn128_pairing` in
stage 3, which only needs the stage 2 output PDA (no data account
re-read). On-chain numbers match Mollusk within 56 CU per stage —
no emulation drift. See `crates/verifier/src/stage_state.rs` for the
`Stage2Output` byte format and `kzg/shplonk.rs::build_shplonk_msm_terms`
for phase 1.

## Verifier rejects tampered proofs

Each row is a separate verify-tx where the client flipped one bit of
one byte of the proof bytes before submitting. The mutation positions
were chosen to land in three distinct proof regions; the verifier
returns three different reject mechanisms.

| Tx | Mutation | On-chain log | CU |
|---|---|---|---:|
| [`26Tt9UqC…WCs9`](https://explorer.solana.com/tx/26Tt9UqCYQGPDhaQ2iadt4hji2rGmcJQXFPiC4GX8vCGqEotBMyC2T6y27sYo6XB2hzxLK6UgmKqmuM3v5HaWCs9?cluster=devnet) | `shuffle_product_eval` Fr byte | `Custom 0x200` — pairing equation fails | 1,373,641 |
| [`2C8rCn3R…AFQr`](https://explorer.solana.com/tx/2C8rCn3R6BZYehUeeQSc7R67Xjy8WYk62WNxzPJGCFTVTxohZzXdfxB9ydEQ1KsAUR8BsH8TRAucjLJDeW19AFQr?cluster=devnet) | `shuffle_product_commit` G1 byte | `Custom 0x201` — alt_bn128 syscall caught off-curve point | 1,297,511 |
| [`9iWukM7V…cu16`](https://explorer.solana.com/tx/9iWukM7V6GZUnSvJiEfAKBznyQgRnHNBHwd59GP5b7LD7sAEZUU5rsFFJ8eTro5poRwwc9gXtncBZQSKXAKcu16?cluster=devnet) | `advice_commit` G1 byte | `Custom 0x201` — alt_bn128 syscall caught off-curve point | 1,274,877 |

The 0x200 row is the strongest one: 1,373,641 CU is only 661 more
than the valid 1,372,980 run, so the verifier ran the full pipeline
(read_proof, lagrange, evaluate_gates, build_queries, shplonk,
pairing) and the pairing equation at the end is what said no. Not a
parse error, not an early bailout. The cryptographic check actually
fired.

The 0x201 rows are the alt_bn128 syscall rejecting off-curve points
produced by the bit-flip, propagated back to the verifier as
`VERIFIER_ERROR`.

## Mollusk per-circuit numbers

Same `.so`, every circuit, `request_heap_frame(256_000)` to match
on-chain. Two columns: **1-tx total** and the per-stage breakdown for
the **3-tx split path** introduced in v2.1.

| Circuit | 1-tx CU | STAGE1 | STAGE2A | STAGE3 | 3-tx total | Fits 1.4 M cap? |
|---|---:|---:|---:|---:|---:|---|
| Shuffle | 1,123,442 | 804,457 | 437,861 | 167,664 | 1,409,982 | **1-tx ✓** |
| Range-check (1 Plookup) | 1,294,206 | 859,779 | 572,025 | 197,476 | 1,629,280 | **1-tx ✓** |
| Multi-lookup (2 Plookup) | 1,508,493 | 954,831 | 733,579 | 271,956 | 1,960,366 | 3-tx ✓ |
| Bound-range-check | 1,609,953 | 1,089,730 | 696,767 | 257,048 | 2,043,545 | 3-tx ✓ |
| Fibonacci | 1,653,156 | 1,045,418 | 792,662 | 227,216 | 2,065,296 | 3-tx ✓ |
| StandardPlonk | 1,672,427 | 1,008,011 | 871,570 | 331,668 | 2,211,249 | 3-tx ✓ |

**Every reference circuit fits the 1.4 M cap end-to-end via the 3-tx
flow.** The largest single stage is StandardPlonk STAGE1 at 1.008 M
(392 k slack). Shuffle and range-check additionally fit in a single
tx after Path B (Montgomery batched inverse + cached Lagrange basis
in `kzg::shplonk`) — no split required for those circuits today.

These numbers reflect a v2.1 binary (program ID still
`KvBa8qgb…SK8N`). The pre-Path-B / pre-3-tx numbers are kept on chain
as historical artifacts (see "SIMD-bound aborts" below) — they
correspond to the v2.0 binary that was running before the latest
upgrade tx
[`5BCm5Doftr…SJhqC`](https://explorer.solana.com/tx/5BCm5DoftrgFk8QPFQCwPvcV2x5xLXv4gZc5XbSFRfrE2SXRfpNyMTdSRzoKF3eThDRcNDZ6arz2NoTd82dSJhqC?cluster=devnet).

### Pre-Path-B aborts (historical, v2.0 binary)

The original 1-tx attempts for the larger circuits exhausted the 1.4 M
cap mid-SHPLONK. They're preserved here as negative evidence and to
date the cost reduction:

| Tx | Circuit | CU | Status |
|---|---|---:|---|
| [`2gMQXTfC…BDWo`](https://explorer.solana.com/tx/2gMQXTfCfdAnyRnqVz7zzoTaWzzNi5XdktZi9vjWe9sT9GcHTN2tXBYt8E1QHvdrbqrDKTQBwiRVgMJ7TYxoBDWo?cluster=devnet) | range-check (Plookup), 1-tx pre-Path-B | 1,399,644 | cap exhausted (now fits at 1.29 M) |
| [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) | StandardPlonk (v1), 1-tx pre-Path-B | 1,399,644 | cap exhausted (now 1.67 M, fits 3-tx) |
| [`5yc9VpEr…rJFx`](https://explorer.solana.com/tx/5yc9VpErguYcJUQVptD7PUNytgF6yVJt8QQJbh86b8BGnVfKX4xKqrcVYuhkRkWN4bDYqBpoMQC8oZZ9gjb7rJFx?cluster=devnet) | Fibonacci, 2-tx **stage 2** pre-Path-B | 1,399,644 | cap exhausted (now fits 3-tx with stage 2a=793 k + stage 3=227 k) |
| [`4ZkvgNGx…vJkd`](https://explorer.solana.com/tx/4ZkvgNGxhdsnnqNHbs2uNfmZ3HmzMtnuBRD7ykZaavp4yZTpgiKQJVnew5h9Kcq8yCsDrkiqiMrw7E93r49dvJkd?cluster=devnet) | Multi-lookup, 2-tx stage 2 pre-Path-B | 1,399,644 | cap exhausted (now fits 3-tx) |

These prove the cost reduction is real and on-chain visible:
range-check 1.69 M → 1.29 M = −23 %, Fibonacci 2.28 M → 1.65 M = −28 %,
StandardPlonk 2.71 M → 1.67 M = −39 %. The full table is in
[`README.md`](../README.md#numbers).

## Per-stage CU profile

Two views — the legacy `stage-trace` feature breakdown for the 1-tx
flow, and the per-tx Mollusk readouts for the 3-tx flow.

### 1-tx flow (range-check, post-Path-B)

Captured via the `stage-trace` cargo feature, which emits
`sol_log_compute_units_` between every verifier stage. The numbers
below reflect the Path B refactor (`shplonk::build_shplonk_msm_terms`
runs phase 1 with Montgomery batched inverse + cached Lagrange basis,
which is what dropped `shplonk::verify_opening` from 764 k to ~370 k
CU on this circuit).

| Stage | CU (post-Path-B, range-check) | Notes |
|---|---:|---|
| `parse_vk` | ~11 k | unchanged |
| `read_proof` | ~149 k | unchanged |
| `lagrange::evaluate_lagrange` | ~542 k | unchanged (top-level Lagrange not in the batched-inverse path yet) |
| `compute_expected_h_eval` | ~96 k | unchanged |
| `aggregate_h_commitment` | ~24 k | unchanged |
| `omega_last` | ~19 k | unchanged |
| `build_queries` | ~36 k | unchanged |
| `shplonk::verify_opening` | **~370 k** | **−394 k vs pre-Path-B** (was 764 k) |
| `alt_bn128_pairing` | ~50 k | unchanged |
| **total** | **~1,294 k** | down from ~1,692 k, fits 1.4 M cap |

The Path B win is concentrated in `shplonk::verify_opening`'s
rotation-set inner loop, where the legacy code called `lagrange_interpolate`
once per commitment with N Fermat inverses internally. The new
`build_shplonk_msm_terms` does ONE Fermat inverse + 3(N−1) Fr muls
across all rotation sets via Montgomery's trick. Cached numerator
polynomials remove the rebuild cost too.

### 3-tx flow (Fibonacci, devnet on-chain)

Per-tx Mollusk vs on-chain — match to within 56 CU per stage:

| Stage | Mollusk | On-chain | Δ |
|---|---:|---:|---:|
| STAGE1   | 1,045,418 | 1,045,362 | 56 |
| STAGE2A  |   792,662 |   792,606 | 56 |
| STAGE3   |   227,216 |   227,160 | 56 |
| total    | 2,065,296 | 2,065,128 | 168 |

The 168-CU constant gap is tx-dispatch + heap-frame initialization
overhead. No algorithmic drift between emulation and real BPF VM.

What runs in each stage:

- **STAGE1**: `parse_vk + read_proof + lagrange::evaluate_lagrange +
  compute_expected_h_eval + aggregate_h_commitment + omega_last` →
  writes `Stage1Output` PDA (4 KB).
- **STAGE2A**: reads `Stage1Output`, runs `parse_proof_no_fs +
  build_queries + shplonk::build_shplonk_msm_terms` (Path B phase 1,
  Fr-only) → writes `Stage2Output` PDA (8 KB).
- **STAGE3**: reads `Stage2Output`, runs
  `shplonk::finalize_shplonk_pairs` (single G1 MSM via
  `alt_bn128_g1_multiplication_be` × N) + `alt_bn128_pairing`. **No
  data-account access** — the kzg-vk G2 fields are persisted inside
  Stage2Output, so soundness depends only on the program ownership
  of the PDAs + the three replay-binding keccak hashes carried
  forward from STAGE1.

## Soundness audit (host-side shadow)

Three of the test circuits ship with a `shadow.rs` audit that runs
**both** halo2's reference `verify_proof` and our verifier on the
same proof bytes:

1. Both must accept the unmodified proof.
2. The audit has a hardcoded list of byte offsets covering every
   distinct proof region. For each offset, it flips bit 0 and re-runs
   both verifiers. Both must reject. Asymmetric verdict — one
   accepts, the other rejects — panics.

| Circuit | byte-mutation positions | regions covered |
|---|---:|---|
| range-check (1 lookup) | 11 | advice / lookup permuted_input / permuted_table / lookup product / random_poly / vanishing h / advice_eval / random_poly_eval / lookup_product_eval / lookup_permuted_table_eval / opening W |
| shuffle | 8 | advice / shuffle_product / random_poly / vanishing h / advice_eval / random_poly_eval / shuffle_product_eval / opening W |
| multi-lookup (2 lookups) | 5 | lookup_0 permuted_input / lookup_1 permuted_input / lookup_0 product_eval / lookup_1 product_eval / opening W |

24 differential checks total, all symmetric on the latest run. The
intent is to catch the soundness-regression class of bug — our
verifier accepting strictly more than halo2's. The multi-lookup audit
specifically targets the per-lookup loop indexing in
`lookup::expressions`.

```bash
cargo run -p range-check-circuit         --bin gen-rc-proof  -- --shadow-audit
cargo run -p shuffle-check-circuit       --bin gen-sh-proof  -- --shadow-audit
cargo run -p multi-lookup-check-circuit  --bin gen-ml-proof  -- --shadow-audit
```

## Test coverage

`cargo test --workspace` reports **152 / 152** at HEAD.

| Surface | What's covered |
|---|---|
| `halo2-solana-verifier` (lib) | gate RPN evaluator, Lagrange basis math, permutation expressions, lookup + shuffle expressions, SHPLONK rotation-set construction (incl. pointer-eq-vs-byte-eq trap that bit v1), expected-h-eval Horner fold, proof-reader wire layout, VK byte format, **Path B batched-inverse bit-equivalence with legacy `lagrange_interpolate`**, **`Stage2Output` byte format + replay binding (Stage1Output + Stage2Output across stages)**, **BE↔LE syscall differential against arkworks** (`a2_tests::g1_add_matches_arkworks`, `g1_mul_matches_arkworks`), **multi-phase VK appendix parser (3 reject cases + 1 accept)**. |
| `halo2-solana-vk-host` | VK roundtrip for every supported circuit shape (single + multi-phase). |
| `g1-msm-ref` (Pippenger reference) | 11 tests — oracle for the G1 MSM SIMD. |
| `fr-batch-inv-ref` (Montgomery reference) | 7 tests — independent reference for the Path B batched-inverse algorithm. |
| `halo2-solana-verifier-program` | Lib + Mollusk BPF VM integration: every circuit verifies 1-tx; full 3-tx flow for every circuit in `cu_bench_3tx_all.rs` (each stage asserted under 1.4 M cap); 3-tx host-side replay-protection tests (wrong payer / wrong nonce / data-account tampering between stages). |

Each non-trivial circuit additionally ships a `shadow.rs` host-side
audit (`--shadow-audit` flag) — see the next section.

## Working application — ZK-gated reward pool

`programs/reward-pool` is a single-claim SOL escrow that releases its
locked balance only when a halo2 proof verifies on-chain. Three
instruction tags: `INIT_POOL` / `CLAIM` / `CLOSE_POOL`. Full design in
[`docs/reward_pool.md`](reward_pool.md).

Program: [`13AspyxT…Qh4q`](https://explorer.solana.com/address/13AspyxTTyVs5PE6mApQDuspMDD5tmuWrBuV2278Qh4q?cluster=devnet).
Deploy: [`44n2VnYo…TweY`](https://explorer.solana.com/tx/44n2VnYoTstFGYks6jPHZGnPN2mQDh7FWd55civRpPWGam2xPduVceZuCxhQSkKi5FS7az6ZkzzZgaG69HoKTweY?cluster=devnet).
Skip-FS upgrade: [`2ALjY8UC…fYLM`](https://explorer.solana.com/tx/2ALjY8UCnrZeKbfPgtPfaYuQQcvc8ZzV6r5G9bpdRhT8AMeCsSFUDGARpt4TzKpcoXXcQwZExk29FqSzTqpZfYLM?cluster=devnet).

Full end-to-end demo flow on the range-check pool (`nonce = 2`):

| Step | Tx | Status |
|---|---|---|
| `init_pool` (locks 0.1 SOL into per-(authority, nonce) PDA) | [`2hGRJEUS…dedF8`](https://explorer.solana.com/tx/2hGRJEUSSD1m2Lq12h4HtMuS1x5cmpxFV7hTJQkPKvwVNsv5TFtd4qn6evof7typwMvXcsQU5G9aYGFBufTdedF8?cluster=devnet) | Ok |
| Pool PDA address | [`2bQgYp78…qjpG`](https://explorer.solana.com/address/2bQgYp78SaWxu7wHcwtn2y9ADW52P3oEadEWxSn3qjpG?cluster=devnet) | locked 0.1 SOL |
| `verifier::STAGE1` (claimer) | [`3nWawDwz…icxe`](https://explorer.solana.com/tx/3nWawDwzqQjbeTnUgeLda8B5no6yqt9GwGFdtwrZg9vBrhzSLR3Nu7kDDWRt1H7sB5UA9k1abesy82FqwPa1icxe?cluster=devnet) | Ok |
| **`reward-pool::CLAIM`** (CPI's `verifier::STAGE2` + transfers reward) | [`2EbQHB17…ME47`](https://explorer.solana.com/tx/2EbQHB17RVvYsVqBKbmA5c3kSUovrGXZzUo6iLcqU2r4wV8R8kdAFvLeyHj2Heg2Abub6FbAzqDZEFnZLeqBME47?cluster=devnet) | **Ok, 1,065,591 CU** |

The CLAIM tx's on-chain log is the headline:

```
Program 13AspyxTT… invoke [1]
Program KvBa8qgb… invoke [2]                                  ← CPI'd verifier
Program KvBa8qgb… consumed 1060790 of 1396152 compute units
Program KvBa8qgb… success                                     ← STAGE2 verified the proof
Program log: reward-pool: claim ok, transferred 100000000 lamports
Program 13AspyxTT… consumed 1065235 of 1399700 compute units
Program 13AspyxTT… success
```

Negative evidence — the same flow can't be replayed:

| Test | Result |
|---|---|
| Re-claim same pool (after CLAIM succeeded) | `Custom 0x501 POOL_ALREADY_CLAIMED`, fail-fast at 1,848 CU (verifier was never invoked) |
| `close_pool` on orphaned pool, refund authority | [`4vyYhBoS…MGLS`](https://explorer.solana.com/tx/4vyYhBoSfPtMmBmc14uSUKLdRLbr9gTjPDGwV4QPBaZCfqfyNUEmmJ5GwkkHmEEtAP6XPDbn3fGsaGhyHFHXMGLS?cluster=devnet) Ok |

Replay the full flow yourself:

```bash
# 1. Build + deploy reward-pool to devnet (~0.6 SOL).
cargo build-sbf --manifest-path programs/reward-pool/Cargo.toml --features bpf-entrypoint
solana program deploy --url devnet target/deploy/reward_pool.so

# 2. Authority creates pool, locks reward.
cargo run -p reward-pool-cli -- init \
    --reward 100000000 --nonce 2 \
    --reward-pool-program <DEPLOYED_PROGRAM_ID>

# 3. Claimer generates proof and atomically claims the SOL.
cargo run -p reward-pool-cli -- claim \
    --authority $(solana address) --nonce 2 \
    --reward-pool-program <DEPLOYED_PROGRAM_ID>

# 4. Try to re-claim → fails with Custom 0x501.
cargo run -p reward-pool-cli -- claim \
    --authority $(solana address) --nonce 2 \
    --reward-pool-program <DEPLOYED_PROGRAM_ID>
```

## Reproduce all of this locally

Six independent commands. Each produces its own evidence; nothing
shared.

```bash
# 1. Off-chain provers + host-side verify + shadow audits.
cargo run -p standard-plonk-circuit       --bin gen-proof    -- --write-golden
cargo run -p fibonacci-circuit            --bin gen-fib-proof -- --write-golden
cargo run -p range-check-circuit          --bin gen-rc-proof  -- --write-golden --shadow-audit
cargo run -p shuffle-check-circuit        --bin gen-sh-proof  -- --write-golden --shadow-audit
cargo run -p multi-lookup-check-circuit   --bin gen-ml-proof  -- --write-golden --shadow-audit
cargo run -p challenge-check-circuit      --bin gen-ch-proof

# 2. BPF program build.
cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml --features bpf-entrypoint

# 3. Mollusk benches — every circuit through the same .so.
cargo test -p halo2-solana-verifier-program -- --nocapture

# 4. Per-stage CU breakdown (any single circuit).
cargo build-sbf --manifest-path programs/verifier-program/Cargo.toml \
                --features bpf-entrypoint,stage-trace
cargo test -p halo2-solana-verifier-program --test cu_bench_rc -- --nocapture

# 5. MSM bench grid (sequential syscall vs proposed-SIMD model).
cargo build-sbf --manifest-path programs/g1-msm-bench/Cargo.toml --features bpf-entrypoint
cargo test -p g1-msm-bench-program --test cu_grid -- --nocapture

# 6. Devnet roundtrip (~3 SOL devnet on default keypair).
cargo run -p devnet-send -- --sh                    # valid shuffle, expect Status: Ok
cargo run -p devnet-send -- --sh --mutate-byte 480  # tampered Fr eval, expect Custom 0x200
cargo run -p devnet-send -- --sh --mutate-byte 128  # tampered G1 commit, expect Custom 0x201
cargo run -p devnet-send -- --rc                    # range-check, hits 1.4 M cap (expected)
```

Every devnet tx replayable: `solana confirm -v <SIG> -u devnet`.

## Honest caveats

What the verifier supports today (after Tier A): lookup, shuffle,
single-phase user challenges, **multi-phase circuits**, in-gate
`Expression::Instance` queries, 2-tx split (range-check on devnet),
**3-tx split** (Fibonacci on devnet, every reference circuit fits in
Mollusk).

What still doesn't quite work:

- **End-to-end LE syscall path** — the `mainnet-le` Cargo feature
  routes `alt_bn128_*_be` → `alt_bn128_*_le` and ships an arkworks
  differential test that passes for both endianness modes. But the
  `_le` op-codes are unrecognized by `agave-syscalls 3.1.14` (the
  runtime Mollusk pins), so the end-to-end Mollusk test for the LE
  path returns `InvalidAttribute` at ~761 k CU. **Runtime gap, not
  a verifier bug** — the wrappers go live the moment SIMD-0284 LE
  op-codes land in mainnet-aligned agave.
- **Free-able allocator** — Pinocchio's bump allocator never frees,
  so circuits beyond a certain size eventually exhaust the 256 KB
  heap. Linked-list allocator is in the roadmap.
- **halo2-lib chip-library circuits** — would now compile through
  vk-host (multi-phase no longer rejected) but the chip wiring is
  large; not part of the current compat test corpus. See
  [`docs/compatibility.md`](compatibility.md) for the open gap list.
- **Log-derivative lookups (LogUp)** — modern halo2-lib uses these
  instead of Plookup; verifier currently only handles Plookup.

The Layer 2 + Layer 3 SIMD drafts in `docs/simd-proposals/` remain
useful — the Path B refactor in software captured most of the Layer
3 (Fr-batch-inverse) win without a syscall, but a native syscall
would still save ~400 k CU on top. The Layer 2 (G1 MSM) syscall is
still worth ~15-20 % total verify CU after Path B. Neither has been
filed as a formal SIMD-XXXX PR yet.

## Repo

https://github.com/nzengi/Solana-Plonk

License: MIT OR Apache-2.0.
