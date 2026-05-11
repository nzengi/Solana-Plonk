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

Same `.so`, every circuit. `request_heap_frame(256_000)` to match
on-chain.

| Circuit | Mollusk CU | Fits 1.4 M cap? |
|---|---:|:---:|
| StandardPlonk | 2,728,844 | no |
| Fibonacci | 2,284,029 | no |
| Multi-lookup (2 Plookup args) | 2,286,887 | no |
| Range-check (1 Plookup arg) | 1,692,408 | no |
| Shuffle | 1,374,962 | **yes** |

The SIMD-bound aborts kept around as the negative case:

| Tx | Circuit | CU |
|---|---|---:|
| [`2gMQXTfC…BDWo`](https://explorer.solana.com/tx/2gMQXTfCfdAnyRnqVz7zzoTaWzzNi5XdktZi9vjWe9sT9GcHTN2tXBYt8E1QHvdrbqrDKTQBwiRVgMJ7TYxoBDWo?cluster=devnet) | range-check (Plookup), 1-tx attempt | 1,399,644 |
| [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) | StandardPlonk (v1), 1-tx attempt | 1,399,644 |

Even with the 2-tx split, three of our reference circuits still
overshoot stage 2's 1.4 M cap because their SHPLONK slice alone is
between 1.18 M and 1.67 M. The pattern is consistent — stage 1 fits
for every circuit, stage 2 only fits for range-check (Plookup):

| Circuit | stage 1 tx | stage 2 tx | stage 2 CU |
|---|---|---|---:|
| Fibonacci | [`4m1ERjQy…tpGK`](https://explorer.solana.com/tx/4m1ERjQyGRqTogvGFfWi5rMEXsFgG9Vb9RtMAdPbkSaeb2qtYeBXRkbLtFBftUWwZ8vpGC2f4WEykNhEgSMVtpGK?cluster=devnet) Ok 1,045,360 | [`5yc9VpEr…rJFx`](https://explorer.solana.com/tx/5yc9VpErguYcJUQVptD7PUNytgF6yVJt8QQJbh86b8BGnVfKX4xKqrcVYuhkRkWN4bDYqBpoMQC8oZZ9gjb7rJFx?cluster=devnet) failed | 1,399,644 |
| Multi-lookup (2 Plookup) | [`3KnYHnHh…75oe`](https://explorer.solana.com/tx/3KnYHnHhRN9uhHWs9pNj5atxvKYSv4bLyhYYD2CYKGUFp4hVmPwxc3R8KhhuR1C1seRCpD2mSuxcMNGYmKGa75oe?cluster=devnet) Ok 954,773 | [`4ZkvgNGx…vJkd`](https://explorer.solana.com/tx/4ZkvgNGxhdsnnqNHbs2uNfmZ3HmzMtnuBRD7ykZaavp4yZTpgiKQJVnew5h9Kcq8yCsDrkiqiMrw7E93r49dvJkd?cluster=devnet) failed | 1,399,644 |

These stage 1 successes are not just curiosities — they prove the
2-tx framework correctly checkpoints and replay-binds *any* halo2
circuit regardless of stage 2 fit. A 3-tx split or a Layer 2 SIMD
(`alt_bn128_g1_msm`) closes the remaining gap; design notes in
[`docs/2_tx_split.md`](2_tx_split.md).

## Per-stage CU profile

`stage-trace` cargo feature emits `sol_log_compute_units_` between
every verifier stage.

Range-check (k=6, 4-bit Plookup):

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
| **total** | **1,692,387** | 100 |

77 % of cost lives in two stages: `shplonk::verify_opening` (G1 MSM)
and `lagrange::evaluate_lagrange` (Fr inverses). Both have SIMD drafts
in `docs/simd-proposals/`.

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

`cargo test --workspace` reports 101 / 101 at HEAD.

| Crate / test surface | Tests |
|---|---:|
| `halo2-solana-verifier` (verifier crate, with `solana-syscalls`) | 83 |
| `halo2-solana-vk-host` | 6 |
| `g1-msm-ref` (Pippenger reference) | 11 |
| `fr-batch-inv-ref` (Montgomery batch inverse reference) | 7 |
| `halo2-solana-verifier-program` | lib + 6 BPF VM integration tests |

The verifier crate's tests cover: gate RPN evaluator, lagrange basis
math, permutation expressions, lookup expressions, shuffle
expressions, SHPLONK rotation-set construction (including the
pointer-eq-vs-byte-eq trap that bit v1), expected-h-eval Horner fold,
proof-reader wire layout, VK byte format. The BPF VM integration
tests run every test circuit's verify-tx through Mollusk.

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

The verifier supports lookup, shuffle, and single-phase user
challenges. It does not yet support:

- multi-phase circuits (vk-host hard-rejects)
- 2-tx split for circuits that don't fit one tx
- LE byte format (mainnet active per SIMD-0284 — repo is BE-first)
- free-able allocator (the Pinocchio bump allocator caps practical
  circuit size)

The Layer 2 + Layer 3 SIMD drafts in `docs/simd-proposals/` lay out a
path to bring every reference circuit under 1.4 M with margin. Both
drafts ship reference implementations and Mollusk bench grids; neither
has been filed as a formal SIMD-XXXX PR yet.

## Repo

https://github.com/nzengi/Solana-Plonk

License: MIT OR Apache-2.0.
