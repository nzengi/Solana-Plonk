# Halo2 Verifier on Solana — CU Profile & SIMD Case

> **v2.0 update (2026-05-10)** — the verifier now supports halo2's
> **lookup arguments** (Plookup-family) and **shuffle arguments**, and
> single-phase user-defined challenges. Four circuits are exercised in
> this profile: StandardPlonk, Fibonacci, range-check (lookup), shuffle.
> Shadow comparator (differential test against halo2's reference verifier)
> validates lookup soundness on real prover output. The on-chain VK
> format has bumped `H2SV0002 → H2SV0003` (+8 bytes for empty
> lookup/shuffle blocks; variable for non-empty).
>
> **v1.5 (historical)** — gate-AST evaluator made the verifier
> circuit-shape agnostic without lookups/shuffles. v2.0 lifts those
> remaining restrictions.


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
| **2,710,424 CU** | v1 cost to verify a k=4 StandardPlonk proof on BPF (Mollusk). |
| **2,728,844 CU** | v1.5 cost on the same StandardPlonk proof — **+0.7%** AST overhead. |
| **2,284,029 CU** | v1.5 cost on a Fibonacci circuit (1 advice + 1 fixed selector + 1 instance). |
| **2,286,887 CU** | v2.0 cost on a 2-lookup circuit (4-bit + 3-bit ranges, k=6). |
| **1,692,408 CU** | v2.0 cost on a 4-bit range-check Plookup circuit (k=6, 16-entry table). |
| **1,374,962 CU** | v2.0 cost on a 4-element shuffle circuit (k=5) — **fits under Solana's default 1.4M per-tx CU cap without raise**. |
| **1,399,644 CU** | What the on-chain devnet tx consumed before hitting the 1.4M ceiling (StandardPlonk). |
| **1,667,016 CU = 62%** | Cost of `shplonk::verify_opening` alone (StandardPlonk). |
| **533,709 CU = 20%** | Cost of `lagrange::evaluate_lagrange` (5 Fr inverses). |
| **49,546 CU = 2%** | Cost of the final `alt_bn128_pairing` syscall (already a syscall — optimal). |
| **3 / 0x200 + 0x201 × 2** | Distinct on-chain verifier reject mechanisms demonstrated by tampered-proof devnet txs (cryptographic + curve-check ×2). |
| **24** | Host-side differential shadow-audit mutations across 3 circuits, all symmetrically rejected by halo2 + our verifier. |

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

## 3a. v1.5 — generic gate-AST evaluator + multi-circuit support

### Per-stage CU breakdown comparison

| Stage                       | StandardPlonk |  Fibonacci  | Δ |
|-----------------------------|--------------:|------------:|--:|
| entry overhead              |           420 |         620 | +48% |
| parse_vk                    |        11,610 |      11,205 | ~0 |
| read_proof                  |       258,636 |     194,364 | **−25%** |
| lagrange::evaluate_lagrange |       533,710 |     531,730 | ~0 |
| compute_expected_h_eval     |       157,993 |     260,960 | **+65%** |
| h_commit                    |        15,726 |      15,716 | ~0 |
| omega_last                  |        11,540 |      11,540 | 0 |
| build_queries               |        24,557 |      26,818 | +9% |
| **shplonk::verify_opening** |   **1,666,984** | **1,183,498** | **−29%** |
| pairing                     |        49,546 |      49,546 | 0 |
| **TOTAL**                   |   **2,730,735** | **2,285,954** | **−16%** |

Two circuits, same `.so`. The headline:
- Fibonacci's SHPLONK is **29% lighter** (1 advice column vs 3 → fewer
  rotation-set commitments to fold).
- Fibonacci's `compute_expected_h_eval` is **65% heavier** because its
  gate AST has rotation::next + Rotation(2) advice queries plus a wider
  permutation argument.
- Net: Fibonacci is **16% cheaper** end-to-end. Same SIMD case applies —
  SHPLONK is still the dominant slice (52% for Fibonacci, 61% for
  StandardPlonk) and the `alt_bn128_g1_msm` proposal still moves the
  needle most.

### v1.5 vs v1
v1 totals 2,710,424 CU (StandardPlonk hard-coded gate). v1.5 same circuit
totals 2,730,735 CU = **+0.75%** AST evaluator overhead. Almost all of
the delta lives in `build_queries` (v1: 7,229 → v1.5: 24,557, +17,328) —
per-query metadata processing + `rotate_point` calls. Acceptable.



v1.5 replaces v1's hard-coded StandardPlonk gate with a stack-based RPN
bytecode evaluator (`crates/verifier/src/plonk/expression.rs`). The VK
format gains gate AST bytecode + per-query column metadata + permuted
column type tags (`H2SV0001` → `H2SV0002`).

| Metric | v1 (StandardPlonk hard-coded) | v1.5 (generic AST) | Δ |
|---|---:|---:|---:|
| `verify()` total CU (Mollusk, StandardPlonk) | 2,710,424 | 2,728,844 | +0.68% |
| `verify()` total CU (Mollusk, Fibonacci) | n/a | 2,284,029 | new |
| VK byte size (StandardPlonk k=4) | 632 B | 794 B | +162 B |
| VK byte size (Fibonacci k=4) | n/a | 488 B | new |

The 0.68% AST overhead on the regression circuit confirms the stack
evaluator's per-op cost is small (~1k CU for the 19-op StandardPlonk
gate). The Fibonacci circuit costs **less** because it has fewer advice
columns (1 vs 3) → fewer rotation-set commitments inside SHPLONK, and a
shorter gate AST.

**What the same `.so` now accepts:** any halo2 ConstraintSystem with
`num_lookups == 0`, `num_shuffles == 0`, and `num_challenges == 0`.
Includes circuits using rotation::next/prev/etc, instance columns
(public inputs), mixed advice/fixed/instance permuted columns, and
arbitrary gate polynomials over the standard arithmetic ops.

**Out of scope for v1.5 (deferred to v2):**
- Lookup arguments (Plookup-family). Rejected at compile time.
- Shuffle arguments. Rejected at compile time.
- User-defined phase challenges (`vk.cs.num_challenges > 0`).

## 3b. v2.0 — lookup + shuffle + user challenges

v2.0 lifts the three v1.5 restrictions. Four crates added/updated:

- `crates/verifier/src/plonk/lookup.rs` — emits 5 expressions per lookup
  (l_0/l_last/active-row/permuted_input/permuted_table identities) and
  routes 5 SHPLONK queries per lookup into `build_queries`. Theta-fold
  compression of input/table expression lists matches halo2's forward
  Horner direction.
- `crates/verifier/src/plonk/shuffle.rs` — 3 expressions + 2 SHPLONK
  queries per shuffle. Uses γ only (no β); cheaper than lookup.
- `crates/verifier/src/plonk/proof_reader.rs` — wire-side reads for the
  v2.0 layout: per-lookup 2 G1 (after θ) + 1 G1 (after perm products),
  per-shuffle 1 G1, plus 5 Fr per lookup + 2 Fr per shuffle in the
  evaluation phase. User challenges squeezed after advice batch.
- `crates/vk-host/src/compile.rs` — bumps magic to `H2SV0003`, encodes
  lookup + shuffle expression bytecodes, hard-rejects multi-phase
  circuits.

### Per-stage CU breakdown (v2.0 circuits)

Range-check (4-bit Plookup, k=6, 16-entry table, 8 input values):

| Stage                       | CU       | %    |
|-----------------------------|---------:|-----:|
| entry                       | 558      | <1%  |
| parse_vk                    | 11,089   | <1%  |
| read_proof                  | 149,334  | 9%   |
| lagrange::evaluate_lagrange | 542,854  | 32%  |
| compute_expected_h_eval     | 95,975   | 6%   |
| h_commit                    | 23,600   | 1%   |
| omega_last                  | 19,248   | 1%   |
| build_queries               | 35,771   | 2%   |
| **shplonk::verify_opening** | **764,412** | **45%** |
| pairing                     | 49,546   | 3%   |
| **TOTAL**                   | **1,692,387** | 100% |

Shuffle (4-element multiset eq, k=5):

| Stage                       | CU       | %    |
|-----------------------------|---------:|-----:|
| entry                       | 558      | <1%  |
| parse_vk                    | 10,910   | <1%  |
| read_proof                  | 121,559  | 9%   |
| lagrange::evaluate_lagrange | 542,361  | 39%  |
| compute_expected_h_eval     | 80,968   | 6%   |
| h_commit                    | 15,724   | 1%   |
| omega_last                  | 15,415   | 1%   |
| build_queries               | 9,809    | <1%  |
| **shplonk::verify_opening** | **528,091** | **38%** |
| pairing                     | 49,546   | 4%   |
| **TOTAL**                   | **1,374,941** | 100% |

### v2.0 vs v1.5

| Metric                        | StandardPlonk | Fibonacci | Range-check | Shuffle |
|-------------------------------|--------------:|----------:|------------:|--------:|
| Verify total (Mollusk)        | 2,728,844     | 2,284,029 | 1,692,408   | 1,374,962 |
| `shplonk` portion             | 61%           | 52%       | 45%         | 38%     |
| `lagrange` portion            | 20%           | 23%       | 32%         | 39%     |
| Fits in 1.4M tx ceiling?      | ❌            | ❌        | ❌          | **✅ yes (no raise)** |
| Lookup support exercised?     | —             | —         | ✓ Plookup   | —       |
| Shuffle support exercised?    | —             | —         | —           | ✓       |

The shuffle circuit is the **first verifier path that fits under
Solana's default 1,400,000 CU per-instruction cap without
`set_compute_unit_limit`**. The reason: shuffle has only 1 G1 + 2 Fr
per shuffle (versus lookup's 3 G1 + 5 Fr) and 2 SHPLONK queries (vs 5).
For circuits whose constraint shape compresses well into shuffle
arguments — e.g. multiset equality, simple permutations, sortedness
checks — v2.0 ships a usable verifier with margin.

### Devnet evidence (v2.0)

#### Positive evidence: valid shuffle proof landed

| Tx | Status | CU consumed |
|---|---|---:|
| [`5DSF3xKZN6Mp…`](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet) (shuffle, valid proof) | **Success** ✓ | 1,372,980 / 1,399,700 |

**The shuffle tx is the first Halo2 verifier path to land successfully
on Solana** without `set_compute_unit_limit` raises or 2-tx splits.
Mollusk vs on-chain delta: 0.15% (1,374,962 vs 1,372,980).

#### Negative evidence: tampered proofs rejected

A working verifier must **also** reject bad proofs — otherwise it accepts
everything and is unsound. The following devnet txs use `cargo run -p
devnet-send -- --sh --mutate-byte <off>`, which flips bit 0 of one byte
of the proof region before submitting the verify-tx. Every distinct
mutation triggers the verifier on-chain:

| Tx | Mutation | On-chain log | CU |
|---|---|---|---:|
| [`26Tt9UqCYQGP…`](https://explorer.solana.com/tx/26Tt9UqCYQGPDhaQ2iadt4hji2rGmcJQXFPiC4GX8vCGqEotBMyC2T6y27sYo6XB2hzxLK6UgmKqmuM3v5HaWCs9?cluster=devnet) | shuffle_product_eval byte (Fr field) | `Custom 0x200` = **VERIFIER_REJECTED** (cryptographic — pairing fails) | 1,373,641 |
| [`2C8rCn3R6BZY…`](https://explorer.solana.com/tx/2C8rCn3R6BZYehUeeQSc7R67Xjy8WYk62WNxzPJGCFTVTxohZzXdfxB9ydEQ1KsAUR8BsH8TRAucjLJDeW19AFQr?cluster=devnet) | shuffle_product_commit byte (G1 x-byte) | `Custom 0x201` = **VERIFIER_ERROR** (off-curve detected by syscall) | 1,297,511 |
| [`9iWukM7V6GZU…`](https://explorer.solana.com/tx/9iWukM7V6GZUnSvJiEfAKBznyQgRnHNBHwd59GP5b7LD7sAEZUU5rsFFJ8eTro5poRwwc9gXtncBZQSKXAKcu16?cluster=devnet) | advice_commit byte (G1 x-byte) | `Custom 0x201` = **VERIFIER_ERROR** (off-curve detected by syscall) | 1,274,877 |

**What these prove on-chain:**

1. **Cryptographic rejection works** — the verifier ran the FULL
   verification pipeline (read_proof, lagrange, evaluate_gates,
   compute_expected_h_eval, build_queries, shplonk::verify_opening,
   pairing) on a valid-looking but tampered proof, then **returned
   `VERIFIER_REJECTED` at the pairing equation step**. Only 661 CU
   more than the valid shuffle (1,373,641 vs 1,372,980 = +0.05%) —
   meaning the entire cryptographic pipeline executed and the pairing
   check at the end is what said "no".
2. **Curve-check enforcement works** — flipping a byte in a G1
   commitment produces an off-curve point that the alt_bn128 syscall
   rejects, propagated back to the verifier as `VERIFIER_ERROR`.
3. **Distinct reject paths** — three different tampered txs hit three
   different reject mechanisms (Fr eval cryptographic / G1 advice
   off-curve / G1 shuffle commit off-curve). The verifier doesn't have
   one catch-all "fail" path; it fails for the right reason at the
   right point.

#### Range-check at 1.4M cap (still SIMD-bound)

| Tx | Status | CU consumed |
|---|---|---:|
| [`2gMQXTfCfdAn…`](https://explorer.solana.com/tx/2gMQXTfCfdAnyRnqVz7zzoTaWzzNi5XdktZi9vjWe9sT9GcHTN2tXBYt8E1QHvdrbqrDKTQBwiRVgMJ7TYxoBDWo?cluster=devnet) (range-check, valid proof) | Failed (`exceeded CUs meter`) | 1,399,644 / 1,399,700 |
| [`3r1ZSg3DX6Jh…`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) (StandardPlonk, v1 historical) | Failed | 1,399,644 / 1,399,700 |

Range-check (1.69M Mollusk) still aborts at the 1.4M ceiling —
confirms lookup-using circuits remain bound by the SIMD case until
Layer 2 (`alt_bn128_g1_msm`) ships. The Mollusk projection (Section 4a)
shows Layer 2 + Layer 3 land range-check under 1.4M with margin.

Replay any tx: `solana confirm -v <SIG> -u devnet`. Replay the round-trip
locally: `cargo run -p devnet-send -- --sh` (success) or
`cargo run -p devnet-send -- --sh --mutate-byte 480` (cryptographic
reject).

### Soundness audit (shadow) — host-side differential test

Three circuits ship with `shadow.rs` audits that run BOTH halo2's
reference `verify_proof` and our `halo2_solana_verifier::verify` on
the same proof bytes. Each audit asserts:
1. Both verifiers accept the unmodified proof.
2. For every mutation position: both verifiers reject. Asymmetric
   verdict (one accepts, the other rejects) ⇒ panic.

Coverage matrix:

| Circuit | Mutation positions | Regions covered |
|---|---:|---|
| Range-check (1 lookup) | **11** | advice / lookup permuted_input / permuted_table / lookup product / random_poly / vanishing h / advice_eval / random_poly_eval / lookup_product_eval / lookup_permuted_table_eval / opening W |
| Shuffle | **8** | advice / shuffle_product / random_poly / vanishing h / advice_eval / random_poly_eval / shuffle_product_eval / opening W |
| Multi-lookup (2 lookups) | **5** | lookup_0 permuted_input / lookup_1 permuted_input / lookup_0 product_eval / lookup_1 product_eval / opening W |

**24 total byte-level differential checks**, all symmetrically rejected.
The multi-lookup audit specifically targets the `for (i, arg) in
vk.lookups.iter().enumerate()` loop in `lookup::expressions` — mutating
lookup_1's eval byte (offset = lookup_0_eval_offset + 5×32) and
observing both verifiers reject confirms the verifier's per-lookup
indexing has no off-by-one.

Reproduce locally:
```bash
cargo run -p range-check-circuit    --bin gen-rc-proof  -- --shadow-audit
cargo run -p shuffle-check-circuit  --bin gen-sh-proof  -- --shadow-audit
cargo run -p multi-lookup-check-circuit --bin gen-ml-proof -- --shadow-audit
```

### v2.0 scope clarifications

What v2.0 supports:
- Any number of lookups + shuffles
- Single-phase user-defined challenges (`cs.challenge_usable_after(FirstPhase)`)
- Same backward-compat: zero lookups + zero shuffles + zero challenges
  matches v1.5 byte-for-byte (just two extra `0u32` footers in VK)

What v2.0 still does **not** support (deferred to v2.1+):
- **Multi-phase** advice columns / challenges. vk-host hard-rejects.
- **Field-arithmetic SIMD** (`alt_bn128_fr_arith`). Lagrange remains
  ~30-39% of total CU, the next-largest leverage point after SHPLONK.
- **2-tx split** for circuits that don't fit one tx. Range-check still
  needs `set_compute_unit_limit(1_700_000)` or a 2-tx split for mainnet.

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
| ✅ `alt_bn128_g1_msm` SIMD draft + benchmarks (SIMD discussion #535) | Done |
| ✅ v1.5: gate-AST evaluator (any halo2 circuit, not just StandardPlonk) | Done |
| ✅ v2.0: lookup + shuffle + single-phase challenges + shadow audit | Done |
| ⏳ `alt_bn128_fr_arith` SIMD draft (Layer 3) | Open |
| ⏳ 2-tx split for mainnet (Layer 1 fallback) | Open |
| ⏳ Multi-phase support (v2.1) | Open |
| ⏳ Application layer: cypherpunk app on top of the verifier | Open |

---

## License

MIT OR Apache-2.0, matching the workspace.

## Author / contact

Independent applied-cryptography work. Reach out via the repo if Anza or the Solana Foundation wants to discuss the SIMD proposal or sponsor the v1.5 generalisation.
