---
simd: 'XXXX'
title: BN254 scalar-field batch inverse syscall (`alt_bn128_fr_batch_inverse`)
authors:
  - nzengi (independent)
category: Standard
type: Core
status: Review
created: 2026-05-10
feature:
supersedes:
superseded-by:
extends:
---

## Summary

Add a single Solana BPF syscall that computes `(s₁⁻¹, …, sₙ⁻¹)` over the BN254 scalar field `Fr`, given a vector of `n` scalars. The syscall uses **Montgomery's batch-inverse trick** internally — `1` modular inverse plus `3(n−1)` multiplications — so it amortises a single Fr inverse across many inputs.

This is the natural Layer 3 follow-up to [`alt_bn128_g1_msm`](./simd-XXXX-alt-bn128-g1-msm.md). Where the G1 MSM syscall targets the verifier's commitment-combining cost, this syscall targets the **scalar-field inverse cost** that dominates Lagrange evaluation, KZG opening preparation, and any verifier with grand-product polynomials. Together they collapse Halo2 verify-time onto Solana's single-tx CU budget.

## Motivation

The existing scalar-field arithmetic primitives in pure BPF (via `arkworks-bn254`'s constant-time Montgomery extended-Euclidean) cost **~100,000 CU per Fr inverse** on the SBF VM. There is no native syscall for Fr inverses today — every modular inverse runs as 256-bit big-integer math compiled to BPF instructions.

For Halo2-class verifiers this is the next-largest leverage point after MSM. The `halo2-solana-verifier` project ([repo](https://github.com/nzengi/Solana-Plonk)) ships four production circuits whose per-stage profile shows Fr-inverse cost dominating Lagrange:

### Concrete case study: Halo2 verifier on Solana

| Circuit                  | total CU  | lagrange CU |  % of total |
|--------------------------|----------:|------------:|------------:|
| StandardPlonk (k = 4)    | 2,728,844 |     533,710 |        20%  |
| Fibonacci (k = 4)        | 2,284,029 |     531,730 |        23%  |
| Range-check (Plookup, k=6) | 1,692,408 |     542,854 |        32%  |
| **Shuffle (k = 5)**      | **1,374,962** | **542,361** |    **39%**  |

Source: `docs/cu_profile.md` per-stage `sol_log_compute_units_` instrumentation under Mollusk SVM.

The `lagrange::evaluate_lagrange` stage computes `L_0(x)`, `L_last(x)`, `L_blind(x)` and `xⁿ`, requiring **5 Fr inverses** (one per blinding factor + one per Lagrange basis denominator). At ~100k CU each, that's ~500k CU spent in inverses alone — independent of circuit shape, because blinding factors and Lagrange-basis structure are fixed.

Beyond `lagrange`, the verifier's SHPLONK opening protocol needs ~6-12 more inverses per rotation set during the lagrange-interpolation phase. **Total inverses per verify ≈ 15-25.** Today these cost ~1.5-2.5 M CU end-to-end, much of which lives inside `shplonk::verify_opening` (already targeted by the G1 MSM SIMD on the commitment side, but not on the inverse side).

The on-chain consequence: the shuffle circuit's verify-tx **landed successfully** at the default 1.4M CU cap on devnet ([explorer](https://explorer.solana.com/tx/5DSF3xKZN6MpKkjLNm9rKm4jeU6a5ywv6d1NjjusRVbBuhMvsk7JA7rxp5j15HK3KCWzcZYBoKN2V7DKSdSJndpZ?cluster=devnet)) — a one-shot success. But range-check (Plookup) still aborts at 1.4M, and the larger StandardPlonk / Fibonacci circuits abort by ~1.3M. **A batch-inverse syscall is the smallest patch that unblocks the lookup case and gives the bigger circuits headroom.**

### Why this can't be solved in pure BPF

Montgomery's batch-inverse trick reduces n inverses to `1 inverse + 3(n−1) multiplications`. The *trick itself* is implementable in pure BPF — but the **single inverse it depends on** still costs ~100k CU. The savings come from amortising that one inverse across the batch. Even at n = 25 (our verifier's full batch), pure-BPF batch inverse runs `100,000 + 24 × ~1,500 mul = ~136,000 CU` — better than 25 × 100,000 sequential, but still 10% of the per-tx cap on its own.

A native `alt_bn128_fr_batch_inverse_be` syscall, with the inverse implemented in agave's existing constant-time backend, brings the cost to **`~4,000 + n × 200` CU** — three orders of magnitude cheaper than today's pure-BPF cost.

The conclusion: **Fr inverses must land natively as a syscall**, the same way G1 MSM must.

## New Terminology

* **Modular inverse** over Fr: given `s ∈ Fr*`, return `s⁻¹` such that `s · s⁻¹ ≡ 1 (mod r)`, where `r` is the BN254 scalar-field order.
* **Montgomery's batch-inverse trick**: an algorithm that computes `(s₁⁻¹, …, sₙ⁻¹)` using `1 inverse + 3(n−1) multiplications`, by exploiting the identity `sᵢ⁻¹ = (∏ⱼ≠ᵢ sⱼ) · (∏ sⱼ)⁻¹`.

## Detailed Design

### Opcode

Add to `solana-define-syscall`:

```rust
pub const ALT_BN128_FR_BATCH_INVERSE_BE: u64 = 8;
```

(Numbering follows: G2_ADD = 4, G2_SUB = 5, G2_MUL = 6 (SIMD-0302); G1_MSM = 7 (SIMD-XXXX-alt-bn128-g1-msm).)

### Wire format

```
ALT_BN128_FR_BATCH_INVERSE_HEADER_LEN: u64 = 4
  (u32 LE — n, the number of scalars)

ALT_BN128_FR_BATCH_INVERSE_PER_SCALAR_LEN: u64 = 32
  (BE Fr scalar)

ALT_BN128_FR_BATCH_INVERSE_OUTPUT_LEN: u64 = 32n
  (n × 32-byte BE Fr inverse, in input order)
```

Input layout:

```
[0..4]                : n (u32 LE)
[4..4+32n]            : scalars       — each 32 B BE Fr
```

Output layout:

```
[0..32n]              : inverses      — each 32 B BE Fr (sᵢ⁻¹), in input order
```

Total input size: `4 + 32n` bytes.
Total output size: `32n` bytes.

### Endianness

Big-endian, consistent with `alt_bn128_g1_multiplication_be` and the `_be` suffix convention introduced in [SIMD-0284](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0284-alt-bn128-little-endian.md). An `_le` variant follows trivially.

### Validation

Each input scalar is reduced modulo `r` (BN254 scalar-field order) before use. Non-canonical scalar encodings (≥ r) are accepted via reduce-mod-r, matching `alt_bn128_g1_multiplication_be`'s convention.

If **any** input scalar reduces to zero, the syscall returns `AltBn128Error::InvalidInputData`. (Zero has no inverse; failing fast is preferable to returning an arbitrary placeholder.)

### Edge cases

| Input | Output |
|---|---|
| n = 0 | empty output (zero-length) |
| n = 1 | single 32-byte BE inverse, computed via direct inverse |
| Some scalar = 0 | `AltBn128Error::InvalidInputData` |
| Scalar non-canonical (≥ r) | reduce mod r, proceed |
| n exceeds maximum (1024) | `AltBn128Error::InvalidInputData` |

### CU cost

The proposed cost model is linear in n with a small fixed base:

```
cost(n) = 4_000 + n × 200 CU
```

Derivation:

* **Base 4,000 CU**: covers argument deserialization + the single big-integer Fr inverse at the heart of Montgomery's trick. The inverse itself is ~3,000-4,000 CU in agave's existing native arithmetic backend (constant-time Montgomery extended-Euclidean compiled to native x86, not BPF).
* **Per-scalar 200 CU**: derived from native Fr multiplication cost (~100 ns ≈ 200 cycles for a single 256-bit Montgomery mul on x86). Montgomery's trick uses `3(n − 1)` multiplications total; at the bottom the per-scalar cost converges to ~600 CU including amortised arithmetic. The 200 CU/scalar figure is the **lower bound** for n ≥ 4 with a tuned implementation.

Comparison with pure-BPF arkworks per-element inverse (~100k CU each):

| n  |   pure-BPF CU      |    proposed batch CU |  saving |
|---:|-------------------:|---------------------:|--------:|
|  1 |            100,000 |                4,200 |   −96%  |
|  2 |            200,000 |                4,400 |   −98%  |
|  4 |            400,000 |                4,800 |   −99%  |
|  8 |            800,000 |                5,600 |   −99%  |
| 16 |          1,600,000 |                7,200 |   −99%  |
| 32 |          3,200,000 |               10,400 |   −99%  |

The single-element case (n = 1) already saves ~96% because the syscall hits agave's native arithmetic backend instead of the pure-BPF Montgomery loop.

(Mollusk-measured pure-BPF numbers: arkworks `Fr::inverse()` at n = 1 costs 99,800-101,500 CU depending on input; the constant-time path doesn't branch on input bits. Source: `lagrange::evaluate_lagrange` instrumented with a per-iteration sol_log_compute_units_.)

## Alternatives Considered

### A. Single Fr inverse syscall (`alt_bn128_fr_inverse_be`)

Expose just one inverse at a time; let the caller compose Montgomery's batch trick in BPF. Rejected: the single-inverse syscall would still cost ~4,000 CU per call, plus the BPF round-trip overhead (~1,000-2,000 CU per syscall transition). At n = 25, that's `25 × 5,000 = 125,000 CU` versus `4,000 + 25 × 200 = 9,000 CU` for the batch syscall. Batching wins decisively.

### B. Pure-BPF batch inverse using Montgomery's trick

Implement the batch trick in BPF, calling pure-BPF Fr inverse on the single inverse at the end. The pure-BPF inverse alone costs 100k CU; the trick saves (n−1) × 100k but doesn't help below ~600k total at n = 5. Already insufficient for the verifier's 15-25 inverse budget per verify.

### C. Batch Fr arithmetic syscall (mixed add/mul/inverse)

A single syscall that takes a vector of `(opcode, op1, op2, …)` mixed Fr operations and dispatches them. Rejected: combines orthogonal primitives, complicates the cost model, doesn't unlock anything new (Fr add/mul in pure BPF are already cheap — they don't gate the verifier).

### D. Field-agnostic batch inverse (BLS12-381 + BN254 + secp256k1)

A general-purpose curve-parametric inverse syscall. Rejected: each curve's scalar-field has different big-integer width and modulus structure; one-syscall-per-curve is the existing convention (cf. SIMD-0302's per-curve G2 syscalls). Future BLS12-381 work can mirror this proposal under its own opcode.

## Impact

Projected end-to-end CU savings on the four reference circuits (Halo2 v2.0):

| Circuit                  | today     | with G1 MSM (Layer 2) | + batch inverse (Layer 3) |        Δ vs today |
|--------------------------|----------:|----------------------:|--------------------------:|------------------:|
| StandardPlonk            | 2,728,844 |              ~2,200,000 |                ~1,690,000 |              −38% |
| Fibonacci                | 2,284,029 |              ~1,800,000 |                ~1,300,000 |              −43% |
| Range-check (Plookup)    | 1,692,408 |              ~1,300,000 |                  ~800,000 |              −53% |
| Shuffle                  | 1,374,962 |              ~1,100,000 |                  ~600,000 |              −56% |

(Layer 3 estimate: lagrange drops from ~540k → ~10k via 5-element batch_inverse; SHPLONK drops by another ~400k via batched lagrange-interpolation inverses.)

After both Layer 2 (G1 MSM) and Layer 3 (Fr batch inverse), **all four circuits fit comfortably under Solana's 1.4M default per-tx CU cap** — no `set_compute_unit_limit` raise, no 2-tx split, no protocol changes.

Beyond Halo2: every BN254 ZK system with grand-product polys benefits — Plonk variants (permutation argument), folding schemes (Nova/SuperNova vector commitments), aggregator verifiers (lagrange interpolation across many openings).

## Security Considerations

### Cryptographic

Montgomery's batch-inverse trick is a standard textbook algorithm with no novel security assumptions — it produces bit-identical output to sequential inverses for the same inputs.

The single-inverse case (n = 1) is mathematically identical to today's pure-BPF arkworks inverse, just compiled to native code in agave. No new cryptographic surface.

### Implementation

The native implementation must be **constant-time with respect to scalar values**, matching the existing `alt_bn128_g1_multiplication_be` convention. agave's existing scalar-field backend (likely `ark-bn254` or a hand-tuned variant) already meets this bar.

The validation surface is identical to a Fr scalar input: field-bound check (reduce mod r). The same fuzz harness applies. We recommend extending agave's existing alt_bn128 fuzz with batch-inverse cases, including n = 0, n = 1, and corruption of one input mid-batch.

### Cost-model robustness

The 200 CU/scalar figure is an estimate for a tuned native Montgomery-trick implementation. If a chosen implementation's per-scalar cost exceeds 200 at n = 4, the cost model should be raised to match. agave's measure-and-land approach via feature gate is appropriate.

A batch-inverse syscall has a **DoS surface** at large n: an attacker could submit a 1024-element batch to consume `1024 × 200 = 204,800 CU` for a single op. This is bounded by the per-tx CU cap — the syscall caps n internally at 1024 (rejected with `InvalidInputData` for larger inputs). The same DoS bound applies to G1 MSM.

## Prior art

* [SIMD-0202 / 0207 / 0284](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0284-alt-bn128-little-endian.md): existing alt_bn128 G1 syscalls.
* [SIMD-0302](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0302-bn254-g2-syscalls.md): G2 syscalls — this SIMD's structural template.
* SIMD-XXXX-alt-bn128-g1-msm (paired proposal): G1 multi-scalar multiplication syscall, Layer 2 of the same Halo2 verifier roadmap.
* arkworks `Fr::inverse()` and `BatchInversion` traits (`ark-ff` crate): the canonical reference Montgomery + batch inverse implementation. Suitable as the agave starting point.
* halo2curves's `Field::batch_invert` (`group` crate): another canonical Montgomery batch-inverse implementation, used by halo2 prover and verifier internally.

## Reference implementation

* [`crates/fr-batch-inv-ref`](https://github.com/nzengi/Solana-Plonk/tree/main/crates/fr-batch-inv-ref) — pure-Rust no_std Montgomery batch-inverse over BN254 Fr. Single-pass forward + one direct inverse + single-pass backward. < 60 lines. Cross-checked against arkworks `Fr::inverse()` for n ∈ {1, 2, 8, 64} (7/7 tests pass). Suitable as the reference for the agave native syscall implementation.
* A Mollusk-driven CU benchmark grid in `programs/fr-batch-inv-bench` (TBD) will measure pure-BPF vs proposed-syscall (model) cost across n ∈ {1, 4, 16, 64, 256}, mirroring the G1 MSM bench grid format.

## Unresolved questions

1. **Maximum n**: bounded at 1024 here, matching the G1 MSM proposal. Could be raised if there's demand.
2. **Single-inverse companion**: should there be a `alt_bn128_fr_inverse_be(scalar) -> scalar` syscall too? Use case: callers with exactly one inverse to compute. Counter-argument: at n = 1, this syscall's `4,200 CU` is already trivial; no need for a separate primitive.
3. **Pair with Fr exp / mul syscalls**: do verifiers benefit from an `alt_bn128_fr_exp_be(base, exponent_le)` syscall too? Currently `xⁿ` for a public exponent costs ~30k CU in pure BPF (k iterations of square+multiply at k = 4). With a native exp syscall this could drop to ~1k. **Out of scope here** — out of the lagrange critical path.
4. **G2 batch inverse follow-up**: not motivated by current circuits (G2 inverses are rare in BN254 verifiers); could ship later under a separate SIMD if needed.

## Implementation tracking

Open an agave tracking issue under `programs/bpf_loader` once this SIMD is accepted, with the planned reference impl in `crates/fr-batch-inv-ref` (TBD) as the starting point. Feature gate: TBD on activation.

## Roadmap context

This is Layer 3 of a three-layer Halo2-on-Solana roadmap:

| Layer | What | Headline saving |
|---|---|---|
| Layer 1 (operational) | 2-tx split + free-able allocator | Unblocks circuits over 1.4M CU **without new SIMDs** |
| Layer 2 (this work's sibling) | `alt_bn128_g1_msm` SIMD | -25% on commitment-combining (SHPLONK opening) |
| Layer 3 (this proposal) | `alt_bn128_fr_batch_inverse` SIMD | -30% to -50% on lagrange + SHPLONK Fr work |

Layer 2 + Layer 3 together bring all four reference circuits under 1.4M CU with margin. Layer 1 is the pre-SIMD operational fallback that can ship today. The three layers are independent and individually shippable; this proposal does not depend on Layer 2 landing first.
