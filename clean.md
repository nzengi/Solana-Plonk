Been working on a PSE Halo2 (BN254/KZG/SHPLONK) verifier for Solana BPF the last few weeks and got it deployed on devnet. As far as I can tell it's the first one of its kind on the chain — groth16-solana, sp1-solana, risc0-solana all wrap down to Groth16 before hitting the chain. Wanted to write this up before turning it into a formal SIMD because there are a few design questions I'd rather hash out first.

**The concrete problem**

Under Mollusk, a k=4 StandardPlonk proof completes in 2,710,424 CU. Per-tx mainnet cap is 1.4M, so on devnet the tx aborts at 1,399,644 CU. On-chain evidence: `3r1ZSg3D…XUje5`.

Per-stage breakdown puts 62% of the cost in `shplonk::verify_opening`'s rotation-set inner loop — basically a sequential Σᵢ scalarsᵢ · pointsᵢ over BN254 G1, done today as individual `alt_bn128_g1_multiplication_be` syscalls. That's exactly what a batched MSM syscall would replace.

**Why you can't fix this in pure BPF**

Pippenger window-NAF in pure BPF runs into the heap. Each window needs a `Vec<G1Projective>` of size 2^c; with c = ⌊log₂ n⌋ + 2 and ~43 windows for 254-bit scalars, you're already at 33KB at n=8 and well past Solana's 256KB heap limit at n≥16. Numbers from Mollusk on a fresh build:

| n | sequential `alt_bn128_g1_mul` | Pippenger BPF | naive BPF |
|--:|--:|--:|--:|
| 2 | 8,558 | 18,188,362 | 12,743,035 |
| 4 | 17,356 | 33,884,582 | 24,988,700 |
| 8 | 34,964 | 58,145,235 | 49,953,590 |
| 16 | 70,180 | **heap OOM** | 100,083,112 |
| 32 | 140,616 | **heap OOM** | 199,589,804 |
| 64 | 281,494 | **heap OOM** | 403,144,846 |

Naive scalar-mul-and-add is already dead past n=4 (which is why `alt_bn128_g1_multiplication_be` exists). Pippenger has to be native.

**The proposal**

A new syscall next to SIMD-0284's G1 ops and SIMD-0302's G2 ops:

```rust
pub const ALT_BN128_G1_MSM_BE: u64 = 7;

// input:  [n: u32 LE | scalars: 32B BE × n | points: 64B BE × n]  = 4 + 96n bytes
// output: 64B BE G1Affine, identity = all zeros
```

Grouped layout (scalars then points) — maps directly to arkworks `VariableBaseMSM::msm`, no internal reorder needed. Validation does per-point field check + curve equation; subgroup check is skipped since G1 cofactor is 1, consistent with the existing G1 syscalls.

Cost model: `4_000 + n × 2_400` CU. Beats sequential `n × 3,840 + (n−1) × 334` for n ≥ 4. At n=2 it's a slight wrong-direction crossover (~0.97×), so callers with n ≤ 3 should stick with the per-point syscall.

For the verifier this projects to roughly −20% total CU and −32% on the SHPLONK slice. Doesn't get verify under 1.4M on its own — you'd still need either a 2-tx split or a follow-up `alt_bn128_fr_arith` for the Lagrange Fr inverses (another ~20%). But it's the highest-impact piece and anything doing verifier-side commitment combination on BN254 benefits: Plonk variants, folding schemes, batched Groth16, all of it.

**What's in the repo**

- `crates/g1-msm-ref` — no_std Pippenger reference, cross-checked against arkworks naive at n ∈ {0, 1, 2, 4, 8, 16, 32, 64}, 11/11 pass
- `programs/g1-msm-bench` — Mollusk bench harness that produced the table above
- `docs/cu_profile.md` — the Halo2 verifier with per-stage CU breakdown
- SIMD draft markdown in closed PR #535 (following the discussion-first convention)

**A few things I'm not sure about**

Input layout — I went grouped (scalars then points) because it matches arkworks and solana-bn254 ergonomics and avoids an internal reorder. EIP-2537 went interleaved for BLS12-381. If there's a reason to flip I'm open to it, just don't see it yet.

Max n cap — proposing n ≤ 1024 to bound input-deserialization DoS surface. Could go tighter, or drop the cap entirely and rely on tx size + CU limits. Not sure which is cleaner.

Canonical scalar handling — current `alt_bn128_g1_multiplication_be` reduces non-canonical scalars mod p. I matched that for consistency, but verifiers (groth16-solana, this Halo2 thing) often want strict-canonical rejection for input hygiene. Worth a `_strict_be` variant, or just pick one mode?

Cost model — `4_000 + n × 2_400` comes from native Pippenger benchmarks at small n. Agave folks will want to bench the actual implementation before locking this in. If anyone has existing Pippenger numbers in the codebase, a rough sanity check would help.

G2 MSM — does `alt_bn128_g2_msm` make sense as a follow-up, or is the G2 use-case rare enough that pairing-based aggregation covers it?

If anyone from Anza or Firedancer has a strong opinion on layout or cost model, early feedback would save a review round. Otherwise happy to keep iterating here before filing a fresh PR.