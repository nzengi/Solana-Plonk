# Add SIMD: `alt_bn128_g1_msm` syscall

> **Status (v2.1, 2026-05):** the numbers in this PR body predate
> the verifier's v2.1 Path B refactor (Montgomery batched inverse +
> cached Lagrange basis in `kzg::shplonk`). After Path B and the
> 3-tx split (Fibonacci end-to-end on devnet), every reference
> circuit fits the 1.4 M per-tx cap and the verifier is no longer
> blocked. The MSM syscall remains net positive (~15-20 % total
> verify CU saving and the path to fold larger circuits back into a
> single tx), but the case below is no longer "verifier cannot land
> at all" — see [`docs/cu_profile.md`](../cu_profile.md) for the
> updated profile.

## Summary

This PR proposes a new BN254 G1 multi-scalar multiplication syscall — `alt_bn128_g1_msm` — to replace the pattern of calling `alt_bn128_g1_multiplication_be` n times followed by `alt_bn128_g1_addition_be` (n − 1) times. The proposal sits in the `alt_bn128_*` syscall series alongside [SIMD-0284](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0284-alt-bn128-little-endian.md) (LE byte order) and [SIMD-0302](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0302-bn254-g2-syscalls.md) (G2 syscalls).

The syscall is justified by a concrete on-chain workload: a Halo2 KZG/SHPLONK verifier whose dominant cost is sequential G1 MSM. Per-stage CU profile, reference implementation, and Mollusk benchmarks are linked below.

## Headline numbers

* **Verifier total cost (Mollusk, k=4 StandardPlonk):** 2,710,424 CU
* **`shplonk::verify_opening` slice:** 1,667,016 CU = 62%
* **Devnet abort tx:** [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) — verifier hits Solana's 1.4M per-tx ceiling at 1,399,644 CU consumed
* **Projected impact** of this syscall on the verifier: −20% total, −32% on the SHPLONK slice

## Bench grid

Mollusk-driven CU comparison at n ∈ {2, 4, 8, 16, 32, 64} between (a) the today path of sequential `alt_bn128_g1_multiplication_be` syscalls, (b) pure-BPF Pippenger MSM, (c) pure-BPF naive scalar-mul-and-add, against (d) the proposed syscall's cost model `4000 + n × 2400`:

| n  |       sequential syscall |    Pippenger BPF |     naive BPF | proposed-SIMD model | ratio |
|---:|-------------------------:|-----------------:|--------------:|--------------------:|------:|
|  2 |                    8,558 |       18,188,362 |    12,743,035 |               8,800 | 0.97× |
|  4 |                   17,356 |       33,884,582 |    24,988,700 |              13,600 | 1.28× |
|  8 |                   34,964 |       58,145,235 |    49,953,590 |              23,200 | 1.51× |
| 16 |                   70,180 | **heap-OOM**     |   100,083,112 |              42,400 | 1.66× |
| 32 |                  140,616 | **heap-OOM**     |   199,589,804 |              80,800 | 1.74× |
| 64 |                  281,494 | **heap-OOM**     |   403,144,846 |             157,600 | 1.79× |

Three findings:
1. **Pippenger BPF runs out of heap at n ≥ 16** even with `request_heap_frame(256KB)`. The MSM has to land natively; pure-BPF Pippenger is not a viable path.
2. **Naive BPF MSM** blows past the 1.4M per-tx cap immediately — exactly why `alt_bn128_g1_multiplication_be` exists.
3. **Sequential syscall (today)** is linear and bench-able. The proposed SIMD beats it at n ≥ 4 (n = 2 is the wrong-direction crossover; spec note: callers with n ≤ 3 should keep the per-point syscall).

## Reference implementation + replay

* PoC repo: [github.com/nzengi/Solana-Plonk](https://github.com/nzengi/Solana-Plonk)
* Pippenger reference impl (no_std, arkworks): [`crates/g1-msm-ref`](https://github.com/nzengi/Solana-Plonk/tree/main/crates/g1-msm-ref) — 11/11 cross-check tests pass against naive scalar-mul-and-add at n ∈ {0, 1, 2, 4, 8, 16, 32, 64}
* Mollusk bench harness: [`programs/g1-msm-bench`](https://github.com/nzengi/Solana-Plonk/tree/main/programs/g1-msm-bench)
* Halo2 verifier on devnet: program [`KvBa8qgb…SK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet)
* Full per-stage CU profile + the strategic case: [`docs/cu_profile.md`](https://github.com/nzengi/Solana-Plonk/blob/main/docs/cu_profile.md)

To replay locally:

```bash
git clone https://github.com/nzengi/Solana-Plonk
cd Solana-Plonk

cargo run -p standard-plonk-circuit --bin gen-proof -- --write-golden
cargo build-sbf -- -p halo2-solana-verifier-program --features bpf-entrypoint,stage-trace
cargo test -p halo2-solana-verifier-program --features bpf-entrypoint,stage-trace --test cu_bench -- --nocapture

cargo build-sbf -- -p g1-msm-bench-program --features bpf-entrypoint
cargo test -p g1-msm-bench-program --test cu_grid -- --nocapture
```

## Why this SIMD now

The `alt_bn128_*` series so far has covered the primitives Groth16 needs (G1 add/mul/pairing, plus G2 ops via SIMD-0302). Halo2 KZG/SHPLONK — and any other verifier whose verifier-side commitment combination is a many-point MSM — does not fit those primitives. The Halo2 PoC is the first concrete case where the existing surface is provably insufficient, with on-chain evidence. The same syscall benefits Plonk variants and folding schemes; G1 MSM is the right primitive at the right scope.

## Author

[@nzengi](https://github.com/nzengi) — independent applied-cryptography work.

## Notes for reviewers

* The CU cost model (4,000 base + n × 2,400) is derived from native arkworks Pippenger benchmarks; agave's actual implementation should benchmark and confirm or adjust.
* I'm happy to iterate on (i) the input layout (grouped vs interleaved), (ii) the maximum-n cap, (iii) the canonical-scalar-mode question — see Unresolved Questions in the proposal.
* If a reviewer wants me to land a `simd-msm` cargo feature in the verifier crate that wires this through (host-validation only until activation), happy to do so as a follow-up.
