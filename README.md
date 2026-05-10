# halo2-solana-verifier — Halo2 KZG/SHPLONK on Solana, with a SIMD case

Two artifacts in one repo:

1. **A circuit-shape-agnostic PSE-Halo2 BN254/KZG/SHPLONK verifier on the Solana BPF VM.** First of its kind on Solana — prior art (groth16-solana, sp1-solana, risc0-solana) all wrap to Groth16 first; this one verifies Halo2 natively. v1.5 (2026-05-10) replaced the StandardPlonk-specific gate with a generic RPN bytecode evaluator: the same `.so` accepts any halo2 circuit without lookups/shuffles/phase-challenges.

2. **A concrete proposal for `alt_bn128_g1_msm`, a new Solana syscall.** The verifier's per-stage CU profile motivates it: 62% of the cost is sequential G1 multi-scalar multiplication, exactly the operation the proposed syscall replaces. SIMD discussion: [#535](https://github.com/solana-foundation/solana-improvement-documents/discussions/535).

## Headline numbers

* **StandardPlonk verify (Mollusk, k=4):** 2,728,844 CU under v1.5's generic AST (vs 2,710,424 CU under v1's hard-coded gate — +0.7% AST overhead).
* **Fibonacci verify (Mollusk, k=4):** 2,284,029 CU — second circuit shape, exercises rotation::next + instance column path.
* **Devnet on-chain abort tx:** [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) — v1 verifier hit Solana's 1.4M per-tx ceiling at 1,399,644 CU consumed, mid-way through `shplonk::verify_opening`.
* **`alt_bn128_g1_msm` SIMD impact (projected):** −20% total verify CU, −32% on the SHPLONK slice. Bench grid in [`programs/g1-msm-bench`](programs/g1-msm-bench/) confirms the underlying syscall-layer ratios (1.66× at n=16, 1.79× at n=64).

## Documents

* **[`docs/cu_profile.md`](docs/cu_profile.md)** — full per-stage CU profile, devnet artifact list, comparison vs prior art, replay instructions.
* **[`docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md`](docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md)** — formal SIMD draft following the SIMD-0001 template: motivation, syscall surface, byte layout, CU cost model, alternatives, security, prior art.

## Repo layout

```
crates/verifier/                  no_std verifier crate (BN254-only, generic gate AST)
crates/vk-host/                   halo2 VK → flat on-chain bytes compiler
crates/g1-msm-ref/                Pippenger reference impl for the SIMD draft
circuits/standard-plonk/          v1 test circuit (StandardPlonk regression baseline)
circuits/fibonacci/               v1.5 test circuit (rotation::next + instance column)
programs/verifier-program/        Pinocchio BPF program wrapping the verifier
programs/verifier-program/tests/  Mollusk-driven CU benchmark (cu_bench + cu_bench_fib)
programs/g1-msm-bench/            naive vs Pippenger BPF vs syscall-seq bench grid
clients/devnet-send/              off-chain client for the devnet roundtrip
docs/cu_profile.md                CU profile + SIMD case + v1.5 multi-circuit table
docs/simd-proposals/              formal SIMD drafts
```

## Quick start

```bash
# 1. Off-chain provers — both circuits, both golden vectors.
cargo run -p standard-plonk-circuit --bin gen-proof -- --write-golden
cargo run -p fibonacci-circuit       --bin gen-fib-proof -- --write-golden

# 2. Build verifier .so.
cargo build-sbf -- -p halo2-solana-verifier-program --features bpf-entrypoint

# 3. Mollusk benches — same .so, both circuits.
cargo test -p halo2-solana-verifier-program --features bpf-entrypoint --test cu_bench     -- --nocapture  # StandardPlonk
cargo test -p halo2-solana-verifier-program --features bpf-entrypoint --test cu_bench_fib -- --nocapture  # Fibonacci

# 4. Per-stage CU profile (StandardPlonk).
cargo build-sbf -- -p halo2-solana-verifier-program --features bpf-entrypoint,stage-trace
cargo test -p halo2-solana-verifier-program --features bpf-entrypoint,stage-trace --test cu_bench -- --nocapture

# 5. MSM bench grid (sequential syscall vs proposed-SIMD model).
cargo build-sbf -- -p g1-msm-bench-program --features bpf-entrypoint
cargo test -p g1-msm-bench-program --test cu_grid -- --nocapture

# 6. Devnet roundtrip (requires ~5 SOL devnet in default keypair).
cargo run -p devnet-send
```

## On-chain artifacts (devnet)

| | |
|---|---|
| Program | [`KvBa8qgb…SK8N`](https://explorer.solana.com/address/KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N?cluster=devnet) |
| Verify-attempt tx (1.4M abort) | [`3r1ZSg3D…XUje5`](https://explorer.solana.com/tx/3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5?cluster=devnet) |
| Data account | [`HvRcK2dg…tgNkA`](https://explorer.solana.com/address/HvRcK2dg5LJzxHscdpozsZpHaRDhkVN6exYiwLVtgNkA?cluster=devnet) |

## Status

| | |
|---|---|
| Verifier tests | 70/70 passing (v1.5) |
| `g1-msm-ref` cross-check (Pippenger vs naive) | 11/11 passing |
| `cargo build-sbf` | Clean (no stack-frame warnings) |
| Mollusk StandardPlonk | 2,728,844 CU end-to-end |
| Mollusk Fibonacci | 2,284,029 CU end-to-end |
| Mollusk MSM bench grid | n ∈ {2,4,8,16,32,64}, 3 modes — see grid table in `cu_profile.md` |
| Devnet | Deployed; verify-attempt tx confirms 1.4M ceiling hit |
| SIMD discussion | [#535](https://github.com/solana-foundation/solana-improvement-documents/discussions/535) |

## License

MIT OR Apache-2.0.
