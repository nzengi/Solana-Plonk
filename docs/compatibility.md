# External Circuit Compatibility (Tier A3)

`halo2_solana_verifier` was built and primarily tested against six
in-tree circuits we wrote ourselves. Tier A3's question: does the
verifier accept proofs from circuits the team did *not* tailor for it?

## Tested external circuit shapes

### snark-verifier-sdk StandardPlonk — **PASS**

Source: `vendor/snark-verifier/snark-verifier-sdk/examples/standard_plonk.rs`
(Axiom team's example). Ported verbatim to `circuits/external-sp/` so the
test is self-contained and reproducible.

Shape — differs from our `circuits/standard-plonk/` in two ways:

| Property | our SP | external SP |
|---|---|---|
| advice columns | 3 | 3 |
| fixed columns  | 5 | 5 |
| instance columns | 0 | **1** |
| gate AST contains `Expression::Instance` | no | **yes** |
| gate | `q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0` | `… + q_const + instance = 0` |

This is the first circuit in our corpus that exercises the
`OP_INSTANCE` (0x03) opcode in the gate-evaluation bytecode and the
full `instance_queries`-driven query construction in
`build_queries`. Fibonacci has an instance column but only binds via
`constrain_instance` — its gate AST never references it.

**Result** (`cargo run -p external-sp-circuit --bin gen-external-sp`):

| Step | Outcome |
|---|---|
| `vk-host::compile_vk` | `Ok(885 B)` |
| `halo2_proofs::verify_proof` (self-verify) | `Ok(())` |
| **`halo2_solana_verifier::verify` (positive)** | **`Ok(true)`** ✓ |
| flip-one-byte-of-proof negative test | `Ok(false)` ✓ |
| substituted public input negative test | `Ok(false)` ✓ |

No verifier-side changes were required to land this circuit.

## What the test proves

* `gate_compat.rs` evaluates `Expression::Instance` correctly inside
  `OP_INSTANCE` (rotation-aware index lookup against
  `reconstruct_instance_evals` output).
* `vk.rs::parse_vk` decodes a VK that includes a non-empty
  `instance_queries` list.
* `plonk/proof_reader.rs` correctly absorbs the public inputs into
  the Keccak transcript at the protocol's right position (matches
  PSE-Halo2's `verify_proof` order).
* `plonk/lagrange.rs::reconstruct_instance_evals` works for the
  in-gate-query path, not just Fibonacci's `constrain_instance`-only
  path.
* The verifier's `build_queries` produces the same rotation-set
  structure SHPLONK expects.

### Multi-phase circuit (Tier A4 self-test) — **PASS**

Source: `circuits/multi-phase-check/` (in-tree synthetic). Specifically
constructed to exercise the v2.1 multi-phase VK appendix + the
phase-interleaved Fiat–Shamir loop in `proof_reader::read_proof`. Not
"external" in the snark-verifier sense, but the shape — advice columns
spread across multiple halo2 phases + a challenge squeezed mid-protocol —
is the load-bearing primitive every modern halo2-lib / halo2-axiom
circuit uses, so this is the gate the v2.1 verifier had to pass.

Shape:
- 1 advice column `a` in **FirstPhase** (phase 0)
- 1 advice column `b` in **SecondPhase** (phase 1)
- 1 user challenge `r` usable after FirstPhase
- gate: `q · (r · a + b) = 0` (zero-witness, trivially satisfied)

VK byte layout — for the first time — includes the v2.1 appendix:
```
num_phases = 2
advice_column_phase = [0, 1]
challenge_phase     = [0]
```

**Result** (`cargo run -p multi-phase-check-circuit --bin gen-mp-proof`):

| Step | Outcome |
|---|---|
| `vk-host::compile_vk` | `Ok(342 B)` (no longer hard-rejects multi-phase) |
| `halo2_proofs::verify_proof` (self-verify) | `Ok(())` |
| **`halo2_solana_verifier::verify` (positive)** | **`Ok(true)`** ✓ |
| flip-one-byte-of-proof negative test | `Err(SyscallFailed)` ✓ |

The proof-bytes order halo2 emits for multi-phase circuits — `read
phase-0 advice → squeeze phase-0 challenge → read phase-1 advice → squeeze theta → …` —
matches our `proof_reader::read_proof`'s new phase-interleaved loop
bit-for-bit. Single-phase circuits remain unaffected: when `num_phases = 1`
and the appendix is omitted, the loop collapses to the v2.0 batch-read
behaviour and all six legacy circuits keep passing.

## What hasn't been tested yet (honest gap list)

* **halo2-lib** (Axiom's chip library). With Tier A4 now landed, our
  vk-host accepts multi-phase circuits and our `proof_reader`
  interleaves the FS loop correctly. Building one of halo2-lib's
  `range_check_chip` style circuits would still require adding
  halo2-base and a non-trivial chip configuration; out of scope for
  this MVP compat test. The remaining technical gap for newer
  halo2-lib circuits is log-derivative lookups (Tier D2).
* **Scroll / Taiko zkEVM circuits.** Their public proofs are
  produced by halo2-axiom (a halo2 v0.3 fork) — should be wire-
  compatible but unverified against our verifier yet.
* **Log-derivative lookups (LogUp)** — modern halo2-lib uses these
  instead of Plookup. Verifier expects Plookup expressions; LogUp
  would fail at gate evaluation. Tier D2.

## Reproducing

```
cargo run -p external-sp-circuit --bin gen-external-sp
```

Expected output: `Tier A3 compat test complete: …`.
