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

## What hasn't been tested yet (honest gap list)

* **halo2-lib** (Axiom's chip library). Building one of its
  `range_check_chip` style circuits would require adding halo2-base
  and a non-trivial chip configuration; out of scope for this MVP
  compat test. Halo2-lib's gates are still single-phase Plookup-using,
  so once Tier A4 (multi-phase) lands the only remaining gap should
  be log-derivative lookups (Tier D2).
* **Scroll / Taiko zkEVM circuits.** Their public proofs are
  produced by halo2-axiom (a halo2 v0.3 fork) — should be wire-
  compatible but unverified against our verifier yet.
* **Multi-phase circuits** — see Tier A4. Today
  `compile_vk` hard-rejects `cs.challenge_usable_after(SecondPhase)`.
* **Log-derivative lookups (LogUp)** — modern halo2-lib uses these
  instead of Plookup. Verifier expects Plookup expressions; LogUp
  would fail at gate evaluation. Tier D2.

## Reproducing

```
cargo run -p external-sp-circuit --bin gen-external-sp
```

Expected output: `Tier A3 compat test complete: …`.
