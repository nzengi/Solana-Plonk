# 2-tx Split — Design Note

> **Status note (v2.1):** the 2-tx split documented below is the
> **historical predecessor** of the current 3-tx split. The 2-tx flow
> still works (range-check on devnet) and the on-chain
> [`STAGE1_TAG = 0x02`](../programs/verifier-program/src/lib.rs) /
> `STAGE2_TAG = 0x03` instruction tags remain wired in the .so. But
> after the Path B refactor (Montgomery batched inverse + cached
> Lagrange basis in `kzg::shplonk`) and the 3-tx split shipping in
> v2.1, the production path for larger circuits is now **3-tx**
> (`STAGE1 → STAGE2A → STAGE3`, tags `0x02 / 0x04 / 0x05`) — see
> [`EVIDENCE.md`](EVIDENCE.md) for the Fibonacci 3-tx devnet evidence
> and [`README.md`](../README.md#numbers) for the post-Path-B CU
> table. Two paths matter going forward: 1-tx for small circuits
> (shuffle, range-check post-Path-B both fit in a single tx), and
> 3-tx for everything else.

The verifier originally shipped with a 2-tx split path so circuits
whose single-tx total CU exceeded Solana's 1.4 M per-tx cap could
still verify end-to-end on devnet, no SIMD landing required.

This document covers what the 2-tx split is, the byte format passed
between the two transactions, the replay-protection mechanism, and
which circuits actually fit (and which now have a better fit via
3-tx instead).

## What gets split where

`halo2_solana_verifier::verify` is structured as a linear pipeline:

```
parse_vk → read_proof → lagrange::evaluate_lagrange → reconstruct_instance_evals
        → compute_expected_h_eval → aggregate_h_commitment → omega_last
        → build_queries → shplonk::verify_opening → alt_bn128_pairing
```

The natural seam is right after `aggregate_h_commitment` and
`omega_last`. That's where Lagrange (~540 k CU on every circuit)
finishes and SHPLONK (the per-circuit-variable big slice) starts.

| Stage | Includes | Range-check Mollusk |
|---|---|---:|
| Stage 1 | parse_vk, read_proof, lagrange, reconstruct_instance_evals, compute_expected_h_eval, aggregate_h_commitment, omega_last, serialise → PDA | ~860 k |
| Stage 2 | parse_vk, parse_proof_no_fs, replay-binding check, build_queries, SHPLONK opening, pairing | ~1,060 k |

`parse_proof_no_fs` is a parallel parser that skips the Fiat-Shamir
keccak squeezes (challenges are already in the stage 1 PDA, replay
hashes guarantee the proof bytes haven't changed). Saves ~75 k CU on
stage 2 vs `read_proof`.

## The PDA byte format

Stage 1 writes a `Stage1Output` struct into a per-payer account
(owned by the verifier program; allocated off-chain via
`system_program::create_account` before stage 1). Format:

```
[0..4]    serialised_len    : u32 LE
[4..]     Stage1Output bytes:
   magic                  : "STG10001"
   version                : u32 LE = 1

   theta, beta, gamma, y, x, shplonk_y, shplonk_v, shplonk_u  (8 × Fr BE)
   user_challenges_count  : u32 LE
   user_challenges        : (user_challenges_count) × Fr BE

   l_0, l_last, l_blind, xn                                   (4 × Fr BE)

   expected_h_eval        : Fr BE
   h_commitment           : G1 (64 B BE x ‖ y)
   omega_last             : Fr BE

   instance_evals_count   : u32 LE
   instance_evals         : (instance_evals_count) × Fr BE

   vk_hash                : keccak256(vk_bytes)            (32 B)
   proof_hash             : keccak256(proof_bytes)         (32 B)
   instance_hash          : keccak256(public_inputs flat)  (32 B)

   payer                  : 32 B Solana pubkey
   nonce                  : u64 LE
[serialised_len + 4 ..]   zero-padding
```

Total fixed bytes: 668 (excluding length prefix and variable Vecs).
Worst-case allocation: 4 + 668 + 32 × (32 + 32) = 2,720 bytes; 4 KB
allocated to leave headroom.

Length prefix lets stage 2 deserialise from a fixed-size account
without knowing the circuit shape upfront.

## Replay protection

Three classes of attack the design protects against:

**1. Different payer reusing someone else's stage 1.**

Mitigation: stage 1 writes the original payer's pubkey into the
`Stage1Output`. Stage 2 reads it and rejects if the current signer
differs (`STAGE_AUTH_MISMATCH`, error code `0x203`).

**2. Same payer concurrently running two verifies, account collision.**

Mitigation: each verify gets a fresh `nonce: u64`. Stage 1 stores it
in the `Stage1Output`; stage 2 rejects if the instruction-data nonce
differs. The off-chain client allocates a separate stage_state
account per nonce (so concurrent verifies don't collide on the
account itself either).

**3. Tampered data account between stage 1 and stage 2.**

The data account holds `(vk_bytes, proof_bytes, kzg_vk, public_inputs)`.
If an adversary swaps any of these between txs, stage 2's challenges
(from the trusted stage 1 PDA) wouldn't match the swapped proof's
required challenges, and the pairing equation would fail anyway. But
that's a "wastes CU then rejects" outcome rather than fail-fast.

Mitigation: stage 1 stores `keccak256(vk_bytes)`, `keccak256(proof_bytes)`
and `keccak256(public_inputs)` in the `Stage1Output`. Stage 2
re-computes them from the current data account and rejects on
mismatch (`STAGE_REPLAY_MISMATCH`, error code `0x204`). Fast-fail at
~5 k CU after parse rather than running the whole shplonk loop.

This is the pattern Light Protocol uses for its `groth16-solana`
multi-tx flow — `commitment-hash binding` between txs.

## Devnet evidence

Range-check (Plookup), the only circuit whose stage 2 fits under
1.4 M, lands successfully end-to-end:

| Tx | Status | CU |
|---|---|---:|
| [`4TrEPtG2…8jYn`](https://explorer.solana.com/tx/4TrEPtG21v4EZHeiNYEDy4T4HRQUJWdAcWDFn9p1rGDsThUSk8xu6zG41jEER7aeFn842s9KZLbPwEbW4oKi8jYn?cluster=devnet) (range-check stage 1) | Ok | 859,721 |
| [`64HeT7V1…t1BC`](https://explorer.solana.com/tx/64HeT7V16TFwRRGPVN3yTR5WXpbmC2eJhLyHFvGujCvH6omivnStAEL9wtkPKe933dG83CJcVUHDyYJw12pbt1BC?cluster=devnet) (range-check stage 2) | Ok | 1,063,172 |

This is the **first lookup-using verifier on Solana to land
end-to-end**. The sister tx pair from the same circuit on the
1-tx path aborts at the 1.4 M cap (
[`2gMQXTfC…BDWo`](https://explorer.solana.com/tx/2gMQXTfCfdAnyRnqVz7zzoTaWzzNi5XdktZi9vjWe9sT9GcHTN2tXBYt8E1QHvdrbqrDKTQBwiRVgMJ7TYxoBDWo?cluster=devnet)
).

## What still doesn't fit

Stage 1 succeeds for every tested circuit. Stage 2 is constrained by
the SHPLONK slice + ~75 k stage-2 baseline overhead (parse_vk +
parse_proof_no_fs + replay check + build_queries + pairing).

| Circuit | Stage 1 | Stage 2 | Verdict |
|---|---:|---:|---|
| Range-check (Plookup) | 859,721 ✓ | 1,063,172 ✓ | full success |
| Multi-lookup (2 Plookup) | 954,773 ✓ | cap exhausted at 1,399,644 | partial |
| Fibonacci | 1,045,360 ✓ | cap exhausted at 1,399,644 | partial |
| StandardPlonk | 1,007,953 ✓ | cap exhausted at 1,399,644 | partial |

Multi-lookup, Fibonacci, and StandardPlonk all have SHPLONK slices
between 1.18 M and 1.67 M. Stage 2's baseline overhead (~225 k)
plus those slices puts every one of them past the 1.4 M cap.

Two paths to unblock the rest:

* **3-tx split.** Push `parse_proof_no_fs` + `build_queries` into a
  middle stage, leaving stage 3 with only `shplonk::verify_opening` +
  `pairing`. Range-check + Multi-lookup definitely fit at 3-tx.
  Fibonacci probably fits. StandardPlonk's 1.67 M SHPLONK slice still
  doesn't.
* **Layer 2 SIMD** (`alt_bn128_g1_msm`). Cuts SHPLONK by ~32 % across
  the board. Combined with the 2-tx split, every reference circuit
  including StandardPlonk fits one tx. Tracked in
  `docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md`.

## Stage1 / Stage2 instruction layout

```
STAGE1_TAG = 0x02

instruction_data: [STAGE1_TAG, nonce u64 LE]   = 9 bytes total

accounts: [
  data_account     (read,  owned by verifier program),
  stage_state_acct (write, owned by verifier program),
  signer           (signer, fee payer),
]
```

```
STAGE2_TAG = 0x03

instruction_data: [STAGE2_TAG, nonce u64 LE]

accounts: [
  data_account     (read,  owned by verifier program),
  stage_state_acct (read,  owned by verifier program),
  signer           (signer, must match Stage1Output.payer),
]
```

`accounts[2].address()` is what the verifier program reads as the
signer's pubkey. The stage_state account is allocated off-chain
(`system_program::create_account` with `owner = verifier_program_id`).
After stage 2 succeeds the account can be left orphaned (paying ~5 mSOL
of permanent rent) or closed via a separate close-ix path.

## Error codes

| Code | Meaning |
|---|---|
| `0x202` `STAGE_INVALID` | stage_state bytes did not deserialise — wrong magic / version / size |
| `0x203` `STAGE_AUTH_MISMATCH` | signer ≠ Stage1Output.payer, OR instruction nonce ≠ Stage1Output.nonce |
| `0x204` `STAGE_REPLAY_MISMATCH` | data account changed between stages — vk_hash / proof_hash / instance_hash mismatch |
| `0x205` `STAGE_PDA_TOO_SMALL` | stage_state account size < serialised Stage1Output |

## References

* `crates/verifier/src/stage_state.rs` — `Stage1Output` struct + serialisation + `compute_replay_hashes`.
* `programs/verifier-program/src/lib.rs::run_stage1` and `run_stage2` — on-chain dispatch.
* `clients/devnet-send/src/main.rs::run_two_tx_flow` — off-chain orchestration.
* `crates/verifier/src/plonk/proof_reader.rs::parse_proof_no_fs` — Fiat-Shamir-skipped parser.
