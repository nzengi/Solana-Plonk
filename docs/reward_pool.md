# reward-pool — ZK-gated SOL escrow

A small Solana program that locks SOL in a per-(authority, nonce) PDA
and only releases it when a halo2 proof verifies on-chain. First app
on Solana built on the halo2-solana-verifier from this repo.

The hot path is one tx: `reward-pool::CLAIM` does a CPI into
`verifier-program::STAGE2`, gets back a Solana `Ok`, and atomically
transfers the locked SOL to the claimer.

> **Status note (v2.1):** the on-chain CLAIM flow documented here
> uses the **2-tx** verifier path (CPI's into `verifier::STAGE2`
> after the claimer pre-runs `STAGE1`). It still works on devnet
> (the headline CLAIM tx
> [`2EbQHB17…ME47`](https://explorer.solana.com/tx/2EbQHB17RVvYsVqBKbmA5c3kSUovrGXZzUo6iLcqU2r4wV8R8kdAFvLeyHj2Heg2Abub6FbAzqDZEFnZLeqBME47?cluster=devnet)
> ran at 1.06 M CU end-to-end). After the v2.1 Path B refactor
> (`docs/cu_profile.md`) the 1-tx verifier flow shrank to 1.29 M CU
> for range-check; the same CLAIM design will work on top of the
> v2.1 3-tx split too, just with a STAGE3 CPI instead of STAGE2.
> No reward-pool source changes are required — the CPI target name
> is the only thing that needs to flip when the demo is rebuilt
> against the v2.1 binary.

## Why this demo

The verifier on its own only answers `accept / reject`. Most of the
hackathon-side question is "what does that buy you?" — and the cheapest
honest answer is "you can gate a SOL transfer on a ZK proof". This
program is the smallest end-to-end story that demonstrates exactly
that, with three explicit tx classes a viewer can replay.

## Lifecycle

```
INIT_POOL  →  (claim attempts)  →  CLAIM (success)
   ↓                                   ↓
 lock SOL                         transfer SOL
                                  pool.claimed = true

CLOSE_POOL (only before claim, authority-only) →  refund SOL
```

The pool is single-claim (`max_claims = 1` baked into the design). Once
`CLAIM` succeeds the pool is closed via the `claimed` flag; any further
`CLAIM` attempt fail-fasts at ~1,800 CU with `0x501 POOL_ALREADY_CLAIMED`.

## Account model

`init_pool`:

```
[0] authority   (signer, writable, fee-payer of init)
[1] pool_pda    (writable, will be created)         seed: [POOL_SEED, authority, nonce_le_8]
[2] system_program
```

`claim`:

```
[0] payer            (signer, writable, gets reward on success)
[1] pool_pda         (writable, drained for reward)
[2] data_account     (read, owned by verifier-program; holds vk + proof + kzg + public_inputs)
[3] stage_state_acct (read, owned by verifier-program; holds Stage1Output bytes)
[4] verifier_program (executable, target of the CPI)
```

`close_pool`:

```
[0] authority (signer, writable, receives refund)
[1] pool_pda  (writable, drained)
```

## Pool state byte format

93 bytes, hand-rolled (no Borsh dependency to keep the program small).

```
[0..8]    magic = "RWPL0001"
[8..12]   version u32 LE = 1
[12..44]  authority pubkey (32 B)
[44..76]  vk_hash_required (32 B) — keccak256 of the canonical halo2 VK bytes the pool accepts
[76..84]  reward_lamports u64 LE
[84]      claimed (u8: 0 = unclaimed, 1 = claimed)
[85..93]  nonce u64 LE — disambiguates pools by the same authority
```

## Replay protection / claimer binding

Three layers, in order of cost:

1. **Pool ownership check.** `pool_pda.owner == reward-pool program id`.
   Without this, anyone could pass a fake account and we'd happily
   write the `claimed` flag and try to transfer lamports the program
   doesn't own.

2. **VK hash gate.** The Stage1Output blob (in stage_state_acct) carries
   `keccak256(vk_bytes)` from the verifier. The pool only accepts
   proofs whose VK hash matches what the authority specified at init.
   Different circuit / different VK → reject at `0x503 VK_HASH_MISMATCH`.

3. **Stage1 payer match.** Verifier-program's `run_stage1` records
   `accounts[2].address()` (the signer) into `Stage1Output.payer`.
   The pool's `claim` requires the same signer here. Eve can't replay
   Alice's prepared stage_state by signing with her own key — the
   payer field would diverge → `0x504 CLAIMER_HASH_MISMATCH`.

For circuits with public inputs (e.g. bound-range-check) the verifier's
own Fiat–Shamir transcript provides additional binding: if the
public_inputs vector at verify time differs from what the prover used,
the squeezed challenges diverge and STAGE2 returns failure inside the
CPI → reward-pool returns `0x505 VERIFIER_FAILED`.

The pool intentionally does **not** re-derive a public-input hash
itself. The verifier already enforces correctness via Fiat–Shamir;
adding pool-side binding would just hardcode the demo circuit's
public-input shape.

## CU budget

The headline transaction — `reward-pool::CLAIM` with the range-check
circuit's stage_state_acct — measured on-chain at 1,065,591 CU
([explorer](https://explorer.solana.com/tx/2EbQHB17RVvYsVqBKbmA5c3kSUovrGXZzUo6iLcqU2r4wV8R8kdAFvLeyHj2Heg2Abub6FbAzqDZEFnZLeqBME47?cluster=devnet)).
Breakdown:

| Layer | CU |
|---|---:|
| reward-pool entrypoint + state read + replay checks | ~4,400 |
| CPI dispatch overhead | ~1,000 |
| `verifier-program::STAGE2` (skip-FS proof parse + build_queries + SHPLONK + pairing) | 1,060,790 |
| **total** | **1,065,591 / 1,399,700** |

Fits the 1.4 M default per-tx cap with ~334 k CU of margin.

`reward-pool` itself is tiny — host build is 80 k of BPF compared to
the verifier-program's 632 k.

## Error codes

| Code | Meaning |
|---|---|
| `0x500` `POOL_OUT_OF_BOUNDS`     | (reserved; not currently emitted) |
| `0x501` `POOL_ALREADY_CLAIMED`   | second `CLAIM` against a single-claim pool |
| `0x502` `POOL_AUTHORITY_MISMATCH`| `close_pool` signer ≠ pool.authority |
| `0x503` `VK_HASH_MISMATCH`       | proof's VK hash ≠ pool.vk_hash_required |
| `0x504` `CLAIMER_HASH_MISMATCH`  | claim signer ≠ stage1.payer |
| `0x505` `VERIFIER_FAILED`        | the CPI'd `verifier::STAGE2` returned an error |
| `0x506` `STAGE_STATE_INVALID`    | stage_state account bytes wouldn't deserialise as a `Stage1Output` |
| `0x507` `POOL_NOT_OWNED`         | pool_pda is owned by a different program |

## Off-chain orchestration

The reference client is `clients/reward-pool-cli`. Three subcommands:

```
reward-pool-cli init  --reward <lamports> --nonce <u64> \
                      --reward-pool-program <addr>

reward-pool-cli claim --authority <pubkey> --nonce <u64> \
                      --reward-pool-program <addr>

reward-pool-cli close --nonce <u64> \
                      --reward-pool-program <addr>
```

`claim` orchestrates 7 transactions (data account create, 2 LOAD
chunks, stage_state create, STAGE1 verify, CLAIM with CPI). All other
subcommands are 1 tx each. The default keypair (`~/.config/solana/id.json`)
is used as both authority and claimer; for a production-style demo
with two parties, two keypair files would be needed.

## Devnet artifacts

Program ID: `13AspyxTTyVs5PE6mApQDuspMDD5tmuWrBuV2278Qh4q`.

Initial deploy:
[`44n2VnYo…TweY`](https://explorer.solana.com/tx/44n2VnYoTstFGYks6jPHZGnPN2mQDh7FWd55civRpPWGam2xPduVceZuCxhQSkKi5FS7az6ZkzzZgaG69HoKTweY?cluster=devnet).
Skip-FS upgrade:
[`2ALjY8UC…fYLM`](https://explorer.solana.com/tx/2ALjY8UCnrZeKbfPgtPfaYuQQcvc8ZzV6r5G9bpdRhT8AMeCsSFUDGARpt4TzKpcoXXcQwZExk29FqSzTqpZfYLM?cluster=devnet).

End-to-end claim flow on the range-check pool (nonce = 2):

| Step | Tx |
|---|---|
| init_pool, locked 0.1 SOL | [`2hGRJEUS…dedF8`](https://explorer.solana.com/tx/2hGRJEUSSD1m2Lq12h4HtMuS1x5cmpxFV7hTJQkPKvwVNsv5TFtd4qn6evof7typwMvXcsQU5G9aYGFBufTdedF8?cluster=devnet) |
| Pool PDA | [`2bQgYp78…qjpG`](https://explorer.solana.com/address/2bQgYp78SaWxu7wHcwtn2y9ADW52P3oEadEWxSn3qjpG?cluster=devnet) |
| verifier::STAGE1 | [`3nWawDwz…icxe`](https://explorer.solana.com/tx/3nWawDwzqQjbeTnUgeLda8B5no6yqt9GwGFdtwrZg9vBrhzSLR3Nu7kDDWRt1H7sB5UA9k1abesy82FqwPa1icxe?cluster=devnet) |
| reward-pool::CLAIM (CPI STAGE2 + transfer) | [`2EbQHB17…ME47`](https://explorer.solana.com/tx/2EbQHB17RVvYsVqBKbmA5c3kSUovrGXZzUo6iLcqU2r4wV8R8kdAFvLeyHj2Heg2Abub6FbAzqDZEFnZLeqBME47?cluster=devnet) |
| Re-claim attempt → 0x501 | (next `cargo run` after CLAIM) |
| close orphaned pool nonce=1 | [`4vyYhBoS…MGLS`](https://explorer.solana.com/tx/4vyYhBoSfPtMmBmc14uSUKLdRLbr9gTjPDGwV4QPBaZCfqfyNUEmmJ5GwkkHmEEtAP6XPDbn3fGsaGhyHFHXMGLS?cluster=devnet) |

Replay any of these via `solana confirm -v <SIG> -u devnet`.

## What this is not

* Not a private mixer. The proof says "I know an x in `[0, 16)`",
  which is trivially satisfiable — anyone can produce such a proof.
  Production claim-gating would use `bound-range-check` (a ZK-bound
  claimer-hash gate, see `circuits/bound-range-check/`); that circuit
  doesn't fit a single-tx CPI today (stage 2 ~1.5 M CU vs 1.4 M cap)
  and would need either a 3-tx split or the `alt_bn128_g1_msm` SIMD
  to land.

* Not multi-claim. `claimed: bool` field caps the pool at one claim;
  refactoring to `claim_count: u32` is straightforward but out of
  scope for the demo.

* Not collusion-proof against the authority. The authority can always
  `close_pool` before someone claims, recovering the locked SOL. To
  remove this you'd add a deadline / expiry timestamp to the pool
  and gate `close_pool` on it.

These are honest limitations, kept out of scope so the working flow
fits in one Phase of the 3-week hackathon plan.
