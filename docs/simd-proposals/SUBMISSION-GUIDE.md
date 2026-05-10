# SIMD submission guide — `alt_bn128_g1_msm`

Step-by-step to land the SIMD draft as a PR on
[solana-foundation/solana-improvement-documents](https://github.com/solana-foundation/solana-improvement-documents).

The Solana SIMD process numbers proposals from the **PR number itself**: open
a PR with `XXXX` placeholders, take note of the PR number GitHub assigns,
then rename the file + update the frontmatter accordingly. Process spec:
[SIMD-0001](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0001-simd-process.md).

## Steps

### 1. Fork the SIMD repository
On GitHub, hit "Fork" on
<https://github.com/solana-foundation/solana-improvement-documents>.
Result: `https://github.com/<your-username>/solana-improvement-documents`.

### 2. Clone the fork
```bash
cd ~/Desktop   # or wherever
git clone https://github.com/<your-username>/solana-improvement-documents
cd solana-improvement-documents
git checkout -b alt-bn128-g1-msm
```

### 3. Drop the draft into `proposals/`
The draft lives in this repo at
`docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md`. Copy it over with the
SIMD repo's expected filename (XXXX prefix, no `simd-` prefix):

```bash
cp ~/Desktop/solana-poc/docs/simd-proposals/simd-XXXX-alt-bn128-g1-msm.md \
   proposals/XXXX-alt-bn128-g1-msm.md
git add proposals/XXXX-alt-bn128-g1-msm.md
git commit -m "Add SIMD: alt_bn128_g1_msm syscall"
git push origin alt-bn128-g1-msm
```

### 4. Open the PR
On the fork's GitHub page, click "Compare & pull request". Use:

- **Base repository:** `solana-foundation/solana-improvement-documents`
  base branch `main`
- **Head:** your fork's `alt-bn128-g1-msm`
- **Title:** `Add SIMD: alt_bn128_g1_msm syscall`
- **Body:** copy-paste the contents of [`PR-BODY.md`](PR-BODY.md)

### 5. Take note of the PR number, rename
GitHub will assign a PR number — say `#401`. The SIMD process treats this
number as the SIMD's official ID:

```bash
git mv proposals/XXXX-alt-bn128-g1-msm.md proposals/0401-alt-bn128-g1-msm.md
# Edit the file: frontmatter line `simd: 'XXXX'` → `simd: '0401'`
sed -i "s/simd: 'XXXX'/simd: '0401'/" proposals/0401-alt-bn128-g1-msm.md
git commit -am "Update SIMD number to 0401"
git push origin alt-bn128-g1-msm
```

(Replace `0401` with the actual PR number throughout.)

### 6. Tag reviewers
The most relevant core contributors for this SIMD are whoever shipped the
existing alt_bn128 syscalls — most recently:

- SIMD-0302 (G2 syscalls) authors
- SIMD-0284 (LE byte order) authors
- SIMD-0334 (pairing length check fix) authors
- Anza folks working on `programs/bpf_loader` and the alt_bn128 syscall
  surface in agave

Look at recent merged SIMDs in the same area to find the right reviewer
handles. Tag them in a follow-up PR comment ("@…, would appreciate a
look").

### 7. Iterate on review feedback
Reviewers may push back on any of:

- The CU cost model (4,000 + n × 2,400 — they may want concrete agave
  benchmarks before accepting)
- The grouped-vs-interleaved input layout decision
- The skipped subgroup check (already conventional for G1, should not be
  contentious)
- The fixed `n ≤ 1024` cap (Unresolved Question #1)
- The non-canonical scalar handling (Unresolved Question #2)

When in doubt, point to:
- The PoC repo `nzengi/Solana-Plonk` as a live reference impl + bench
- The Mollusk bench grid output (replayable)
- The devnet abort tx
  (`3r1ZSg3DX6JhWp3zupEqqUptyz8GGpFekoqkjfyepBZySDCScMo5DAZYtwHpAM6cFw2Zajfchw7K7hho6YGXUje5`)
  as concrete evidence that the existing syscall surface is insufficient

### 8. After merge
- Open an agave tracking issue under `programs/bpf_loader` for the
  implementation work.
- Open a feature-gate issue per the SIMD-0001 process.
- Wire `alt_bn128_g1_msm_be` into `solana-bn254` crate as a downstream
  ergonomics layer once the syscall lands.

## Estimated timeline

- PR submission + initial reviewer response: 1–2 weeks
- Substantive review + revision iteration: 4–8 weeks
- Acceptance + merge: 8–12 weeks
- Implementation + feature gate activation on mainnet: 6–9 months total
  from submission

This is in line with similar primitive-syscall SIMDs (0284, 0302, 0334).
