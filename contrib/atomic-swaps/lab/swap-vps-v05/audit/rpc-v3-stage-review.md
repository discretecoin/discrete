# RPC SBPFv3 staging — independent mechanical review

Reviewed 2026-09-08 UTC by consensus_review. Accepted for the parent's separately authorized synthetic real-RPC qualification. No runtime test of the new program was performed by this reviewer, and this acceptance does not import historical real-RPC results.

Scope: `rpc-v3-stage`, `run_solana_rpc_v3.py`, their frozen originals and the author's offline receipts. The separate new `run_paired_rpc_v3.py` lifecycle wrapper is outside this mechanical stage manifest and receives its own review.

## Exact artifacts

| Artifact | SHA256 |
|---|---|
| `rpc-v3-stage-manifest.json` | `a8d1a9a8c5297c2c82bd2eb465932b0123d3cd511797923640266e9cf28750cb` |
| `rpc-v3-stage/mechanical-runtime.diff` | `0914f3ed6fbd4c8bfa3b6f012a545ff1ea3cf74991da1c6b710c318090b37230` |
| New standalone `driver.py` | `1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3` |
| New paired `bindings.py` | `4421104ed9e80b517cd4420aaf0e964ef11f97bcff297728e11a823ea8f93465` |
| New standalone package manifest | `e7bb57d8091aa58aedc2cbcb221bba9faed86f693eb462273ab41f1ea3325140` |
| New paired package manifest | `c5a745f258406be5cbbeb19937f9c6db88ccb4708a48fe0166863d7925864e02` |
| `run_solana_rpc_v3.py` | `0d2c551b0b8a2a918586dc1f8f52d81c89cec9866f4451905febdfee4833c400` |
| Offline qualification receipt | `e456c7bec68f3b2f60915038a7ba1a8362fa78497b01b6b75ab4d0cbf5e054ec` |
| Referenced Rust ELF, 32912 bytes | `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7` |

## Independent checks

All 33 files/logs referenced by the top manifest matched their hashes. Both nested package manifests matched all their entries (5 standalone and 8 paired); all 5 runtime dependency pins in paired bindings matched actual sibling files. All 17 original source-copy hashes also matched the frozen originals, so the comparison did not rely on a stale declared baseline.

The runtime change is exactly:

- Standalone driver: old C ELF hash/9248-byte size becomes the new Rust ELF hash/32912-byte size. AST comparison after masking only these two constants is equal.
- Paired bindings: only the standalone driver's hash changes. The other four dependencies remain exact byte copies.
- Standalone outer wrapper: package directory, expected driver hash and measured SBF artifact path change to the separate v3 paths.

Eleven of the 17 copied artifacts remain byte-identical: requirements, both guard suites, paired implementation and runner, both historical comparison diffs, and the four Linux helpers. The other six are the two runtime files and four README/test-manifest updates. No old run directory, signed intent, transaction receipt or historical outcome is relabeled as a new-program result.

The driver retains the immutable ProgramData authority-None condition, exact on-chain payload hash/size, expected genesis and Agave-version gates, finalized receipt/transaction-byte checks, durable send attempts, duplicate ingress requirement and bounded identical-wire recovery. The paired runner and journal remain byte-identical: current admission, post-persistence age guard, actual XDS public witness, foreign-first handoff, exact amounts and 0.01 XDS fees retain the prior reviewed behavior. This staging does not strengthen or weaken those contracts.

## Evidence and limits

The author's bound offline receipt has identical before/after hashes and exit code 0 for the mechanical check, 11 standalone guards, 20 paired guards and 10 outer-helper controls. Each referenced log hash was independently recomputed and its PASS footer read; no skipped test appears in these logs. The reviewer did not rerun them or operate a network.

These are offline controls. New-program deployment/finalization, the six standalone RPC cases, the two actual XDS/Solana paired cases, process-tree cleanup, combined resource capacity, crash recovery and production USDC/mainnet remain separate gates. The new ELF's source/ABI/VM evidence is reviewed separately. No frozen V03/V04/Core or original harness was edited for this review. The parent maintains the project routing/status documents while the qualification task remains active.
