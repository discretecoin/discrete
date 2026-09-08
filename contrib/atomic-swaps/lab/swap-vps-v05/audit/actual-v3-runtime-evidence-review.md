# Actual SBPFv3 / XDS runtime — independent evidence audit

Reviewed 2026-09-08 UTC. The retained evidence supports **six passing actual Solana RPC cases, two passing actual XDS/Solana paired cases, and persistence of 23 settled public accounts across one clean validator/target stop/start followed by final stop**. No contradiction invalidating those bounded results was found. The paired run used four actual XDS daemon processes and two actual wallet processes alongside Agave in the owned private namespace.

This reviewer performed no VPS access, node operation, transaction, signing, source change or broad knowledge-base update. Public local artifacts, exact source and collection metadata were inspected. A separate local program recomputed provenance, public-wire fields, transaction IDs, amounts, fees, admission arithmetic and account equality: **136 checks PASS**, exit 0. These are evidence checks, not 136 new runtime test scenarios.

## Immutable evidence bindings

All paths below are relative to `evidence/swap-vps-v05/`.

| Artifact | SHA256 |
|---|---|
| `remote-evidence/solana/escrow-rpc-v3-run01-receipt.json` | `8de5d0729292b6755c1c6374a9aa0991c289480ab20254e86adcbc3790a6637d` |
| Matching standalone log | `218c6013cf65c3ede650b62c0b80b570b6107ef7bb19ecaa7031b26fad242948` |
| `remote-evidence/solana/paired-rpc-v3-run01-receipt.json` | `8ea2f95d5d628d09bdf7c46ac4b8ebee544ff608f27162ada0f803e413a11dbb` |
| Matching paired log | `a627487df75a4f5e9a86ca96f7e9c33f374c5284d904572e8b1d14f2f04968af` |
| `remote-evidence/public-metadata-v3/v3-paired-runtime-public.json` | `805645f7f08f8e6d7939a75ded8a0a3f8bb414765f40c0b88824624676ca099a` |
| `remote-evidence/public-metadata-v3/v3-settled-state-restart-public.json` | `596a042fce64940d7ea17e1c3926a28841c1f6bd99348bcf1c00fa947a1da721` |
| `remote-evidence/public-metadata-v3/paired-wire/export-manifest.json` | `db0ec37265dbe2170097f00c81f9d055b54aa7e8ddef4b31f2679474f6407b04` |
| `audit/actual-v3-runtime-evidence-check.json` | `e342f1eff8c563c6440f47b3cf3f526be076a807f7c24f1cd90b8fbe78632cc3` |
| Audit checker source / log | `4d2b60c56f4de25aa3ae0cd3814e43d79464ee58645332f27df8755e1a54cfb7` / `a9096f7ceff7d8ad733bd71cae9b52b6690ea9dea7096dda1bcd0a6ce4f9ca68` |

Both outer receipts have exit 0, PASS, unchanged before/after snapshots and matching full log hashes. The standalone and paired collection records dated `20260908T054520897084Z` and `20260908T055850731486Z` bind the same file bytes, lengths and hashes. The additional public export manifest matches all ten exported artifacts. Two `terms.public.json` files are explicitly public projections with private `refund_rho` omitted and original source hashes recorded; they are not mislabeled byte-identical copies. No original private terms, role keys, wallet or journal database was read by this reviewer.

The raw paired `run.json` hash is `d4d7d6ecc06329adb274f1ea411b79a2adf4d7bb5b87816e55100a5185a68a4b`, exactly the outer receipt's `public_run_sha256`; its parsed object equals the embedded object. An initial reconstruction produced a different hash solely because originally integer rent keys `82,165,192` become strings after JSON parsing and sort lexically as `165,192,82`. Exact raw export and a diff resolved this formatting question; no value differs.

## Chain, program and real-process identity

- Private Solana genesis: `H6SXasBhyzMhf5qCmcXwRUGU4UQGzS9Jc5zEjXKxtpxe`; all financial receipt confirmations reviewed here are finalized.
- Agave 4.2.2, reported feature set 565236538; program `cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN`; reviewed Rust ELF 32912 bytes, SHA256 `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`.
- The strict driver `1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3` enforces authority None and the exact payload. Loader authority-removal provenance and pruned-history limitations remain in `audit/agave-v3-loader-evidence-review.md`; this run does not invent fresh historical signature status after pruning.
- XDS private genesis in the exported live observations: `03e1c12d4662263fb7c41e683c96b0cab7e2d7e06bdc0be08a3ecd079bebb2a1`.
- Actual paired native snapshot equals the entire successful native build receipt snapshot: head `f3f84ce6ba44f5391a5bec78418a5d78052a1b3d`, 1696 source-file identities and 45 binary identities. Build receipt SHA256 `4c69814fff2137258d2aa777d630aa7b2fff1e7ff1f05bf8df9e0a2177010c5e`. Equality to this build does not establish full CTest success.
- Process evidence at 05:47:47 UTC records daemon PIDs 12314–12317 and wallet PIDs 12343/12357; all six share `net:[4026532666]` and the paired service cgroup. Actual executable hashes agree with the run: `discreted` `7286557d93ff83756e994778222c87b9e99ce1e28ad868959ac386e6a0d510ab`; `simplewallet` `f2a2f09e99100c44dc96a5c183cbf74366cd5f64861bd565afd19d82b6479add`. No Bitcoin process was observed in this particular process capture.

The old C ELF still listed among frozen native fixture files is an unchanged baseline artifact. The actual Solana program, separate RPC stage and live immutable-profile checks bind the Rust ELF above.

## Six actual RPC cases

The synthetic mint is `EdmxWPmx2WH6WgFfTdu9xfkYf3k1g5wD1zccTVySEEh1`, with six decimal places. Each fixture creates 10,000,000 units and swaps 1,234,567 units (**1.234567 synthetic tokens**). It is not Circle USDC.

1. Funding finalized at slot 797: source 8,765,433; vault 1,234,567; destinations zero; state funded.
2. Wrong-secret transaction finalized at slot 830 with exact Custom 4110. Token balances and all state bytes equal the funded snapshot. Its 5000-lamport transaction fee is present despite rejection; independently, payer debit and the sum of all account deltas equal that fee.
3. Claim finalized at slot 863: vault zero, claimant 1,234,567, terminal status 2. An identical replay has a new accepted-for-relay attempt (index 8), handoff slot 864 and observation slot 866. Pinned executed assertions compare the same original receipt/wire, unchanged token/state accounting and no additional relayer fee. This is one identical-replay observation window, not general crash/expiry recovery.
4. Subsequent ordinary owner transfer finalized at slot 898, moving those tokens to the other destination while retaining the status-2 tombstone.
5. Early refund finalized at slot 1058, before immutable deadline 1154, with exact Custom 4111. The pinned executed assertions compare unchanged funded state; independently checked exported fee balances total 5000 lamports.
6. Refund finalized at slot 1186, after deadline 1154; a subsequent ordinary transfer finalized at 1218. Vault zero, total fixture units conserved, status-3 tombstone retained.

Full standalone per-intent signed wire records and duplicate pre/post relayer balance values are not part of this export. Those detailed assertions are supported by the exact pinned executed driver and matched logs/results; this reviewer did not independently re-sign or revalidate every Solana signature.

## Paired amount, fee and first-disclosure evidence

One XDS atom here is **0.01 XDS**. Both funding wires independently decode to a 1001-atom conditional output; the prepared fee is one atom. Success funding outputs are `[1001,6608]`; abandonment funding outputs `[1001,5606]`. Both transaction IDs independently match SHA3-256 of the entire exported canonical wire, using the frozen chain hash implementation in `core-timer/src/crypto/hash.c:35` and the serializer at `CryptoNoteSerialization.cpp:195`.

| Case | Alice XDS atoms before → after | Bob XDS atoms before → after | Foreign settlement |
|---|---:|---:|---|
| Success | 7610 → 6608 | 0 → 1000 | Alice receives 1,234,567 units; claim slot 1633 < deadline 2365 |
| Abandonment | 6608 → 6606 | 1000 → 1000 | Bob's refund account receives 1,234,567 units; refund slot 2564 ≥ deadline 2562 |

Success costs Alice 10.02 XDS and credits Bob 10.00 XDS. Abandonment returns the principal less the second fee, leaving a total 0.02 XDS cost across the two transactions. The base fee remains 0.01 XDS **per transaction**.

The public node-3 claim witness independently matches raw wire, transaction ID `04b2ef09cfae2ef945ce1ed16885666beaf3c5a9410baf5844e3bf7b39c0285c`, main-chain block hash/index 28 and exact prior funding transaction/output 0, branch 1. Its raw public preimage hashes to the hashlock in both contracts. The raw claim output is 1000 atoms against the independently decoded funding value 1001: **one-atom spend fee**, also equal to RPC input/output totals. No private preimage fallback was used by the pinned runtime path (`runner.py:93–104,219–223`). The independent checker did not cryptographically reverify ML-DSA signatures; actual validators did transaction admission. The source funding input's earlier origin output is not separately exported, so funding-fee evidence additionally relies on the prepared result and actual wallet accounting.

Foreign funding finalized first at slots 1598 and 1796 before XDS funding/admission. Exported observations show success with one confirmation denied, then the same contract at eleven confirmations eligible. The live fee quote is 5000 lamports; Alice's 50,000,000-lamport balance exceeds the two-fee reserve. The successful admitted observation has 734 foreign slots and 21 XDS blocks remaining, with finalized observations 31 slots behind the processed clock and a 0.0061-second read duration. These are observed laboratory budgets, not a finality guarantee from eleven blocks.

The two cases have distinct hashlocks. Successful disclosure uses the public on-chain XDS witness; abandonment leaves coordinator exposure false. Alice subsequently transfers the claimed tokens with her own authority; after abandonment Bob transfers refunded tokens back to his source account. The settled tombstones remain unchanged.

Each case's six recorded setup/fund/settle/ordinary operations totals **60,000 lamports in fees** and **10,384,320 lamports in account-creation outflows**. The latter is retained account funding, not a transaction fee. The 60,000 total is 20,000 + 15,000 + 5,000 + 10,000 + 5,000 + 5,000, reflecting different signer counts; do not describe every setup/fund instruction as a 5000-lamport transaction. The full pre/post balance sums of the exported foreign funding, settlement and subsequent-transfer receipts agree with their 10,000/5000 fees. The earlier separate 50,000,000-lamport Alice fee-reserve funding is outside these per-case totals.

## What the five paired negative records actually establish

| Record | Actual observation/action | Boundary of the evidence |
|---|---|---|
| Absent foreign state, success | Finalized RPC returns null at slot 1469; fixture snapshot rejects | Before setup/registration; no claim intent or handoff |
| Underconfirmed XDS, success | Actual journal handoff denies first exposure at one confirmation; intent remains prepared and transaction absent | A real first-disclosure denial, then the same prepared wire succeeds after eleven confirmations |
| Absent foreign state, abandonment | Finalized RPC null at slot 1666; fixture snapshot rejects | Again before setup, not a second journal handoff denial |
| Insufficient real slot margin | Actual admission changes from eligible at 732 slots remaining to denied at exactly 128 remaining against budget 128 | Real chain read and predicate; neither secret-bearing claim intent was prepared or sent |
| Consumed foreign escrow | Finalized status 3 / empty vault after refund at slot 2564 fails the funded-state predicate | Actual state predicate with no claim intent; not a post-refund disclosure attempt |

Thus there are five recorded negative observations, including one actual journal disclosure denial. Describing all five as end-to-end rejection transactions would overstate the evidence.

## Resource envelope

| Metric | Six-case RPC | Two-case pair |
|---|---:|---:|
| Shared-cgroup samples | 56 | 111 |
| First-to-last sample span | 275.04 s | 541.56 s |
| Sampled maximum RAM | 629,141,504 bytes / 600.00 MiB | Same |
| Sampled maximum swap | 830,693,376 bytes / 792.21 MiB | 1,054,085,120 bytes / 1005.25 MiB |
| CPU consumed over sample span | 273.64 s / 99.49% of one CPU | 539.46 s / 99.61% |
| Increase in `memory.events high` | 3708 | 7971 |
| `oom`, `oom_kill`, `oom_group_kill` | All zero at every sample | All zero at every sample |

The cgroup's `memory.peak` remains 641,892,352 bytes (612.16 MiB) from the first sample; it is cumulative and is not a newly measured per-run peak. Maximum simultaneous RAM plus swap for the pair is 1,682,681,856 bytes (1604.73 MiB). Peak recorded ten-second memory pressure averages are `some=5.73`, `full=3.37` for the pair. The wrapper records its `ended_utc` before final evidence sampling; therefore its 540.16-second timestamp interval is slightly shorter than the 541.56-second complete resource sample span.

The captured workload ran without an OOM event in this shared cgroup. It was CPU-saturated and depended substantially on swap/reclaim. This supports a short bounded qualification on this small host, not sustained concurrency, a production capacity margin, no global host memory pressure, or a long-duration load claim.

## Clean restart persistence

The actual restart receipt binds corrected control `5f1b644bfd009e2cf7744094f73993d42f12d758bc6f5e7abe037bd1ae366326`, strict driver and the exact six/two-case receipt hashes. The retained execution log reports PASS and the same receipt hash; parent reports successful process exit. Log SHA256 `ea5cd16715549fb9a9c547ef526289d831a35d0be40b096e48a38d6833d5a547`.

From 06:06:17 to 06:06:28 UTC (11.034 seconds), old validator PID **11551** disappears and new PID **12547** starts. Both `/proc/.../exe` hashes equal `d723f3a99fa3f5b3df6841fc04ac0d8b5302837689d43a07222aa2125b6713d1`. Finalized slot advances **4307 → 4308**, genesis/profile remain identical.

All **23 account address sets, owners, executable flags, lamports, data lengths and full data hashes** are exactly equal before/after. They comprise four escrow states, sixteen token accounts, mint, Program and ProgramData. Independently, the four 192-byte state hashes equal the four final case tombstones from the six/two-case receipts, establishing that the restart compared these settled fixtures. Both initial stop and final cleanup capture all eight named units inactive, zero MainPID where applicable and empty ControlGroup. The final result leaves the owned target stopped.

This was one clean target/validator stop/start. It is not VPS reboot, power loss, process-kill crash, recovery from an older backup, wallet/journal restore, websocket resubscription or a new swap after restarting.

## Remaining evidence boundaries

Full UnitTests/CTest qualification is separate and not promoted to PASS here. The post-restart log describes an independently running UnitTests retry; it does not contain a terminal result. These receipts do not establish mainnet activation, real Circle USDC, downstream GUI acceptance, autonomous recovery, production key custody or long-duration load performance. No such readiness conclusion follows from this audit.
