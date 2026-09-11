# Native Timer candidate — independent interim evidence review

Reviewed 2026-09-08 UTC from local, imported evidence. Scope ends at the first Timer CTest matrix and the four subsequent integration receipts collected at 05:34:19 UTC, plus the later export of that same first matrix's XML and LastTest log. No test rerun, SSH, node operation, credential access, or source change was performed for this review. Only this report was written. A later UnitTests retry or Agave run is outside this snapshot.

**Evidence consistency: PASS for the examined artifacts. Native qualification: incomplete.** The exact candidate builds; 38 of 39 CTest entries pass, and four separate integration invocations pass 12/12, 12/12, 58/58 and 4/4. The first CTest invocation exits 8 because UnitTests reaches its external 1800-second timeout. Separate passing suites do not turn that invocation into 39/39.

## Candidate and source binding

The local `core-timer` checkout is clean on `[local branch]`, HEAD `f3f84ce6ba44f5391a5bec78418a5d78052a1b3d`. Its comparison with frozen `1e947a8e66ec963e8e634b14fec29343ef7d8822` changes exactly `src/System/Timer.h` and `tests/System/TimerTests.cpp`: 64 insertions, 7 deletions. This review did not modify either candidate or baseline.

All seven examined receipts contain the same 1696 source hashes and f3 HEAD. I independently compared all 1678 `core/` entries with canonical Git blob bytes at that exact commit, and all 18 remaining helper entries with the local `linux-harness` files: zero mismatches. Canonical blob comparison avoids conflating Windows checkout line endings with Linux source bytes.

For the six test invocations, `before == after` was recomputed from the actual JSON objects rather than accepted solely from the `unchanged` boolean. Their complete 46-entry binary inventories are identical. The build's 45 post-build binaries all have exactly the same hashes as these tests. The extra test entry is the explicitly selected Bitcoin 31.1 executable at `/var/lib/discrete-swap-lab/bitcoin-download/bitcoin-31.1/bin/bitcoind`; it is an inventory/path addition, not a changed native binary. Build binary changes are expected; its source snapshots remain equal.

Selected common executable bindings:

| Artifact key | SHA256 |
|---|---|
| `b/src/discreted` | `7286557d93ff83756e994778222c87b9e99ce1e28ad868959ac386e6a0d510ab` |
| `b/src/simplewallet` | `f2a2f09e99100c44dc96a5c183cbf74366cd5f64861bd565afd19d82b6479add` |
| `b/tests/unit_tests` | `8688dd15fbe00140c79f377c5d2731a24960a6dae5f76c4b3abfd7ca64ced3b5` |
| `b/tests/system_tests` | `7189994c372ee5b917f41ec9612e327c57e1f78c7791e2e5f3c6446353c40b54` |
| `b/tests/http_framing_tests` | `79da6fe453319d41ce4e3874bde8eb026903c4b3abe7e6ecfa0eaa25e7712226` |
| `b/tests/SwapChainTests` | `2a161b6efd5fd3e87a2e4b7fd3f6ef7b4e35e598b58520f4248d7e867b8cf874` |
| `solana_escrow.so` — previous C/LiteSVM fixture | `91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89` |
| explicit Bitcoin 31.1 `bitcoind` | `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08` |

These are coherent runner-recorded execution bindings, not independently downloaded Linux executables or a reproducible-build attestation. `run_evidence.py` inventories selected source files and executables before/after a process; it does not hash the complete OS, dynamic libraries or Python site-packages, continuously monitor file changes, or cryptographically attest the remote machine. No stronger environment claim follows from `unchanged`.

## Actual results

| Run | Direct result | Elapsed evidence and scope |
|---|---|---|
| `linux-timer-build` | exit 0 | `cmake --build b --parallel 1`; 680.123657 seconds between receipt timestamps. Source unchanged. |
| `linux-timer-http-repeat` | 30 RUN / 30 OK, exit 0 | Same `HttpClientTimeout.RequestTimesOutAgainstAnUnresponsivePeer` repeated 30 times; original assertion retained; 15.034244 seconds for invocation. |
| `linux-timer-ctest` | **38/39; exit 8** | 2098.77 seconds in CTest summary; UnitTests timeout at 1800.10 seconds. |
| `linux-timer-network` | **12/12 PASS**, exit 0 | 12 individual `ok` rows plus terminal `OK`; unittest 138.558 seconds. Eight real four-daemon/wallet RPC cases and four cross-chain network cases. |
| `linux-timer-boundaries` | **12/12 PASS**, exit 0 | 12 `ok` rows and terminal `OK`; 71.919 seconds. Lab bind/testnet/auth/origin/content-type, resolver/proxy and owned-process cleanup controls. |
| `linux-timer-adapters` | **58/58 PASS**, exit 0 | 58 `ok` rows and terminal `OK`; 2.857 seconds. Bitcoin 8, Solana LiteSVM 13, generic journal 13, Solana journal 11, recovery 13. |
| `linux-timer-pair` | **4/4 PASS**, exit 0 | 4 `ok` rows and terminal `OK`; 2.761 seconds. Native Core pair-session fixture with Bitcoin regtest / local SBF. |

The exact first matrix command was:

```text
ctest --test-dir b --output-on-failure --output-junit ../linux-timer-ctest.xml --parallel 1 --timeout 1800
```

Its receipt starts at `2026-09-08T04:41:04.889824+00:00` and ends at `2026-09-08T05:16:03.690164+00:00`. The XML contains 39 testcase entries, one failure (`UnitTests`), zero CTest skipped/disabled entries. Full LastTest output confirms:

- SystemTests: 140 RUN / 140 OK, including all 21 Timer cases; four separately disabled tests remain disabled.
- HttpFramingTests: 11 RUN / 11 OK.
- SwapChainTests: 19 RUN / 19 OK.
- UnitTests: announces 676 tests, records 625 RUN / 624 OK, then stops at `PqWalletIntegration.IndexHITCReceiveAndSpendByAddressString`. No individual GTest assertion-failure row is present; there is no passing UnitTests summary. One case was active and 51 scheduled cases had not started. This is not 676/676 PASS and is not a successful UnitTests run.

The XML truncates successful suites' captured stdout at 1024 bytes. Individual passing-case counts above therefore come from the preserved full LastTest log, not from counting the incomplete XML stdout. The first CTest's aggregate log, XML and LastTest agree on the sole failed entry and time window.

The sampled stack in `timer-unit-function-stack-only.log` shows `yespower_tls → checkFreeRegPow → grindFreeRegPow → WalletGreen::buildPqFreeRegTransaction → PqWalletIntegration_IndexHITCReceiveAndSpendByAddressString`. Together with the unchanged wallet/proof/test paths documented in `timer-unit-pow-duration-review.md`, this supports real preexisting randomized FreeReg PoW as the immediate timeout explanation. It proves active proof work at that sampled moment; it does not establish every moment's state, rule out host contention, or prove that the unfinished case would eventually pass.

The previous 1e Linux matrix also had 38/39, but its failed entry was HttpFramingTests and its UnitTests completed. That historical result must not be substituted for this f3 UnitTests result. The failure classes are different despite the equal aggregate fraction.

## Integration execution scope

The command arrays in the four immutable receipts are the Linux virtualenv Python executable followed by `-B -u -m unittest -v` and these exact modules:

| Run | Modules |
|---|---|
| network | `test_xds_wallet_network test_network_cross_chain` |
| boundaries | `test_localnet_boundaries` |
| adapters | `test_bitcoin_regtest test_solana_vm test_swap_journal test_solana_journal test_journal_recovery` |
| pair | `test_cross_chain` |

Source inspection confirms the network group uses the existing wallet RPC/four-daemon lab path, including mined public XDS witness, reorg/restart and exact owner-settlement assertions. The separate pair group invokes `SwapChainTests --pair-session pair`; it is not another four-daemon production-wallet test. These overlapping suites must not be advertised as a count of distinct independent production scenarios.

The Bitcoin leg is owned regtest. The Solana leg imports `test_solana_vm.Fixture`, loads the old `91004de4…` C program into solders LiteSVM, and creates a local six-decimal SPL mint. It is not Circle-issued USDC, a public Solana cluster, or the new Rust SBPFv3 `30c22dac…` program. Real local token CPI/ledger execution is covered; actual Agave deployment/finalization and new-program RPC qualification require their own receipts. None of the four native integration receipts closes that separate gate.

## Artifact integrity checked

Every following log SHA256 was recalculated and compared with its receipt. Every listed receipt SHA256 was recalculated locally.

| Run | Receipt SHA256 | Log SHA256 |
|---|---|---|
| build | `4c69814fff2137258d2aa777d630aa7b2fff1e7ff1f05bf8df9e0a2177010c5e` | `ed117b488611c545051f4eaed1d459fca63fc37a997ce250946b884b102fb6bd` |
| HTTP repeat | `56658975e35c69602eab75dee1a403818294ef056a00b5a745667f97a2d4be0f` | `1ef3422f4ab7cbeba02787e3f564224167f4d0ff343b9227e9de5ae26f5a13b9` |
| CTest | `66b6f794faa2e7af469fa31b510a1b4db9749f340c9d7ae0b1faf087af6a7bb0` | `99e9e571ffd3a452d1fdf5b073416f737caa026d8b9cd316655af97cc29878e4` |
| network | `88f2a3433b3784daa42a76f90e4a01740b0c85839d7cf9b65ea1147566ac20fc` | `a050ae843809d26b1b5a7257e254373c7ce400828c696cf0bcf4578a6421a384` |
| boundaries | `4dbac84e7b82106dd2a6cfb1918260e01a1093b1853c06d1676a04a3df84dc83` | `a0d942773c91d87bc88d68c6cf0aa0e9e20efdd0ad4e738477493934db0ba3bf` |
| adapters | `0db251aedabf2ab9d054412f97d1d4b66e1112df5780de227e004024d08e7ccd` | `a410164b0bbe8a2066b45116d78f71f22d595199e11aa582867550e1005f0d15` |
| pair | `c6cc0e4f414366e29c48941d31fc8ae4f2334112a954547304b98b54cbef6a16` | `763d8c020693aa75e7ddcc8ba1527aea899d0afdefb1307009077d9f5d70077d` |

Files are under `../remote-evidence/native/`, with receipts under its `run-manifests/` directory and `linux-timer-` filename prefix. Collection `collection-20260908T053419722407Z.json` SHA256 `aa000da6f735f310e6b67b23023fcd471e6dfef9d19fc52310a101f0ca49443c` binds all eight newly collected integration log/receipt files; all sizes and hashes match. The collector and SSH-worker source hashes currently match that collection's recorded hashes. This is provenance of the existing collection, not new remote authentication by this reviewer.

Additional preserved artifacts:

| Artifact | SHA256 |
|---|---|
| `remote-evidence/public-metadata-v3/qualification-v05/linux-timer-ctest.xml` | `af32ba25da3bc076f0536d6b3ef293f7ab19074bb9db03ede31f0d84c3d80552` |
| `remote-evidence/public-metadata-v3/qualification-v05/linux-timer-first-LastTest.log` | `e6bfb415515825b31b1d0ac1c1d395c86ead39d45c0436752ee29554b73933a4` |
| `export-v3-and-timer-first-public-metadata.log` | `31646b0c19943d971e592697d6df8f4aa64919078923f0d75baa84570171fa51` |
| `timer-unit-function-stack-only.log` | `82d9c5c6e370f8a6b42c0492d9e89822cfa41fb0ecaab2a498c8274fbbb77393` |

The two Timer metadata files were also compared byte-for-byte with their decoded base64 entries in the fixed five-file export envelope, including length and SHA256. The other three envelope entries are outside this native review's scope. XML and LastTest were exported after the run and are not fields of the original run receipt; their command, time interval, outcomes and timeout output agree with the receipt-bound aggregate CTest log. Keep both provenance layers rather than pretending the original receipt hashed metadata it did not contain.

## Remaining gates and permitted claims

1. Preserve this first CTest timeout unchanged. A new, bounded UnitTests-only invocation on the same frozen source/binaries must supply its own immutable receipt and full terminal result, with no skipped PoW cases or relaxed assertions. If it passes, describe aggregate qualification with an explicit retry; do not rewrite the first matrix as 39/39. A larger outer budget does not guarantee completion.
2. Keep the completed Timer evidence separate from pending actual Agave/new-SBPFv3 RPC evidence. These four integration invocations do not exercise that new program, a real USDC mint, or public-chain finality.
3. This interim review does not establish GUI behavior, production recovery of real wallets/funds, public RPC resilience, external-network consensus safety, a full Linux sanitizer matrix, or mainnet activation readiness. No source change, production deployment or production service qualification follows from it.
4. No new evidence inconsistency requiring correction was found within this bounded review. The material remaining native gate is the unfinished UnitTests execution. Existing receipts prove the successful scopes above without erasing that failure.

**Перевірено:** coherent f3 source/binary receipts, build exit 0, strict HTTP 30/30, first CTest 38/39 with preserved UnitTests timeout, System 140/140, HTTP suite 11/11, SwapChain 19/19, and separate integration 12/12 + 12/12 + 58/58 + 4/4.

**Не перевірено:** successful completion of f3 UnitTests, later retry results, new SBPFv3/Agave RPC qualification, real USDC/public chains, production recovery/GUI/mainnet. KB and status documents remain parent-owned during active qualification; this task changes only the interim audit report.
