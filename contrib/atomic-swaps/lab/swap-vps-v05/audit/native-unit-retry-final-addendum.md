# Native qualification — separate UnitTests retry addendum

Reviewed 2026-09-08 UTC. **All 39 registered CTest groups have passing results across the first run plus a separate unchanged UnitTests retry. This was not one successful 39/39 CTest run.** No blocker was identified for this exact aggregate claim. One preexisting disabled UnitTests case remains disabled.

This read-only audit supplements `actual-v3-runtime-evidence-review.md`; its then-open native UnitTests result is now resolved by the distinct evidence below. The prior runtime report, initial timeout and original baseline remain unchanged. No source, tests, settings, remote process or node was modified or run by this reviewer.

## Exact result and identity

| Evidence under `remote-evidence/` | SHA256 |
|---|---|
| `native/run-manifests/linux-timer-unit-retry.json` | `351283a7fa6de1c66853f6886adbd55744d426c2eac318ce9397c4330f32c677` |
| `native/linux-timer-unit-retry.log` | `9c49eb133e31a833dee2bd7d50df9b3e2a5c588a0024623ac11f180f62576b4d` |
| `public-metadata-v3/qualification-v05/linux-timer-unit-retry.xml` | `90b6897f1064147f787b8c4374e1b7655e028b081dafcb699a0a6c8aab6183dc` |
| `public-metadata-v3/qualification-v05/linux-timer-unit-retry-LastTest.log` | `ba5f00d91816f186806898d38ea3dd3b8e101e60e0cd3f807635b66958892fa2` |
| Initial `native/run-manifests/linux-timer-ctest.json` | `66b6f794faa2e7af469fa31b510a1b4db9749f340c9d7ae0b1faf087af6a7bb0` |
| Initial `public-metadata-v3/qualification-v05/linux-timer-ctest.xml` | `af32ba25da3bc076f0536d6b3ef293f7ab19074bb9db03ede31f0d84c3d80552` |

The initial serial CTest command used `--timeout 1800`, returned exit 8, and its XML independently shows 38 passing groups and only UnitTests failing at **1800.10 seconds**. The preserved full console log agrees. The distinct retry command is:

`ctest --test-dir b -R ^UnitTests$ --output-on-failure --output-junit ../linux-timer-unit-retry.xml --parallel 1 --timeout 3600`

It returned exit 0 and passed UnitTests in **2292.65 seconds**, between 06:07:27 and 06:45:40 UTC. Its XML represents one CTest group, not 676 separate testcases; XML stdout is explicitly truncated at 1024 bytes. The complete LastTest log supplies the stronger case-level evidence: **676 unique RUN entries, 676 corresponding OK entries in the same order, final PASSED 676, and one disabled test**. Its direct command is the unchanged `b/tests/unit_tests` with no case filter. The `-R` argument selects a CTest group and does not remove UnitTests assertions or cases.

Retry before/after snapshots exactly equal both initial CTest snapshots: head **`f3f84ce6ba44f5391a5bec78418a5d78052a1b3d`**, **1696 source identities and 46 binary identities**. UnitTests SHA256 is **`8688dd15fbe00140c79f377c5d2731a24960a6dae5f76c4b3abfd7ca64ced3b5`**.

All 1696 sources and all 45 binaries in the earlier successful build are identical. The 46th recorded binary is solely the explicit `BITCOIND` override `/var/lib/discrete-swap-lab/bitcoin-download/bitcoin-31.1/bin/bitcoind`, hash `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`; the associated runtime path is the only path-map difference. No Core binary changed. The later network 12, boundaries 12, adapters 58 and fixture-pair 4 receipts all have this same complete 46-binary snapshot and matched successful logs. The separately audited actual Agave pair binds the same 1696 sources and 45 common build binaries, including this exact UnitTests binary.

## Assertions, disabled count and long runtime

All 676 executed case names and their order match the known-good Linux 1e baseline's full UnitTests output. The retained disabled case is `PaymentGateTest.DISABLED_addTransaction` (`tests/UnitTests/PaymentGateTests.cpp:84–89`), already disabled for its classical-address/coinbase assumptions. The other textual name `DISABLED_sendTransaction` is inside an old block comment and is not a second compiled disabled test. The baseline already reports one disabled UnitTests case. CTest XML's `disabled="0"` is group-level metadata and must not be presented as zero internally disabled cases.

Eleven targeted wallet, FreeReg, configuration, test/stub/generator and CMake source files match the captured native hashes exactly. They also match V04 before the Timer change after accounting only for that Windows checkout's CRLF line endings. Fresh Git readback shows clean f3 and only `src/System/Timer.h` plus `tests/System/TimerTests.cpp` changed from 1e. No PoW target, test assertion, disabled status or fixture changed for the retry.

The unchanged path remains `WalletGreen::buildPqFreeRegTransaction → grindFreeRegPow → checkFreeRegPow → yespower`; the default target is `0x00007FFFFFFFFFFF`. Random wallet seed and reference-tip inputs give variable proof search work. The three registration cases actually took:

- `PaymentGateTest.IndexModeRegistersAndIssuesHITC`: **567.037 s**.
- `PaymentGateTest.DepositEndpointsFailClosedOnAnUntrustedDaemon`: **585.424 s**.
- `PqWalletIntegration.IndexHITCReceiveAndSpendByAddressString`: **1130.967 s**.

Together they account for **2283.428 of 2292.640 seconds** reported by GoogleTest, about 99.6%. The prior diagnosis in `timer-unit-pow-duration-review.md` remains applicable. Passing once under 3600 seconds does not make that a deterministic future upper bound.

Two brief parent-operated function-only GDB observations occurred during this retry, at **06:17:40** and **06:38:25 UTC**. The retained logs show process 13134 executing yespower through FreeReg in the second and third named tests respectively, followed by debugger detachment. Hashes: `unit-retry-function-only-progress.log` **`4c20f9e18cd358686e7c3e7d2a10e8706778a0e06f2f4c6273d5790cb1683a70`**; `unit-retry-function-only-after-30min.log` **`0dea4099341ec8fc324b6dcd01105b0ce0bba019ce866f076eab2e16c228b6ae`**. These observations support the sampled execution path; attach pauses mean the run should not be described as an untouched performance benchmark. No case waiver or test edit accompanied them.

## Independent machine audit and limits

`audit/check_native_unit_retry_evidence.py` ran **54 evidence checks PASS**, exit 0. Machine result: `audit/native-unit-retry-evidence-check.json`, SHA256 **`df5a14f10043aabd2ea710db44e65075443f67eae178388950f98eebde94c94e`**. Checker SHA256 **`e6f4cb0d9cdac5b7fa9af964d5ebefd49fe209ad5b7a01257e556f6dd092c2e3`**; successful log **`779178262341df607dcf151431534b054ee0e05df155cf7fc5f5b5b12c520b6f`**. These are evidence checks, not additional native tests.

Two earlier local audit-script attempts are retained separately: one encountered the Windows default decoder on a UTF-8 build log; one incorrectly assumed byte-identical line endings in V04's CRLF checkout. Explicit UTF-8 and recorded EOL-only comparison corrected the checker. Neither was a product/runtime test failure, and no tested artifact changed.

This addendum closes the specific separate UnitTests result and aggregate group-coverage claim. It does not erase the first timeout, execute the disabled case, establish a single green full-matrix run, remove stochastic runtime concerns, or extend the laboratory evidence to mainnet, actual USDC, production custody or load/recovery qualification.
