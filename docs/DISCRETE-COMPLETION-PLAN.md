# Discrete — Completion Plan (fork → fully working coin)

Status snapshot: 2026-06-13. Branch `master`, repo `D:/dev/discrete`.
This is a step-by-step plan to take the Discrete PQ fork from its current state
to a launchable coin. Each step is written as a **self-contained prompt** you can
hand to a coding model (Codex / Sonnet) one at a time. Steps are ordered by
dependency; do not skip ahead past a "BLOCKER" without finishing it.

---

## Current state (what already works)

- **Crypto core**: `src/crypto_pq/` — ML-KEM-768 (view) + ML-DSA-65 (spend),
  AEAD payload, derivation (`PqDerive`), output builder, scan, seed/address.
  KAT-verified.
- **Wire/consensus**: `TransactionInput = {BaseInput, PqInput}`,
  `TransactionOutput target = {PqOutput,...}`; `TRANSACTION_VERSION_1 = 1`;
  ML-DSA sigs live in `Transaction.pqSignatures` (`std::vector<std::array<uint8_t,
  PQ_SIGNATURE_SIZE>>`). Serialization branch in `CryptoNoteSerialization.cpp`.
- **Validation**: `src/CryptoNoteCore/PqValidation.{h,cpp}` — semantic + input
  checks, nullifier computation, fee floor, free-reg PoW.
- **Chain**: nullifiers stored in the type-agnostic spent-key set
  (`Blockchain.cpp`), coinbase PQ outputs spendable after maturity, yespower PoW
  from genesis, all upgrade heights = 0 (PQ from block 0).
- **Daemon RPC**: `getPqAccount` in `RpcServer`.
- **simplewallet**: `pq_address`, `pq_balance`, `pq_transfer`, `pq_register`,
  `pq_register_paid`, `pq_account` (+ dead `bridge_legacy`).
- **WalletGreen**: PQ consumer + state persistence (`buildPqStateBlob` /
  `restorePqStateBlob`).
- **Tests**: 15 PQ test suites (`tests/test_pq_*.cpp`), green under
  `ctest -C Release -R Pq`.

## Major gaps (what this plan closes)

1. **walletd / PaymentGate has ZERO PQ support** — the service API exchanges use
   exposes no PQ address/balance/transfer/registration. (Biggest gap.)
2. **Deposit-wallet modes not implemented** — `--aggregated-multikey` (Spec 1) /
   `--single-key-index` (Spec 2 / H-I-T-C). See
   `discrete-pq-deposit-wallet-modes` memory note.
3. **Wire not frozen** — subaddress index `T` is NOT yet bound into `outContext`
   / `encPayload` (required by both deposit modes; becomes a hard fork after
   launch). `outContext(inputsHash, kemCt, outputIndex)` in
   `src/crypto_pq/PqDerive.cpp` needs a `T` parameter.
4. **Consensus params are placeholders** — `MIN_PQ_FEE_PER_BYTE = 1`,
   `FREE_REG_POW_TARGET`, fee floor calibration.
5. **Network identity not finalized** — `GENESIS_COINBASE_TX_HEX = "PLACEHOLDER"`,
   seed nodes, DNS checkpoint signers (need PQ/ML-DSA), `P2P_STAT_TRUSTED_PUB_KEY`.
6. **Dead bridge code** — `TX_BRIDGE`, `buildBridgeTransaction`,
   `checkBridgeTransactionSemantic`, `bridge_legacy` command all throw / are
   unreachable in Discrete.
7. **Docs/README stale** — README is still Karbo; comments reference "v6
   activation" that does not apply (PQ from genesis).
8. **No multi-node end-to-end test / testnet bring-up checklist.**

---

## Reusable preamble (PREPEND to every step prompt)

> You are working in the Discrete repository at `D:/dev/discrete` (a
> post-quantum-only CryptoNote fork; everything is PQ from genesis — there is NO
> legacy ECC chain, NO rings, NO bridge). Constraints:
> - Build is CMake + Visual Studio 2022, x64. Configure once with:
>   `cmake -S D:/dev/discrete -B D:/dev/discrete/build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=ON -DOQS_BUILD_ONLY_LIB=ON`
> - Build a target: `cmake --build D:/dev/discrete/build --config Release --target <T>`
> - Run PQ tests: `ctest --test-dir D:/dev/discrete/build -C Release -R Pq --output-on-failure`
>   (tests MUST be built/run with `--config Release` — Debug has a Boost/gtest CRT mismatch).
> - Consensus rule: any change to validation/serialization/derivation must keep
>   ALL nodes byte-for-byte identical. If you change a wire/derivation format,
>   update both the writer and reader and every test that pins bytes.
> - Commit style: a single short subject line, NO body, NO trailers, NO
>   "Co-Authored-By", NO "Generated with" line. Example: `git commit -m "Add T to outContext"`.
> - Do NOT `git push`, open PRs, or touch any remote. Local commits only.
> - When done, report: what changed, which tests you ran, and their pass/fail.

---

# PHASE 0 — Freeze the wire format (BLOCKER; must precede any launch data)

### Step 0.1 — Bind subaddress index `T` into derivation + payload
**Goal:** Add an unsigned 64-bit deposit index `T` to the output-key derivation
so the dual deposit-wallet modes can route deposits. Default `T = 0` reproduces
today's behavior for all existing single-address flows.

**Where:**
- `src/crypto_pq/PqDerive.cpp/.h` — `outContext(inputsHash, kemCt, outputIndex)`.
- `src/crypto_pq/PqOutputBuilder.cpp/.h` — `buildPqOutput(...)` callers.
- `src/Wallet/PqTransactionBuilder.cpp` — `buildPqTransaction` output loop.
- AEAD payload assembly in `PqOutputBuilder` / `PqAead`.
- `tests/test_pq_derive.cpp`, `test_pq_output_builder.cpp`, `test_pq_scan.cpp`,
  `test_pq_wire.cpp`.

**Task:**
1. Add a `uint64_t subaddrIndexT` parameter to `outContext(...)`, appended as
   little-endian 8 bytes AFTER `outputIndex` (domain string unchanged).
2. Thread `T` through `buildPqOutput` and the wallet builder (default 0).
3. Add `T` to the AEAD-sealed `encPayload` (authenticated), so the receiver
   reads it back; bind the SAME `T` into `outContext` (so a tampered `T` breaks
   key recovery). Keep `spendCommit`'s spend-authority component = the account
   ML-DSA `spendPub` (do NOT bind `T` into spend authority).
4. On scan, recover `T` from the payload and expose it on the scan result struct.
5. Update every test that pins derivation/wire bytes; add a test that two
   different `T` values for the same `(inputsHash,kemCt,outputIndex)` produce
   different output keys and both round-trip.

**Acceptance:** all `Pq` tests green; a new test asserts `T` round-trips through
build→serialize→parse→scan and that `T≠0` differs from `T=0`.

> NOTE: This MUST land before any persistent testnet/mainnet chain exists.
> Changing it later is a hard fork.

### Step 0.2 — Audit & freeze domain strings and format versions
**Goal:** Lock every domain-separation constant and the wire/format version so
they never silently change.

**Where:** `src/crypto_pq/PqDerive.cpp` (the `kDomain*` constants), `PqAead`,
`PqSeed` HKDF labels, `CryptoNoteConfig.h` (`TRANSACTION_VERSION_1`, sizes).

**Task:** Produce a short doc `docs/PQ-WIRE-FROZEN.md` listing each domain
string, each size constant (`PQ_*_SIZE`), and the tx/format version, with a one
-line "DO NOT CHANGE after launch" banner. Add a test (`test_pq_wire.cpp` or new
`test_pq_domains.cpp`) that pins the exact byte values of the domain constants so
an accidental edit fails CI.

**Acceptance:** new pinning test passes; doc committed.

---

# PHASE 1 — Calibrate consensus parameters

### Step 1.1 — Calibrate PQ fee floor
**Goal:** Replace placeholder `MIN_PQ_FEE_PER_BYTE = 1` with a justified value.

**Where:** `src/CryptoNoteConfig.h:85`; fee-floor logic in
`PqValidation.cpp::checkPqTransactionInputs` (the `minFeePerByte * size` block);
`MINIMUM_FEE`/`MAXIMUM_FEE` (lines 70-71); `COIN`/decimals (lines 56,68).

**Task:** Given a typical `TX_PQ` is dominated by ML-DSA sig (3309 B/input) +
ML-KEM ct + payload, compute a realistic min tx size, pick `MIN_PQ_FEE_PER_BYTE`
so a 1-in/2-out tx costs a sane fraction of `COIN` (propose 2-3 options with the
resulting absolute fee per typical tx and per `MAX_PQ_TX_SIZE`). Document the
choice inline. Keep overflow-safe math. Do NOT lower any value in a way that
would let historical blocks fail (there are none yet, so any value is fine now —
but note the rule for the future: tightening must be height-gated).

**Acceptance:** `test_pq_validation.cpp` fee-floor tests updated and green; a
table of (param → absolute fee for typical txs) in the commit message body is NOT
allowed (terse commits) — put it in `docs/PQ-FEES.md` instead.

### Step 1.2 — Calibrate free-registration anti-spam PoW + rate limit
**Goal:** Make `FREE_REG_POW_TARGET` and `FREE_REG_PER_BLOCK` defensible.

**Where:** `CryptoNoteConfig.h:90-92`; `PqValidation.cpp::checkFreeRegPow` and
`checkFreeRegTransactionSemantic`; wherever free-reg txs are admitted per block.

**Task:** Decide the intended cost (e.g. "≈N seconds on a phone"), set the
target, and ensure the per-block cap on free registrations is actually enforced
in block validation / mempool admission (find where, or implement if missing).
Add/extend a test that a free-reg tx below target is rejected and one at/above is
accepted, and that exceeding `FREE_REG_PER_BLOCK` in a block is rejected.

**Acceptance:** free-reg tests cover PoW boundary + per-block cap; green.

### Step 1.3 — PQ coinbase / emission sanity check
**Goal:** Confirm emission, reward, and PQ coinbase maturity behave correctly
from genesis (no legacy assumptions leaked).

**Where:** `Currency.cpp` (`getBlockReward`, `constructMinerTxPq`),
`Blockchain.cpp` coinbase validation, `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`.

**Task:** Write an integration test (extend `tests/test_pq_chain.cpp`) that mines
N blocks, asserts coinbase reward matches the emission curve, that a coinbase PQ
output is unspendable before maturity and spendable after, and that the spend
produces a valid nullifier recorded once.

**Acceptance:** new chain test green.

---

# PHASE 2 — Network identity & genesis

### Step 2.1 — Freeze the genesis coinbase
**Goal:** Replace `GENESIS_COINBASE_TX_HEX = "PLACEHOLDER"` with a fixed,
deterministic hex so every node agrees byte-for-byte (currently it falls back to
a runtime-generated zero-seed coinbase — works but not frozen).

**Where:** `CryptoNoteConfig.h:143-146`; `Currency.cpp::generateGenesisBlock`
(lines 110-148).

**Task:** Add a tiny tool or daemon flag (e.g. `--print-genesis-tx`) that runs
the existing PQ genesis-coinbase constructor and prints the serialized hex. Paste
that hex into `GENESIS_COINBASE_TX_HEX`. Verify `generateGenesisBlock` now takes
the hex path (not the fallback) and the genesis hash is stable across two fresh
runs. Document the procedure in `docs/GENESIS.md`.

**Acceptance:** two clean `karbowanecd --print-genesis-tx` runs give identical
hex; daemon starts and logs a stable genesis hash; a test pins the genesis hash.

### Step 2.2 — Finalize network identity constants
**Goal:** Lock ports, prefixes, names, P2P trusted key.

**Where:** `CryptoNoteConfig.h` — `CRYPTONOTE_NAME` ("discrete"), `CRYPTONOTE_TICKER`
("DISC"), address prefixes (lines 42-46), ports (222-228),
`P2P_STAT_TRUSTED_PUB_KEY` (269), `CRYPTONOTE_DISPLAY_DECIMAL_POINT`;
`P2p/P2pNetworks.h` (network id GUID).

**Task:** Generate a fresh network-id GUID in `P2pNetworks.h` (must differ from
Karbo so the two networks can't cross-connect). Generate a fresh
`P2P_STAT_TRUSTED_PUB_KEY` keypair (or set to all-zero + disable if unused) and
record where its secret lives. Confirm address prefix actually yields the
intended human-readable prefix letter. Document all final values in
`docs/NETWORK.md`.

**Acceptance:** daemon refuses to handshake with a Karbo node (different network
id); address encode/decode round-trips with the final prefix.

### Step 2.3 — Seed nodes & DNS checkpoints
**Goal:** Real bootstrap infrastructure values (or clearly-marked testnet ones).

**Where:** `CryptoNoteConfig.h` `SEED_NODES` (272-275), `DNS_CHECKPOINTS_HOST`
(147).

**Task:** Replace placeholder seed hostnames with the real ones (or document that
they are testnet placeholders pending DNS). Confirm the daemon tolerates
unreachable seeds without crashing (start with no network). No code change may be
needed beyond the constants + a manual start test.

**Acceptance:** daemon starts and keeps running with unreachable/empty seeds.

---

# PHASE 3 — walletd / PaymentGate PQ support  (largest phase)

> walletd uses `WalletGreen` (which already has PQ internals) behind the
> `PaymentGate` JSON-RPC service. The service API currently exposes NONE of it.

### Step 3.1 — Expose PQ address & balance over the walletd API
**Goal:** Add JSON-RPC methods so a service can read its PQ address and balance.

**Where:** `src/PaymentGate/` (WalletService + the RPC method bindings),
`src/Wallet/WalletGreen.{h,cpp}` (add public getters if missing, mirroring
`pq_address`/`pq_balance` in `SimpleWallet.cpp`), `src/Rpc`/`src/JsonRpcServer`.

**Task:** Add `getPqAddress` and `getPqBalance` service methods + request/response
structs, wired to WalletGreen's PQ state. Match the existing PaymentGate method
style (look at an existing method like `getAddress`/`getBalance` and copy the
pattern). Add a PaymentGate-level test if the harness supports it; otherwise a
manual `curl` example in `docs/WALLETD-PQ.md`.

**Acceptance:** `karbowanecd` + `walletd` run; the new methods return the same
address/balance the simplewallet shows for the same seed.

### Step 3.2 — PQ account registration via walletd
**Goal:** Let a service register its PQ account number through the API.

**Where:** PaymentGate service; reuse `buildFreeRegTransaction` /
`pq_register` + `pq_register_paid` logic from `SimpleWallet.cpp`; daemon
`getPqAccount` RPC for status.

**Task:** Add `registerPqAccount` (free, anti-spam PoW) and
`registerPqAccountPaid` service methods + a `getPqAccountStatus` poller. Move the
shared free-reg PoW grinding into a reusable helper (out of SimpleWallet) if it
is currently inline there, so both wallets call one implementation.

**Acceptance:** via walletd you can register and then observe the account become
confirmed (`getPqAccountStatus`).

### Step 3.3 — Deposit-wallet MODES (the dual-mode requirement)  [BLOCKER for exchanges]
**Goal:** Implement the two deposit schemes selected at container creation by
mutually-exclusive flags, persisted in the container.
- `--aggregated-multikey` → **Spec 1** (shared ML-KEM view key + many ML-DSA
  spend keys; per-deposit spend isolation). **DEFAULT.** Use case: custodial web
  wallet.
- `--single-key-index` → **Spec 2 / H-I-T-C** (one view + one spend key; deposits
  distinguished by integer index `T` from Step 0.1, recovered by decapsulation,
  no per-key registration). Use case: exchange.

Full design + rules: memory note `discrete-pq-deposit-wallet-modes` and the two
source PDFs referenced there.

**Where:** walletd container creation path (where `--generate-container` is
handled), container serialization (add a persisted enum field), PaymentGate
deposit-address API, scan path in `WalletGreen`/`PqConsumer`.

**Task:**
1. Add a persisted `pqDepositScheme` enum to the container metadata, set ONLY at
   creation from the flag; reject changing it on an existing container; reject
   passing both flags; default to `aggregated-multikey`.
2. `aggregated-multikey`: maintain a set of deposit ML-DSA spend keys under one
   shared ML-KEM view key; "new deposit address" mints a new spend key; scanning
   decapsulates once per output then routes by the encrypted spendPub
   fingerprint in `encPayload` (add the fingerprint to the payload, non
   -authoritative hint; verify `spendCommit` against the full spendPub).
3. `single-key-index`: one keypair; "new deposit address" returns a fresh `T`;
   walletd keeps a local `T → user` table; attribution by reading `T` from the
   payload (Step 0.1). Expose the `(account, subaddress_index)` surface mapped to
   `T`.
4. Help text for each flag must state: spec name, use-case (web-wallet vs
   exchange), the per-deposit-spend-isolation tradeoff, and "immutable after
   container creation".

**Acceptance:** create two containers (one per flag); generate 3 deposit
addresses in each; pay each; confirm each scheme attributes deposits to the right
address/index; confirm the flag is persisted (reopen container, scheme
unchanged) and that passing both flags errors.

### Step 3.4 — Deposit-address generation API
**Goal:** The familiar exchange surface: create/list deposit addresses.

**Where:** PaymentGate (mirror `createAddress`/`getAddresses` if present).

**Task:** Add `createPqDepositAddress` (returns address + index/fingerprint) and
`listPqDepositAddresses`, backed by whichever scheme the container uses. For
single-key-index, the returned identifier is the H-I-T-C account number (Height,
Index, T, Luhn mod-36 check char — see memory note; reuse the H-I-C Luhn code if
it exists, extend over `T`).

**Acceptance:** create + list works in both modes; H-I-T-C check char validates
and rejects a transcription typo.

---

# PHASE 4 — PQ checkpoints & message signing

### Step 4.1 — PQ message sign/verify (ML-DSA)
**Goal:** `sign_message`/`verify_message` currently use ECC Schnorr; Discrete has
no ECC account keys. Provide ML-DSA-based signing.

**Where:** `SimpleWallet.cpp` `sign_message`/`verify_message`,
`CryptoNoteFormatUtils` signMessage/verifyMessage, base58 signature prefix
(`CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX`).

**Task:** Implement message signing with the wallet's ML-DSA spend key + a
domain-separated digest; encode base58 with the existing prefix tag. Verify
against the PQ address's spendPub. Add a test signing+verifying a message and
rejecting a tampered one.

**Acceptance:** sign→verify round-trips; tamper rejected; test green.

### Step 4.2 — PQ DNS checkpoint signers
**Goal:** `DNS_CHECKPOINT_SIGNERS` is empty (fail-closed) and references the ECC
scheme. Wire it to the PQ signer from Step 4.1.

**Where:** `CryptoNoteConfig.h:190-195`, the DNS checkpoint loader/verifier.

**Task:** Update the loader to verify checkpoint signatures with the Step-4.1 PQ
verify path; document the maintainer workflow (offline ML-DSA signer wallet);
add at least one real signer address (or leave fail-closed with a clear doc note
that checkpoints are disabled until provisioned).

**Acceptance:** a signed test record verifies; a bad signature is rejected; with
no signers the loader fail-closes (logs once, skips) without crashing.

---

# PHASE 5 — Cleanup & docs

### Step 5.1 — Remove dead bridge code
**Goal:** Delete the unreachable TX_BRIDGE path so it can't confuse auditors.

**Where:** `PqValidation.cpp` (`checkBridgeTransactionSemantic` — entire fn is
dead after the early `fail`), `PqTransactionBuilder.cpp`
(`buildBridgeTransaction` throws), `SimpleWallet.cpp` `bridge_legacy` command +
handler, `PqTxType.h` (`TX_BRIDGE`), any `TX_BRIDGE` references in tests.

**Task:** Remove `bridge_legacy` command + impl, remove `buildBridgeTransaction`,
remove `checkBridgeTransactionSemantic` and its call sites, remove `TX_BRIDGE`
from the txType enum and the dead branch in semantic dispatch. Keep `TX_PQ` and
`TX_FREE_REG`. Update tests that mention bridge.

**Acceptance:** full build clean; all `Pq` tests green; `grep -ri bridge src/`
finds nothing in production PQ paths.

### Step 5.2 — Fix stale comments & README
**Goal:** Remove "v6 activation" / "until PQ activates" language (PQ is from
genesis) and replace the Karbo README.

**Where:** `WalletLegacy.cpp:355-360` (stale `pqScheduled`/v6 comment),
`GreenWallet/CommandImplementations.cpp:1166` ("PQ activation not yet
scheduled"), `docs/PQ-PHASE2-CONFIDENTIAL.md` (its v6/v7 ladder describes the
karbowanec branch, not Discrete — add a banner clarifying Discrete is PQ-from
-genesis, tx v1), `README.md`.

**Task:** Replace the README with a Discrete-specific one (what it is, build
steps for the VS2022/liboqs setup, PQ wallet quickstart). Fix the stale inline
comments to say "PQ is active from genesis". Add the clarifying banner to the
Phase 2 doc.

**Acceptance:** no remaining "until PQ activates"/"block v6" claims in code
comments; README describes Discrete.

### Step 5.3 — GreenWallet (CLI) PQ parity decision
**Goal:** Either bring `greenwallet` to PQ parity with simplewallet or explicitly
scope it out.

**Where:** `src/GreenWallet/`.

**Task:** Decide (and document in `docs/WALLET-SCOPE.md`) whether greenwallet is
supported for Discrete. If yes, add the PQ commands mirroring SimpleWallet. If
no, make it print a clear "use simplewallet for PQ" message and remove half
-wired PQ bits.

**Acceptance:** greenwallet either has working PQ commands or a clean explicit
message; no half-states.

---

# PHASE 6 — Testing & launch

### Step 6.1 — End-to-end multi-node integration test
**Goal:** Prove the chain works across processes, not just unit tests.

**Where:** `tests/` (extend the integration harness used by `IntegrationTests` /
`test_pq_chain.cpp`; the test generator can drive V1 blocks + yespower — see the
`setBlockchain` pattern).

**Task:** A test that: starts a core, mines coinbase to a PQ address, registers a
PQ account (free-reg), sends a `pq_transfer`, mines it, asserts balances on both
sides and that a double-spend (reused nullifier) is rejected at both mempool and
block level.

**Acceptance:** new integration test green.

### Step 6.2 — Manual testnet bring-up checklist
**Goal:** A reproducible 2-node local testnet.

**Where:** new `docs/TESTNET.md`.

**Task:** Document exact commands to launch two `karbowanecd` instances
(`--testnet`, distinct data dirs/ports, `--add-exclusive-node` to peer them),
mine with simplewallet, register a PQ account, transfer between two wallets, and
run walletd against one node in each deposit mode. Capture expected output.

**Acceptance:** following the doc on a clean machine produces a working 2-node
testnet with a confirmed PQ transfer.

### Step 6.3 — CI / regression gate
**Goal:** Keep it green.

**Where:** `.github/workflows/` (or wherever CI lives), `tests/CMakeLists.txt`.

**Task:** Ensure CI builds with `-DBUILD_TESTS=ON -DOQS_BUILD_ONLY_LIB=ON` and
runs the full `Pq` suite + the new integration test on Windows (and Linux if
targeted). Add the domain-pinning test (Step 0.2) and the genesis-hash test
(Step 2.1) to the gate.

**Acceptance:** CI passes on a clean checkout.

---

## Suggested execution order (critical path)

1. **0.1, 0.2** (freeze wire — blocks everything launch-related)
2. **1.1, 1.2, 1.3** (params)
3. **2.1, 2.2, 2.3** (genesis/network)
4. **3.1 → 3.2 → 3.3 → 3.4** (walletd; 3.3 depends on 0.1)
5. **4.1, 4.2** (checkpoints/signing)
6. **5.1, 5.2, 5.3** (cleanup)
7. **6.1, 6.2, 6.3** (test/launch)

Phases 1, 2, 4, 5 can be parallelized across models once Phase 0 lands. Phase 3
is the long pole and depends only on 0.1.
