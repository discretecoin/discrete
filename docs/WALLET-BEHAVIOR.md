# Discrete wallet behavior contract

The PQ wallet machinery **replaced** the classical Karbo/CryptoNote wallet rather than
extending it. This document is the checklist that converts "rediscover each behavior via
a bug" into "port each behavior deliberately." For every operation it states:

- **Intended (CN)** — what the original CryptoNote/Karbo wallet did. The source of truth
  is the pre-PQ code in git history (before commit `b5833ae6`; a clean tree is
  `da185ed5`). When in doubt, read it: `git show da185ed5:src/Wallet/WalletGreen.cpp`.
- **Aggregated** / **Index** — behavior in each deposit mode (below).
- **Status** — ✅ covered by a named test · 🟡 implemented, only indirectly/​unit-tested ·
  ❌ gap (wrong or missing) · ⬜ not yet verified end-to-end.

The two deposit modes (`PqDepositScheme`):

| | **AggregatedMultikey** (default) | **SingleKeyIndex** (H-I-T-C) |
|---|---|---|
| Keys | one shared ML-KEM **view** key + a **per-deposit** ML-DSA spend key (`deriveDepositSpendKeys(seed, i)`) | **one** ML-KEM view + **one** ML-DSA spend key for everything |
| Deposit address | a PQ base58 address carrying the per-deposit spend pubkey | an **H-I-T-C account number** (base account H-I + subaddress index T) |
| On-chain registration | **not required** — a deposit address is self-contained | **required** — H,I are the registration's (block height, tx index); needs `registerPqAccount[Paid]` first |
| Output attribution on scan | match the recovered spend pubkey to the per-deposit pubkey | recover subaddress index **T** from the output by decapsulation |
| Spend authority for a deposit output | the **per-deposit** spend secret | the one spend secret (T is routing only) |

Everywhere an address is accepted, the same three selector forms are interchangeable
(commit `7792c1dd`): a raw PQ/classical **address**, an **H-I-C / H-I-T-C** account
number, or a numeric **address index** (0 = primary, 1.. = deposit in issue order).

---

## A. Identity & addresses

| Operation | Intended (CN) | Aggregated | Index | Status |
|---|---|---|---|---|
| Primary identity | seed → spend/view keys | 32-byte `SeedMaster` → `deriveSpendKeys`/`deriveViewKeys` (no HKDF) | same | ✅ `PqDeriveTests`, `PqWalletSyncE2E` |
| `getAddresses` / `getAddressesCount` | primary + every subaddress | index 0 = primary PQ address; 1.. = deposit PQ addresses | index 0 = primary; 1.. = H-I-T-C numbers | 🟡 `PaymentGateTest.addressIndexAndAccountNumberSelectors` (1 deposit) |
| `createPqDepositAddress` | derive next subaddress | derive per-deposit spend key, return PQ address; **no registration needed** | return H-I-T-C; **requires confirmed registration** | 🟡 Aggregated tested; ⬜ Index path (registration→deposit) not E2E |
| `listPqDepositAddresses` | enumerate subaddresses | list issued deposits + indices | same (needs registration) | ⬜ |
| `getPqDepositScheme` | n/a | reports `aggregated-multikey` + count | reports `single-key-index` + count | ⬜ |
| `validateAddress` (RPC) | parse + report validity | accepts classical, PQ, H-I-C/H-I-T-C, or index | same | ✅ `addressIndexAndAccountNumberSelectors` |
| selector resolution | n/a | index/address/account-number → bucket | same | ✅ same test |

## B. Registration (PQ-specific)

| Operation | Aggregated | Index | Status |
|---|---|---|---|
| `registerPqAccount` (free, PoW) / `registerPqAccountPaid` (fee TX_PQ) | optional (only needed if you want a short account number for the **primary**) | **required before any deposit** (gives H,I) | ⬜ not E2E; `PqFreeReg.BuildsValidRegistration` covers the tx shape only |
| `getPqAccountStatus` | reports registered + H-I-C number once the reg tx confirms | same | ⬜ |

## C. Receiving / balance

| Operation | Intended (CN) | Aggregated | Index | Status |
|---|---|---|---|---|
| Output detection | scan with view key | shared view key decapsulates every owned output | one view key | ✅ `PqScanTests`, `PqWalletSyncE2E` |
| Bucket attribution | by subaddress | match per-deposit spend pubkey | recover subaddress **T** | 🟡 unit-level; ⬜ deposit credit not E2E |
| `getBalance` (global) | total / unlocked | `getActualBalance` (confirmed) + `getPendingBalance` | same | ✅ `PqWalletSyncE2E` |
| `getBalance(address)` | per-subaddress actual + locked | per-bucket: `depositBalance − depositPendingBalance` / pending | same | 🟡 `addressIndexAndAccountNumberSelectors` (0 funds) |
| coinbase maturity | locked until `minedMoneyUnlockWindow` | enforced via `unlockHeight` in `spendableInputs` + chain-context | same | ⬜ not asserted for a wallet |

## D. History

| Operation | Intended (CN) | Aggregated | Index | Status |
|---|---|---|---|---|
| `getTransactions` / `…Hashes` / `getUnconfirmedTransactionHashes` | filter by address(es) + paymentId + block range | per-bucket filter; accepts PQ addr / account number / index | same | 🟡 filter tested with stubs + selectors; ⬜ deposit tx filter not E2E |
| per-address transfers | one `WalletTransfer` per owned address the tx touched | `transfersByDeposit` → primary + deposit transfers | same | 🟡 `WalletLedger`-level |
| `getTransaction(hash)` | tx detail | from the PQ ledger | same | ✅ `PqWalletSyncE2E` |

## E. Sending / spending

| Operation | Intended (CN) | Aggregated | Index | Status |
|---|---|---|---|---|
| coin selection / fee / denominations | largest-first, two-pass fee, change | shared `buildPqSend` | same | ✅ `PqSenderTests` |
| **spend authority per input** | sign with the key the output committed to | **per-deposit** key for deposit inputs, primary for primary | the **one** key for all | ✅ `PqTxBuilder.PerInputDepositKeysPassConsensus`, `PqSender.AggregatedDepositInputSignedWithDepositKey` / `SingleKeyIndexUsesOneKeyForDeposits` |
| `sendTransaction` sources | restrict spend to given addresses | `sourceBuckets` filter | same | ✅ `PqSender.SourceBucketFilterRestrictsInputs` |
| **change destination** | explicit `changeAddress` (valid+ours) → sole address → sole source → else `CHANGE_ADDRESS_REQUIRED` | change re-scans into the chosen bucket (`pqChangeTemplate`) | same (T carried) | ✅ `PaymentGateTest.ChangeDestinationRuleMatchesCryptoNote`, `PqSender.ChangeRoutedToChangeDestination` |
| relay / reserve / rollback-on-fail | add-before-relay, delete-on-fail | `addUnconfirmedTransaction` then relay; rollback on relay error | same | 🟡 logic present; ⬜ failure path not tested |

## F. Keys / backup / signing

| Operation | Intended (CN) | PQ behavior | Status |
|---|---|---|---|
| `getSpendkeys(address)` | per-address spend keypair | any of our addresses → the 32-byte master seed (id = hash(seed)) | ✅ `PaymentGateTest.getSpendKeysAcceptsOwnAddress` |
| `getViewKey` | classical view secret | none classical; PQ tracking key is the audit credential | 🟡 |
| `getMnemonicSeed` | per-address electrum words | single identity → master seed as electrum words (address ignored) | 🟡 |
| `signMessage` / `verifyMessage` | per-address signature | ML-DSA over the one spend key (address ignored — single signing identity) | ⬜ |

## G. Lifecycle / sync

| Operation | Intended (CN) | PQ behavior | Status |
|---|---|---|---|
| save / load | persist + restore wallet | v9 container + persisted PQ ledger; balance/history restore without rescan | ✅ `PqWalletIntegration.BalanceSurvivesSaveAndReload` |
| reorg / detach | roll back balance + history | `WalletLedger::rollbackToHeight` on `onBlockchainDetach` | ✅ (primary) `PqWalletIntegration.ReorgDetachReversesCredit`; ⬜ deposit-output reorg |
| tracking / view-only | scan, refuse to spend | zero seed → scan via tracking key, `sendPqTransfer` throws | ⬜ not E2E |
| reset / rescan | re-scan from a height | re-derives the ledger | ⬜ |
| `getStatus` / `getBlockHashes` | node/sync status | pass-through | 🟡 low risk |
| mining keys from wallet | n/a | `MiningKeyLoader` reads the seed (both wallet formats) | ✅ `PqChainTests`, mining path |

---

## Open gaps / next tests (the ⬜ and ❌ rows above, prioritized)

1. **Index-mode deposit lifecycle, end to end** — register account → confirm → create
   H-I-T-C deposit → receive → per-deposit balance → spend (one key) → change. No test
   drives this today; it is the least-exercised mode.
2. **Aggregated deposit credit + spend, end to end** — a real `WalletGreen` receives to
   a deposit address and the deposit balance + history + spend all reflect it (unit
   pieces exist; the full path through scan→attribution→balance→spend does not).
3. **Deposit-output reorg** — orphaning a block that credited a *deposit* rolls back the
   per-deposit balance (only the primary case is covered).
4. **Tracking/view-only wallet** — scans and reports balance but `sendTransaction`
   refuses with a clear error.
5. **Coinbase maturity** — a freshly mined output is locked until the unlock window and
   is not offered for spending before then.
6. **Relay-failure rollback** — a failed relay un-reserves inputs and drops the
   unconfirmed change/history.

These become the deposit-lifecycle test matrix: **{Aggregated, Index} × {receive,
per-address balance, history filter, spend, change, reorg} × {walletd, simplewallet}**.
Each cell that is wrong is a bug we fix on our terms, grounded in the pre-PQ behavior.
