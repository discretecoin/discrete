# Native atomic swaps — draft implementation proposal

This candidate adds conditional XDS funding and claim/refund transactions, wallet/RPC preparation, and laboratory Bitcoin/Solana settlement adapters. An honest owner can claim under the agreed hashlock or recover through the timed refund branch in the tested scenarios. The proposal is open for maintainer review; mainnet activation remains disabled.

## Code and consensus boundary

The four original Core commits are retained through `f3f84ce6ba44f5391a5bec78418a5d78052a1b3d`, based on `ed4a27005bdaa211ff68bfb31f7bd1f7013c7771`. This publication adds companion laboratory code and evidence without changing those tested native files. Canonical master was observed at `3e8ef0bad719c6ac6304674f76df52cc5aecbea7`; this branch has not been rebased onto that newer base.

| Review area | Source |
|---|---|
| Transaction/output grammar | [PqTxType.h](../../include/PqTxType.h), [CryptoNoteSerialization.cpp](../../src/CryptoNoteCore/CryptoNoteSerialization.cpp) |
| Authorization, spentness, amounts and fees | [SwapValidation.cpp](../../src/CryptoNoteCore/SwapValidation.cpp), [Blockchain.cpp](../../src/CryptoNoteCore/Blockchain.cpp), [TransactionPool.cpp](../../src/CryptoNoteCore/TransactionPool.cpp) |
| Activation | [Currency.h](../../src/CryptoNoteCore/Currency.h) |
| Wallet construction and RPC | [SwapWallet.cpp](../../src/Wallet/SwapWallet.cpp), [SwapTransactionBuilder.cpp](../../src/Wallet/SwapTransactionBuilder.cpp), [WalletRpcServer.cpp](../../src/Wallet/WalletRpcServer.cpp), [WalletLegacy.cpp](../../src/WalletLegacy/WalletLegacy.cpp) |
| Native tests | [test_swap_chain.cpp](../../tests/test_swap_chain.cpp), [TestSwapWallet.cpp](../../tests/UnitTests/TestSwapWallet.cpp) |
| BTC, durable journal and private network tests | [Linux harness](lab/swap-vps-v05/linux-harness/) |
| Rust Solana escrow | [src/lib.rs](lab/swap-vps-v05/sbf-v3/src/lib.rs), [Cargo.lock](lab/swap-vps-v05/sbf-v3/Cargo.lock) |
| Real-RPC adapter and coordinator | [Solana driver](lab/swap-vps-v05/rpc-v3-stage/solana-rpc-harness/driver.py), [paired harness](lab/swap-vps-v05/rpc-v3-stage/paired-rpc-harness/) |

`TX_SWAP_FUND`, `TX_SWAP_SPEND` and `SwapOutput` extend the consensus grammar. Old nodes reject the new format, so enabling these transactions requires a coordinated Discrete hard fork. Current admission requires explicit test activation; no mainnet height is selected. The base fee stays 0.01 XDS per transaction and no mandatory XDS RBF is introduced.

The `f3f84ce` timer correction is separate from the swap rules: it fixes rounding/range handling of steady-clock deadlines, retaining the original 150 ms HTTP assertion. It can be reviewed independently from the preceding swap commits.

## Retained validation

| Scope | Recorded outcome |
|---|---|
| Native candidate Linux | First CTest38/39 with UnitTests timeout1800s. Separate unchanged UnitTests retry:676/676, one preexisting disabled case,2292.65s. All39 groups have PASS across two runs; there was no single39/39 run. |
| Timer | Linux original HTTP threshold30/30 repeats; Windows System140/HTTP11 passed. |
| Same-candidate integration | Network12, boundaries12, adapters/journal58 and fixture-pair4 passed. BTC success and owner refunds used real Bitcoin regtest. |
| Rust SBPFv3 | VM13 and24 paired C/Rust differential scenarios passed. Matching rebuild was same host/path/toolchain. ELF SHA256:`30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`. |
| Actual private Agave | Six finalized RPC cases, two real four-XDS-node/two-wallet success/refund cases, and clean restart preserving23 settled account snapshots. Synthetic six-decimal SPL tokens were used. |

Read the [native final audit](lab/swap-vps-v05/audit/native-unit-retry-final-addendum.md), [actual RPC/pair audit](lab/swap-vps-v05/audit/actual-v3-runtime-evidence-review.md), [escrow source review](lab/swap-vps-v05/audit/sbf-v3-port-review.md), and [loader review](lab/swap-vps-v05/audit/agave-v3-loader-evidence-review.md). [Terminal logs and receipts](lab/swap-vps-v05/remote-evidence/) preserve exact command/source/binary identities and original failures.

These are recorded laboratory results, not fresh CI results for the publication commit. Current GitHub checks must be read separately. No node, deployment, new native/chain test or real-fund operation is part of this publication.

## Maintainer decisions and remaining qualification

- Review one consumed identity across claim/refund and ordinary spending, canonical signing domains/encoding, checked principal/fees, pool/template consistency, and database rollback/reorg behavior.
- Integrate against the agreed current base and downstream wallet; preserve ordinary payments and historical funds.
- Select final production wire IDs, amount/recovery composition, supported wallet modes, timing/amount limits and key/backup custody. The local construction uses public amounts and does not choose the separate confidential-amount/recovery workstreams.
- Exercise actual process-death/uncertain-send/expired-blockhash recovery, incomplete swaps across abrupt host restarts, full XDS/BTC backup restore, independent-host splits, disk faults and sustained load.
- Qualify actual Circle USDC separately. The current Solana program/mint IDs are synthetic laboratory fixtures; production deployment and immutable-authority handling need their own specification and acceptance.
- Rehearse activation with old/new nodes and obtain maintainer review before any mainnet activation.

The 11-confirmation XDS floor and foreign-chain budgets are measured/tested laboratory policy, not global finality or final production settings. The Python coordinators are executable laboratory implementations; complete end-user GUI and recovery integration remain open.

## Companion source provenance and execution

[PUBLICATION_MANIFEST.json](PUBLICATION_MANIFEST.json) lists every imported companion file, original review-package path, size and SHA256. Native implementation is in the repository's normal source tree. The companion layout preserves original import relationships; build dependencies and keys/ledgers are not supplied. The four original C/SBF comparison files remain under `lab/swap-localnet-v04/` for unchanged differential tests.

Use [Linux harness prerequisites and explicit executable overrides](lab/swap-vps-v05/linux-harness/README.md) and [Rust build/VM instructions](lab/swap-vps-v05/sbf-v3/README.md). The metadata-bound native runner requires a real Git checkout selected with `SWAP_CORE_DIR` and freshly built binaries selected with `SWAP_BUILD_DIR`. Host-specific outer scripts describe the original controlled lab layout and are not one-click production installers. Use fresh synthetic run identities; do not reuse captured signed intents.

Historical source manifests/reports describe the original larger review package. Their date, exact hashes and pending-at-that-time statements are retained; some referenced preparation/host artifacts are outside this selected public payload. No private credential store, wallet backup, ledger or administrative SSH helper is published here.
