# Native atomic swaps — maintainer review candidate

This proposal adds a narrow conditional XDS output, native wallet construction, and independent Bitcoin/Solana settlement. The current revision integrates upstream `644ce7624c6c2dc8c8dd7edacea05985ae585c50`, including its PQ v2 delivery declaration and P2P transport, with per-owner funding, settlement and recovery. A public synthetic Solana fixture reproduces the owner integration; normal immutable deployment has separately recorded earlier evidence.

The native base fee remains **0.01 XDS per transaction**. Claim/refund share one consumed-output identity. Mainnet and default-testnet activation remain off; enabling the new grammar requires a coordinated hard fork.

## Review map

| Layer | Entry point |
|---|---|
| Consensus grammar and validation | [PqTxType.h](../../include/PqTxType.h), [SwapValidation.cpp](../../src/CryptoNoteCore/SwapValidation.cpp) |
| Chain, pool, accounting and undo | [Blockchain.cpp](../../src/CryptoNoteCore/Blockchain.cpp), [TransactionPool.cpp](../../src/CryptoNoteCore/TransactionPool.cpp) |
| Native wallet and signing | [SwapWallet.cpp](../../src/Wallet/SwapWallet.cpp), [WalletRpcServer.cpp](../../src/Wallet/WalletRpcServer.cpp) |
| Local read-only observations | [RpcServer.cpp](../../src/Rpc/RpcServer.cpp), `/get_swap_outpoint` |
| Per-owner runtime, CLI and recovery | [runtime/README.md](runtime/README.md), [session.py](runtime/swap_runtime/session.py) |
| Independent native/Bitcoin verification | [xds.py](runtime/swap_runtime/xds.py), [bitcoin.py](runtime/swap_runtime/bitcoin.py) |
| Parameterized Solana deployment | [solana/README.md](solana/README.md), [solana.py](runtime/swap_runtime/solana.py) |
| Current integration evidence and limits | [QUALIFICATION_V09.md](QUALIFICATION_V09.md) |

## Wire compatibility

Canonical `TX_PQ_V2` keeps transaction subtype `0x04`. Swap funding uses `0x06`
and swap spending keeps `0x05`. The `SwapOutput` variant tag stays `0x12`;
`0x13` is left free for the maintainer's planned PHASE 2 `PqHiddenOutput`.
Transaction subtypes and output variant tags are separate namespaces.

Earlier unactivated lab revisions used `0x04` for swap funding. Their signed
transactions, native drafts and owner journals are incompatible with this
profile. Preserve those artifacts with their original binary and isolated
ledger; use fresh synthetic state for this revision. Relabeling a signed
transaction would change its prefix, signature, transaction ID and referenced
outpoints. Ordinary canonical PQ v2 transactions remain valid funding sources.

## Protocol and operational rules

The foreign owner funds the longer-deadline Bitcoin HTLC or Solana escrow. The XDS owner verifies it and funds the shorter-deadline native output. The foreign owner first claims XDS; the XDS owner validates that public claim's signature, exact outpoint and hashlock, then claims the foreign escrow. Otherwise each owner can use its timed refund. Claims remain valid after the refund height until a refund consumes the contract: expiry creates a competing refund right, not an exclusive refund window.

Before first disclosure, the runtime requires both exact contracts, current owned-node observations, at least eleven XDS funding confirmations, separate chain-native time budgets and available settlement fees. Eleven blocks are a client qualification floor, not a finality theorem or mainnet parameter selection. Changed tips, unknown state, frozen Solana claim destinations and insufficient fee balance refuse first disclosure.

Signed bytes and possible exposure are committed before sending. After restart, receipts are checked before exact-byte retry. A pre-send crash cannot bypass a later disclosure gate: authenticated evidence of an actual public transaction is required for protective retry after the original admission window. Backup restore creates a new recovery-only journal. Solana renewal requires finalized blockhash expiry and a subsequent still-funded escrow, preserves every economic field and appends rather than overwrites signed attempts.

XDS authorization retains the native scheme; Bitcoin and Solana retain their own signature/finality assumptions. This is not an end-to-end post-quantum swap claim. Amounts and shared hashlocks are public and correlate the chains. USDC issuer freeze authority remains an asset property even when the escrow program is immutable. No bridge custodian, general script VM, foreign light client in XDS consensus, automatic fee increase or mandatory XDS RBF is introduced.

## Revision boundary

The proposal is consolidated on the canonical base above. The preceding review
head is `9a42ca7b26a6043e145c6ba68401634d0f1aa560`; its dated qualification
records describe that older source, including the old funding subtype. The
integration preserves canonical carrying-block activation checks and strict-v2
wallet scanning, adds coexistence coverage, and updates native and Python
dispatch together. It does not schedule either activation.

The `lab/` tree and [PUBLICATION_MANIFEST.json](PUBLICATION_MANIFEST.json) are
frozen historical evidence. The [owner lifecycle](runtime/OWNER-LIFECYCLE.md)
starts from agreed unfunded terms and coordinates funding, signed messages,
settlement and protective recovery. The earlier funded-session interface also
remains supported. Market negotiation, production key custody, GUI integration
and activation deployment remain separate work. This PR requests code review
and integration decisions; public activation remains disabled.
