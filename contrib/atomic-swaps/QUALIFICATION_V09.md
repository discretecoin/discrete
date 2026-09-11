# Revision 0.9: canonical PQ v2 integration — 2026-09-11 UTC

This revision integrates canonical master
`644ce7624c6c2dc8c8dd7edacea05985ae585c50` with the prior swap proposal at
`9a42ca7b26a6043e145c6ba68401634d0f1aa560`, addressing the
[maintainer's integration request](https://github.com/discretecoin/discrete/pull/39#issuecomment-5628305556).
The base includes PQ v2 from `7d00ff73` and the subsequently merged P2P transport
from PR #41. Canonical transport defaults and the swap lab's loopback isolation
are preserved. The new canonical `P2pTransportNodeTests` target needed the same
MSVC legacy-stdio link library already used by other Core test targets; the
Windows-only addition resolves its reproduced `_vsnprintf` link failure.

## Compatibility contract

| Namespace | Identity | Value |
|---|---|---|
| Transaction subtype | Canonical ordinary PQ | `0x01` |
| Transaction subtype | Canonical ordinary PQ v2 | `0x04` |
| Transaction subtype | Swap spend | `0x05` |
| Transaction subtype | Swap funding | `0x06` |
| Output variant | Swap output | `0x12` |
| Output variant | Maintainer's planned PHASE 2 hidden output | `0x13`, unused here |

Canonical delivery activation remains unscheduled. Swaps retain explicit
isolated-test activation; mainnet and default testnet are disabled. One native
fee atom remains **0.01 XDS per transaction**. The Solana program is unchanged.

Core semantic, input, output, pool and block-fee dispatch preserve both canonical
ordinary transfer eras alongside the two swap families. Historical input
validation uses the height of the carrying block. Wallet scanning retains
canonical strict-v2 routing for ordinary `0x04` receipts and accounts for swap
principal separately from wallet change and fees. Python funding verification
accepts canonical PQ v2 source transactions and only the new swap-funding family.
Witness discovery can pass ordinary and funding entries to locate spend `0x05`.

The built-in HTML explorer now labels both swap families, includes their fees
in transaction rows, details and block totals, and renders the referenced swap
input and conditional output. Its refund-height text explicitly retains the
claim right until the output is spent. Ordinary transfer display is preserved.

Solana funding/refund send uncertainty now returns an explicit unknown result,
retaining the exact signed attempt. A later step checks its receipt before any
retry or the existing expiry-qualified renewal path. Previously, an exception
at send time immediately attempted renewal even when the retained blockhash was
still live or the transaction had just executed. The actual legacy owner run
exposed the refusal; deterministic VM cases cover late finalization, a lost
funding reply, a failed live-hash send and a lost refund reply. No expiry,
authorization or accounting guard was relaxed.

Earlier unactivated swap-funding `0x04` transactions are deliberately rejected
as swap contracts. They cannot be renumbered in place: signatures, transaction
IDs, outpoints, agreements and stored checkpoints commit their bytes. Preserve
old ledgers, wallets, drafts and journals with their original source and binary.
All current ledger tests use fresh synthetic state. Earlier qualification
documents and `lab/` records remain historical and are not relabeled as current
wire compatibility evidence.

## Executed qualification

Source inventories remained unchanged during the accepted runs. The
[manifest](QUALIFICATION_V09.json) binds tested bytes, normalized Git blobs and
receipt digests. Detailed wallets, keys and execution receipts stay private.
These rows have different scopes and must not be summed into a single test count.

| Check | Result and scope |
|---|---|
| Offline runtime | 497/497, no skips/errors/failures; 53.968 s. Includes the subtype/source/discovery and uncertain Solana send regressions, crypto, recovery, CLI/TLS and pinned-ELF VM checks. |
| Windows native build | Final Release ALL_BUILD succeeds with OpenSSL 3.5.3 and PQ transport compiled; 1,360 selected native/dependency source files are inventoried. |
| Final native focused cases | 22/22 SwapChain and 28/28 swap wallet/store/PQ-v2 pool cases. Mixed subtype blocks, fees, activation boundaries, rollback/rescan, reopen and onward ordinary PQ-v2 spending pass. |
| Final network regression suites | 3/3: P2pTransportTests (23 cases), SynchronizationActivityTests (8) and PqWalletSyncE2E (34); 150.132 s. |
| Earlier adjacent PQ suites | 12/12 before the later HTML-only and P2P integration changes. Preserved validation/scanning behavior; this is explicitly earlier whole-source evidence. |
| Final actual XDS/Bitcoin hardened owner | 2/2, 42.412 s. Durable funding/checkpoints, claims, ordinary spending, actual explorer HTTP and lost-reply/same-wallet restart recovery. |
| Final actual XDS/Bitcoin original owner | 3/3, 50.674 s. Unfunded success, protective foreign refund and fresh-process recovery on fresh synthetic ledgers. |
| Final actual XDS/Solana hardened owner | 1/1, 103.059 s. Durable preparation, paired checkpoints, claims, reopen without new sends and ordinary XDS/SPL spending. |
| Final actual XDS/Solana original owners | 2/2, 432.765 s. Paired settlement and protective backup/refund after the real finalized-slot deadline, with fresh-process no-send checks before maturity and after refund. |

The final Solana cases use the unchanged pinned ELF and public fixture sources.
The bounded Agave process was resumed with its same ledger, genesis and ready
identity for the final runs; native ledgers were fresh. Provider history and
credentials were retained for the accepted recovery scenario.

The Windows P2P node-matrix executable compiles and links. Its actual process
matrix requires the upstream Linux namespace fixture; the containing PR's
P2P workflow supplies that separate gate. The local transport-unit suite uses
supported dynamic loopback sockets. The native qualification binary's version
text retains the interim checkout `86edb91`; binary hashes and source inventories
bind the executed code. These binaries are not release artifacts.

The HTTP regression first reproduced the missing swap type on the real daemon.
After correction it checked funding, claim and ordinary-transfer pages, row and
block fees, the spent-output link and refund height. The initial test-only
closed-owner reference error and the reproduced MSVC link failure are retained
as failed attempts, excluded from accepted results. Historical lab bytes and
the original `9a42ca7` source/build remain preserved.

The earlier actual Solana owner run exposed the send-time renewal refusal.
A later chain read showed its funded escrow, but the exact old funding receipt
could not be recovered from pruned provider history. That failed test process
also used an ephemeral owner-journal key, so its original Owner journal was not
reopened. The failed run and ledger are preserved; they are not accepted as
Owner recovery evidence. The final backup/reopen qualification uses retained
credentials and available provider history, as required by the owner contract.

## Scope limits

These are owned synthetic ledgers and test assets. Independent provider history,
dedicated signing wallets, recoverable keys and chain liveness remain operating
assumptions. Public chain timing/finality, real USDC, GUI operation, independent
checkpoint-host fault isolation, physical power loss and production capacity
are not established by this integration. The earlier
[recovery qualification](QUALIFICATION_V08.md) explains the unchanged provider,
restore and input-reservation limits.
