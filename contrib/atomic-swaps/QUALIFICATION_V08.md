# Revision 0.8: durable funding and recovery — 2026-09-11 UTC

This revision extends `1df1367b3b829fadcde9310794a95acd2798b31c` with native
funding recovery, independent owner checkpoints and a public synthetic Solana
fixture. It does not change the native consensus rules, wire formats, Solana ELF,
activation policy or base fee from that revision. One native fee atom remains
**0.01 XDS**. Funding and settlement are separate fee-paying transactions.

## Behavior under failure

- Native preparation records an encrypted immutable unsigned draft before signing
  and the prepared transaction before replying. A retained operation can retrieve
  the exact prepared bytes after a lost RPC response and wallet-process restart.
  It does not select new inputs when the result of an earlier operation is unknown.
- Before a new preparation intention, the owner checks a stable daemon tip and
  wallet scan height. Known scan lag waits without creating an operation or plan.
  Native admission still checks its own state; a later race can still refuse the
  operation. An already-started operation uses exact lookup despite current lag.
- An optional external signed checkpoint stream commits the complete encrypted
  Owner and Session state, including plans, transmissions and possible disclosure.
  Fresh head checks detect a local historical rollback while independent provider
  history survives; a retained local accepted head also rejects provider rollback.
  Historical restoration creates a new permanently protective checkpoint.
- Unchanged polls authenticate and check freshness without appending duplicate
  full backups. Changed logical state always requires a new checkpoint.
- A public Agave fixture supplies the full setup and RPC bridge previously provided
  by an operator-specific module. It uses a pinned program and synthetic legacy SPL
  mint in an isolated genesis. No private implementation is needed to reproduce it.

New CLI owners use the durable preparation protocol. Authenticated version-one
owners remain supported with their original uncertainty policy. Independent
checkpoints are explicitly selected with `--anchor-profile`; a missing profile
cannot downgrade an already anchored owner. See the [owner guide](runtime/OWNER-LIFECYCLE.md),
[checkpoint protocol](runtime/ANCHOR.md) and [fixture instructions](runtime/solana_fixture/README.md).

## Executed qualification

The source inventories were unchanged during each accepted final run. The public
[manifest](QUALIFICATION_V08.json) binds the current source and aggregate results.
Detailed receipts, wallets and credentials remain private. Counts below describe
different scopes and must not be summed into an invented end-to-end test count.

| Check | Observed result and scope |
|---|---|
| Final offline runtime | 486/486, zero skips/errors/failures; 55.912 s. Includes crypto, durable preparation, paired recovery, abrupt process exits, real loopback TLS, fresh CLI processes and compiled-ELF LiteSVM. |
| Final Windows native build | ALL_BUILD succeeded; 646 inventoried native source files match the final build receipt. |
| Final native focused tests | 26/26, including durable store publication/reopen, authentication, locks, bounds, exact retry and long Windows paths, plus existing swap-wallet behavior. |
| Final adjacent native suites | 3/3: SynchronizationActivityTests, PqWalletSyncE2E and SwapChainTests. |
| Final actual XDS/Bitcoin, hardened owner | 2/2, 48.433 s. Independently checkpointed durable funding, both claims and ordinary spending; lost preparation reply, abrupt wallet termination, same-wallet reopening and exact lookup with no second prepare. |
| Final actual XDS/Bitcoin, original owner cases | 3/3, 50.880 s. Initially unfunded settlement, ordinary spending, foreign-only protective refund and fresh-process preclaim restoration. |
| Final actual XDS/Solana, hardened owner | 1/1, 103.603 s. Durable native funding and independent checkpoint coordination, both claims using the public native witness, normal reopening with zero new sends and ordinary XDS/SPL spending. |
| Public Solana fixture on actual Agave | 2/2, 247.891 s. Ordinary setup followed by atomic funding and finalized claim or natural refund; empty vault and ordinary token spending. Same public fixture sources and ELF as the final run. |
| Original owner Solana cases through public fixture | 2/2, 456.313 s, at an earlier runtime/native-build snapshot. Includes both claims/ordinary spending and fresh-process foreign-only protective refund. This is separately retained regression evidence, not a claim that these two cases ran on the final hardened-owner source. |
| Earlier full Windows UnitTests | 697/697 with one preexisting disabled test, before the additional Windows long-path correction. Final focused/adjacent/network checks above qualify that correction; this earlier full run is not relabeled as final. |

The financial integration tests use separate in-process signed checkpoint stores.
The offline CLI tests independently exercise pinned HTTPS and fresh client
processes. These results do not prove independent-host checkpoint fault isolation.
The XDS and Bitcoin networks and all Solana tokens were owned synthetic fixtures.

Agave was **4.2.2**, executable SHA-256
`d723f3a99fa3f5b3df6841fc04ac0d8b5302837689d43a07222aa2125b6713d1`.
The unchanged 32,960-byte Solana ELF has SHA-256
`561e0b7ad5e4be59a3056482ea94370064d201f45a378964d0fdb9f0ff76a901`.
The public fixture proves immutable **genesis loading**, not normal deployment or
upgrade-authority removal. The earlier v06 normal-deployment evidence has its own
scope. CI on the containing PR separately reports platform builds, full Linux
native suites and the 486-test offline suite on Linux and Windows.

## Failures retained and corrected

The first actual native run exposed Windows paths longer than MAX_PATH; the store
now uses extended absolute paths consistently, with a native regression case.
Another run correctly refused preparation while the wallet scan lagged behind
the daemon. The fault-injection test now first establishes scan readiness; the
owner also gained the read-only pre-intent readiness check described above.
Neither change retries an absent financial operation automatically.

The first public bridge run exposed decimal serialization in forwarded RPC; the
bridge now preserves exact decimal numbers. The first combined offline run found
a direct-script test import path dependency; the standalone fixture test now works
without inherited PYTHONPATH. Failed receipts and an explicitly cancelled
redundant native test run are retained and excluded from accepted pass counts.

## Remaining operational limits

The independent provider is a trust and availability assumption. Joint rollback of
owner and provider, a malicious provider, compromised signing hosts, or lost keys
and all backups remain outside this protection. External CAS and blockchain
transmission are not atomic; an already authorized transmission can cross a
concurrent restore. Keep one active owner and use dedicated funding wallets.
Native drafts do not globally reserve ordinary wallet inputs.

Explicit `restore --offline-protective` can recover retained evidence without a
reachable provider, but cannot fund, first-disclose a secret, or fence another
running copy. Bounded stores stop instead of pruning live evidence. Physical
power-loss durability, network filesystems, sustained production capacity, public
chain finality/timing, real Circle USDC, GUI integration and mainnet activation are
not qualified by these tests. Public activation remains disabled.
