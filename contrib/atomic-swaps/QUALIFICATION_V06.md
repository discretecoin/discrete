# Revision 0.6 qualification — 2026-09-10

This is a maintainer-review record of executed checks, not a mainnet activation certificate. Native source includes upstream `9fd5415ca5332b512b02dd091fc8d448c5c8b6b5` through `150a6c0`. The native follow-up is `933d579`, with test-only `b342752` and CI-only `eb19f3a`. Source hashes for the new companion package are recorded in `QUALIFICATION_V06.json`.

## Current evidence

| Check | Observed result and scope |
|---|---|
| Fresh merged native baseline | Release build; CTest 39/39, 444.01 s |
| Fresh final native build | Release build; CTest 39/39, 352.74 s |
| Native cases within final CTest | Unit 681, System 140, wallet sync 34, SwapChain 20; one/four preexisting disabled Unit/System cases retained |
| Local outpoint RPC | 5 actual-process tests, including ordinary and restricted default testnet, method/Origin/body bounds, lab alias and retry |
| Existing network/cross-chain suite | First 11/12, one preserved Bitcoin mining RPC timeout; exact failed case subsequently passed with unchanged assertions/timeout |
| Existing startup/network boundaries | 12/12 |
| Combined new offline qualification | 162/162, zero skips/errors/failures, source hashes unchanged |
| Offline breakdown | Bitcoin 29; journal 38; Session 29; native adapter 17; Solana adapter 17; HTTP/CLI 9; deployment profile 7; program VM 16 |
| New Bitcoin adapter on Core 31.1 | 4/4 real regtest: claim/ordinary spend, refund/restart, lost acknowledgment/exact retry, reorg/reconfirmation and full witness conflict handling |
| New XDS adapter on native nodes | 4/4: claim, refund/lost acknowledgment/wallet restart, actual reorg/exact retry, fresh child-process journal reopening without signing wallet |
| New two-owner Session XDS/Bitcoin | Final runtime: 2/2 on both real ledgers, 42.433 s: success, uncertain acknowledgment/child recovery, public witness handoff, ordinary spending and both timed refunds on abandonment |
| New Solana initial deployment | Private Agave 4.2.2: newly generated program account deployed normally, mutable deployment rejected by admission, upgrade authority removed and exact finalized immutable readback obtained |
| New Solana RPC settlement | Actual claim/refund each transferred exactly 1,234,567 synthetic units, vault 0, finalized full-wire receipts, tombstones 2/3; early refund and repeated settlement rejected |
| New two-owner Session XDS/Solana | Final runtime: 2/2 on both real ledgers, 358.303 s: public native witness to foreign claim, receipt-only fresh-process reopening with zero sends, both timed refunds without disclosure |
| Solana renewal after process restart | Additional real-ledger case 1/1, 239.308 s: acquired blockhash at slot 3668, finalized expiry and funded escrow at 3822, renewed inclusion at 3855; original bytes preserved, same economic intent, exactly one send and receipt-only retry |
| Cleanup/evidence audit | Native 1,667 source files and 44 binaries matched; final pair runtime hashes stable; owned native/Bitcoin processes 0; private Agave service exited 0 and stopped |

The 162 offline tests include six actual abrupt subprocess exits at persistence/send/recovery boundaries. Session state-machine tests use controlled adapters. The Bitcoin pair uses actual Session/adapters/LocalRpc on both ledgers. The Solana pair uses local native RPC and real Agave loopback RPC forwarded through authenticated pinned-key SSH into the owned private namespace; its remote fixture creates synthetic contracts. Neither pair replaces ledger or admission responses with mocks. The native-only Session recovery case mocks the foreign observation and must not be counted as a separate fully paired proof.

The first network timeout remains a failure of that first invocation. Its unchanged retry passed after concurrent native testing ended; this does not prove resource contention was the exact cause. A pair rerun during concurrent source edits was also preserved but excluded from final evidence; the final run brackets identical source hashes.

## Solana artifact identity

The private-validator-tested ELF is 32,960 bytes, SHA-256 `561e0b7ad5e4be59a3056482ea94370064d201f45a378964d0fdb9f0ff76a901`. Its exact public manifest/ELF are the [offline fixture](runtime/tests/fixtures/solana-v06/README.md). The Rust body matches the reviewed donor state machine; generated immutable program/mint constants make normal initial deployment possible.

The initial deployment/standalone RPC run used adapter SHA `203f971f97c6847704cd0938f3afa99c08b867643fd8213e91b95cbd5d767a5c`. The final adapter, SHA `92640e163f2b5623561ec08e40247a1038ad8ad0dfa36233ddb3ec581e26761b`, also validates fee-payer account ownership, authenticates blockhash acquisition provenance and marks exact public receipts explicitly. All three new paired cases executed this final adapter and unchanged final journal/Session modules on actual Agave RPC. The third case exercises real finalized expiry and process restart, not a mocked expiry response. LiteSVM separately executes `BlockhashNotFound` and renewed settlement against the compiled program.

The first two paired cases ran before the third test was appended; both test-file hashes and identical runtime hashes were preserved. The final public test includes all three cases. These observations establish behavior on the owned private ledger, not an independent proof of public-network finality.

## Review findings incorporated

- A possible-exposure marker after pre-send process death is insufficient to authorize late first disclosure. Session repeats fresh admission until it holds authenticated evidence of a public transaction.
- Receipt-based disclosure evidence requires an explicit full-wire observation flag. Solana signature-status-only pending results cannot establish that stronger claim.
- Solana fee admission requires an ordinary system-owned, non-executable, empty-data payer with enough lamports. A funded token/program-owned account is insufficient; this profile does not use durable nonces.
- Renewal binds the original transaction to authenticated blockhash acquisition context. A restarted or lagging RPC bank predating acquisition cannot turn an unknown future hash into expiry evidence. New attempt evidence is bound by AES-GCM associated data; removing its version marker or modifying it fails authentication.
- Native admission brackets the actual tip hash as well as height/funding block; same-height tip replacement refuses admission.
- Restored funding is rejected even through the journal's internal broadcast path. Session metadata is never broadcast. Public terms bind to authenticated encrypted configuration.
- Native spentness uses the pool's existing index instead of copying/scanning the complete pool. HTTP handler's 512-byte bound applies after HTTP parsing; it is not a transport allocation bound.
- JSON configuration/RPC fields are unique, Bitcoin amounts use exact decimals, and the CLI accepts private material through files and redacts exceptions.

## Integration and production limits

The current runtime completes settlement/retry/reconciliation for already-funded fixed contracts. It is not an order-negotiation service, automatic funding planner, wallet GUI, production key store or autonomous always-on watcher. Restore cannot manufacture a settlement intent or wallet credential absent from an old backup; whole-storage rollback still needs an external freshness anchor. Native payout address ownership relies on the authenticated native wallet, with independent wire/role/signature validation around it.

No actual Circle-issued USDC, public-network swap, mainnet activation, independent-host endurance, disk-failure campaign or production inclusion/finality calibration was performed. Both new Session pairs were exercised on real private ledgers. The Solana receipt-reopen test covers already-finalized settlement; lost acknowledgment is separately covered in the Bitcoin pair. Earlier frozen paired results remain historical and are not relabeled as new-runtime coverage.

Journal schema remains 3, but new evidence-bearing attempts use a versioned authenticated-data format. This runtime reads legacy attempts; legacy attempts without sealed acquisition provenance cannot be renewed. Older binaries cannot read the new evidence-bearing attempts. Retain a pre-upgrade backup and its matching binary; do not downgrade a live journal after creating new attempts. See the [runtime recovery contract](runtime/README.md#restart-and-backup).

The mint presets match [Circle's registry](https://developers.circle.com/stablecoins/usdc-contract-addresses), checked 2026-09-10. A selected mint preset still needs the correct independently trusted full genesis hash and deployed immutable program. Synthetic tests at an official mint address are not real USDC tests. Native consensus/fee/activation rules were not broadened by this runtime follow-up; new public formats still require maintainer review and a coordinated activation process.

GitHub execution is a separate, mutable evidence level. The workflow repeats offline checks on Linux/Windows and the existing native CI includes swap/read-RPC tests. Consult the checks attached to the exact PR head; local results do not assert their outcome. Full logs and synthetic wallet/ledger directories remain local. Public review includes source, fixture and aggregate qualification metadata only.
