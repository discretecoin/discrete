# Per-owner settlement runtime

For the coordinator starting with **unfunded agreements**, see
[Owner lifecycle](OWNER-LIFECYCLE.md) and `python -m swap_runtime.owner_cli --help`.
It adds funding, a signed mailbox, automatic native witness discovery and
protective owner recovery. New owners can use durable native preparation and
[independent checkpoint storage](ANCHOR.md); the public
[Solana fixture](solana_fixture/README.md) reproduces the owner integration on an
isolated synthetic ledger. The commands below document the earlier funded-session
interface, which remains supported.

The [revision 0.9 qualification](../QUALIFICATION_V09.md) records the canonical
PQ v2 integration and exact executed checks. Swap funding now uses subtype
`0x06`; old unactivated swap-funding `0x04` artifacts require their original
binary and isolated ledger and must not be relabeled or imported. Ordinary
canonical PQ v2 `0x04` sources are supported.

Python 3.11+ reference library and single-action CLI for existing funded XDS/Bitcoin or XDS/Solana contracts. No daemon, wallet or foreign process is started by the runtime. Process creation belongs to opt-in synthetic integration tests.

## Run

Install `requirements.txt` in a private virtual environment. From this directory, `python -m swap_runtime --help` lists commands. Keys and preimages are read from private files, never command arguments or repository files.

```sh
python -m swap_runtime keygen --journal-key /private/swap.key
python -m swap_runtime init --journal /private/swap.db --journal-key /private/swap.key --swap-id trade-1 --rpc-config /private/rpc.json --config /private/terms.json
python -m swap_runtime observe --journal /private/swap.db --journal-key /private/swap.key --swap-id trade-1 --rpc-config /private/rpc.json
```

RPC configuration contains `xds_daemon`, `foreign`, and optional `xds_wallet` objects, each with `url` and optional `credential_file`/`timeout`. URLs must be literal `http://127.0.0.1:<port>`; remote owned nodes require an authenticated local tunnel. Credential files contain the node's `username:password` or Bitcoin cookie. The transport ignores environment proxies, follows no redirects, checks response IDs, rejects duplicate JSON fields and parses Bitcoin amounts exactly. A legacy daemon missing `/get_swap_outpoint` fails closed.

Session configuration contains `version:1`, a stable ASCII `swap_id`, `role` (`xds-owner` or `foreign-owner`), `foreign_chain` (`bitcoin` or `solana`), complete `xds`/`foreign` contract terms, and `policy`. Constructors in [xds.py](swap_runtime/xds.py), [bitcoin.py](swap_runtime/bitcoin.py) and [solana.py](swap_runtime/solana.py) define the strict field sets: genesis, hashlock, funding identity, amount, role/destination commitments and deadline; Solana also binds a trusted build manifest, immutable program and mint. The configuration is authenticated inside the encrypted journal and cannot be replaced when reopening it.

Policy supplies `min_xds_confirmations` (at least 11), `xds_claim_budget_blocks` (at least 2), `foreign_claim_budget_units`, `max_observation_seconds` (at most 15) and `solana_fee_attempt_reserve` (at least 2). Bitcoin units are blocks; Solana units are slots. These are admission constraints, not a production scheduling formula. Negotiate the longer foreign deadline and measured inclusion/finality margins before funding. The runtime does not infer a safe funding schedule from average block times.

## Owner operations

Use the same journal/key/identity/RPC arguments for each command.

- Foreign owner: `prepare --kind xds-claim --key-file <rho-file> --secret-file <preimage-file>`, then `broadcast --kind xds-claim` and `reconcile --kind xds-claim`. Native rho/preimage files contain 32-byte lowercase hex. Native wallet genesis, role commitment and agreed address must match. Independent verification binds the native self-payout bytes to the role signature; payout ownership/decryption remains the native wallet's responsibility.
- XDS owner: `prepare --kind foreign-claim --key-file <foreign-key-file> --public-xds-txid <candidate>`. This verifies the public native witness; injecting a private preimage is rejected. Bitcoin key files contain 32-byte lowercase hex; Solana uses the standard 64-byte CLI keypair JSON array.
- Refund: `xds-refund` for the XDS owner or `foreign-refund` for the foreign owner, with no preimage.
- Solana renewal: `renew --kind foreign-claim|foreign-refund --key-file <payer>`. Requires authenticated original blockhash acquisition, expiry in a later finalized context, and a subsequent unconsumed escrow. The exact normalized message is preserved; old attempts remain. Null/pruned history or an RPC context predating acquisition is insufficient. The fee payer must be an ordinary system-owned account with enough lamports; durable nonce accounts are outside this profile.

Preparation persists signed bytes and prints only metadata. Acknowledgment is not settlement. Reconciliation can return confirmed to unknown after reorg. Spent funding without an identified valid spender is not success. No automatic chain scan is performed: a peer's candidate transaction ID is only a lookup hint. Bitcoin/native fee or destination replacement is not implemented.

## Restart and backup

Ordinary restart opens the same journal under an OS-held single-writer lock. An uncertain response is reconciled before retrying identical bytes. `backup --snapshot <new-path>` creates a WAL-consistent exclusive snapshot. Keep the encryption key separately.

```sh
python -m swap_runtime restore --journal /private/recovered.db --journal-key /private/swap.key --snapshot /private/backup.db
```

The new journal remains recovery-only: no new swap/funding, absent settlement intent or changed economic terms. It can resend an existing validated settlement or append a qualified Solana renewal. If a crash separated foreign-claim preparation from witness persistence, `witness --kind foreign-claim --public-xds-txid <txid>` re-observes and authenticates that public claim.

New evidence-bearing attempts authenticate their metadata as AES-GCM associated data with `_aad_version:1`, including Solana blockhash acquisition. This runtime reads the legacy format, but refuses renewal without sealed acquisition provenance. Schema version remains 3; old binaries cannot read new evidence-bearing attempts. Preserve a pre-upgrade backup and matching binary for rollback, and do not open an upgraded active journal with an older binary.

A backup predating the necessary intent cannot reconstruct missing signing material; retain original wallet/role credentials for native owner recovery. Do not copy snapshots over live databases or open an old copied snapshot as current state. Whole-storage rollback needs an external freshness anchor to be detected.

This is a trusted-owner-host boundary. AES-GCM protects stored intents/configuration; it is not an HSM, OS keychain or protection from the administrator of an unlocked process. POSIX files use owner-only modes; Windows ACL/disk encryption remain operator configuration. Programmatic callers must not log secret-bearing adapter results. The CLI emits no tracebacks or signed claim bytes.

## Qualification

```sh
python -B qualify.py --output /new/local/qualification-directory
```

This runs the selected offline suites without allowed skips, compares source hashes before/after and executes the pinned Solana ELF. Detailed receipts/logs remain local; CI prints aggregate counters only.

[test_pair_rpc_integration.py](tests/test_pair_rpc_integration.py) exercises two owner sessions on real ledgers: funding, lost acknowledgment, process restart, public-witness handoff, ordinary spending and both refunds. Set `SWAP_CORE_DIR`, `SWAP_BUILD_DIR`, `BITCOIND`, `XDS_TEST_DATA` and `BITCOIN_TEST_DATA` to explicit isolated paths. Set `XDS_RPC_INTEGRATION=1` for the native suite or `PAIR_RPC_INTEGRATION=1` for the pair suite, then run `python -B -m unittest discover -s tests -p <test-file> -v`. The Bitcoin RPC suite runs when `BITCOIND` names an existing Core 31.1 binary.

The private-validator [Solana qualification script](tests/test_solana_rpc_integration.py) is an explicit operator tool, not an automatically started unittest. Its procedure requires a fresh private network namespace, new program keypair, matching offline build, ordinary initial deploy, immutable-authority readback and exact adapter transfers. Test run directories contain synthetic private wallets/keys and stay outside the repository. The committed VM fixture contains only public program bytes and metadata. See [current qualification](../QUALIFICATION_V06.md) for executed paths and remaining limits.

### Reproduce the XDS/Solana pair

[test_pair_solana_rpc_integration.py](tests/test_pair_solana_rpc_integration.py) runs success, both refunds and finalized blockhash-expiry renewal after a fresh process restart. Set `SWAP_CORE_DIR`, `SWAP_BUILD_DIR`, isolated `XDS_TEST_DATA`, `PAIR_SOLANA_RPC_INTEGRATION=1` and `PAIR_SOLANA_BRIDGE_FACTORY` to an absolute private Python module path; run `python -B -m unittest discover -s tests -p test_pair_solana_rpc_integration.py -v` from this directory. The native fixture defaults to `discreted` and `simplewallet`. Create an owned private Agave ledger, legacy SPL test mint, fresh keys and matching immutable deployment using [the deployment procedure](../solana/README.md). The committed VM fixture identifies an earlier private ledger, not a deployable fresh-key identity.

The operator supplies the following transport/funding bridge; SSH is optional. Its module exports `create_bridge()`, which reconnects to the same existing ledger without implicitly resetting, deploying or funding it. It must not print to stdout, which child tests use for receipts.

| Member | Contract |
|---|---|
| `key` | `solders.keypair.Keypair` for the configured fee payer; its ordinary system-owned account holds at least two quoted settlement fees. Synthetic qualification used 1 SOL. |
| `rpc(method, params)` | Synchronous real JSON-RPC result; raises on transport/RPC errors and preserves commitment/minContextSlot. Required methods: `getGenesisHash`, `getAccountInfo`, `getMultipleAccounts`, `getLatestBlockhash`, `getFeeForMessage`, `getSlot`, `getSignatureStatuses`, `getTransaction`, `sendTransaction`, `isBlockhashValid`, `getTokenAccountBalance`. |
| `fund(hashlock, delay_slots)` | Receives canonical SHA-256 hex, never a preimage; creates fresh escrow/token accounts, waits for actual funding finalization and returns the exact contract below. |
| `close()` | Closes only that transport instance, retaining the validator/ledger for subsequent child-process connections. |

`fund` returns exactly `manifest, state, vault, mint, claim, refund, source, depositor, authority, payer, amount, hashlock, deadline_slot, min_context_slot, max_finality_lag_slots`. `manifest` is the independently trusted build-manifest object. Account/payer values are base58 strings; `payer` matches `key.pubkey()`. Claim/refund destinations belong to their respective owners and start empty. `amount` is a positive integer in raw token units (qualification: 1,234,567). `deadline_slot` uses the current processed slot near funding plus the requested delay; the tests request 100 or 1,000 slots. Context floor and maximum finality lag are integer test-policy inputs (qualification: 0 and 128).

The committed standalone Solana script supplies `rpc`, `send`, `create`, `confirmed` and `settlement_case` funding encoding/account ordering for this adaptation. Credentials, transport endpoints and generated wallet state remain operator inputs. The executed pair used a pinned-key SSH bridge; a different operator's bridge has not been independently qualified.
