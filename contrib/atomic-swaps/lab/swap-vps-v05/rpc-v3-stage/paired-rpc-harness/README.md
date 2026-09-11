# V05 paired XDS wallet / Solana real-RPC — SBPFv3 candidate

This is an isolated Linux laboratory runner for two cases: success and abandonment. It uses four actual XDS daemons, two actual encrypted XDS wallet RPC processes and an already running owned Agave 4.2.2 validator. It does not start Bitcoin, contact public RPC, change consensus, or modify frozen V03/V04, Core, Linux or standalone Solana sources. The SPL mint is the frozen synthetic mint, not Circle USDC.

**Candidate scope:** paired runtime logic and all 20 guard assertions are byte-identical to the reviewed package. Only the sibling driver pin changes to bind the new exact ELF profile; staged offline outcomes are in the separate audit receipt. No prior paired result qualifies this candidate. Runtime success, combined memory capacity, long-duration liveness and recovery after process death or expired blockhash remain unqualified. The parent owns Linux/validator qualification and deployment.

## Pinned reuse and minimal changes

`bindings.py` checks five exact dependency SHA256 values before importing the staged standalone `driver.py` and Linux `WalletNetwork`, coordinator `Journal`, `xds_localnet` and path adapter. Deploy the three directories as siblings below the same V05 root; the imports deliberately reject another already loaded helper path. The staged standalone driver is `1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3`; only its SBF SHA256/size constants differ from the reviewed original. Four Linux helpers remain byte-identical.

`PairFixture` overrides only initialization, instruction construction, snapshot context capture and expected-state comparison. It takes an explicit 32-byte per-swap hashlock, has no stored secret/default claim preimage, preserves all original account/meta/192-byte state checks, and retains the single `getMultipleAccounts` context slot. `fixture-overrides.diff` records the exact source-method comparison with the frozen fixture; it is a review artifact, not a patch applied to the standalone driver.

`runner.py` adds the coordinator integration. It only changes `xds_localnet.ROOT` in this process while the owned network is alive, placing node/wallet/journal outputs inside the new run directory. It restores that value on cleanup. All XDS process arguments, HTTP transport, mining, signing, fee and validation paths are inherited unchanged. The old hardcoded `WalletNetwork.admission` and `settle` methods are never invoked. New admission reads the actual ledger each time the coordinator requests first exposure.

## Execution and evidence

Each contract gets a fresh secret held by Bob for his XDS claim. On Solana, the configured synthetic payer is Bob, owns source/refund tokens and must be the existing synthetic mint's authority. A new separate Alice identity owns the claim token account and pays its claim fee. Private synthetic keys and intents are written as owned 0600 files below the 0700 run directory; the configured payer's private key is read silently and is not copied into the run.

The foreign funding wire is signed once and persisted by `Sender.prepare`, then registered in the coordinator journal with the exact same bytes, signature and immutable terms before either can send. The paired wrapper `persist_coordinated` checks kind, instruction, program, accounts, hash, amount, deadline and payer; the unchanged Journal preserves opaque wire identity, durability and exposure. Current funded state, owners and amounts come from fixture snapshots and first-exposure observations. Finalized exact-wire funding/state/accounting precede XDS funding. XDS funding is also persisted before both its initial submission and exact-byte retry.

Immediately before first XDS claim handoff, admission reads the exact unspent XDS outpoint/height/11 confirmations, a finalized foreign funded snapshot, actual claim fee quote and available fee balance, then a processed slot used solely as a conservative clock. The stored policy is 2 XDS blocks of claim budget, 128 Solana slots of claim budget, a 768-slot foreign refund window, at most 96 slots of finalized observation lag, and at most 15 seconds for the observation batch including evidence persistence. These are configured laboratory acceptance bounds, not production timing/finality guarantees. The final monotonic age check runs after the evidence JSON has been persisted and refuses first exposure if the batch aged out. The subsequent journal commit and node handoff still take time: this is not atomic cross-chain freshness, and their runtime delay remains a laboratory measurement/qualification limit. Insufficient or inconsistent data cannot authorize first exposure. The coordinator commits sticky exposure before node handoff; uncertainty never clears it or authorizes a different transaction.

Success mines the XDS claim and extracts the preimage only from node 3's public exact transaction/details/outpoint readback. It requires type 5, fee 1, main-chain inclusion, SwapInput 20, the original funding outpoint/branch 1 and both hashlocks. Only that extracted public value reaches the Solana claim builder. The fresh Solana wire goes through both journals. A finalized claim after the immutable refund boundary is still attempted protectively but cannot make this timing test PASS. Wallet scanning waits happen after foreign redemption, outside the disclosure-to-redemption critical path.

| Case | Required primary owner deltas | Subsequent owner-control check |
|---|---|---|
| success | Alice XDS -1002 atoms; Bob XDS +1000; Bob SPL source -1,234,567; Alice SPL claim +1,234,567; vault 0; state 2 | Alice signs ordinary `TransferChecked` moving the acquired tokens to Bob's bound token account |
| abandonment | Alice XDS -2 atoms total fees; Bob XDS unchanged; Bob SPL refund +1,234,567; vault 0; state 3; coordinator unexposed | Bob signs ordinary `TransferChecked` returning the refunded tokens to his source account |

One XDS atom is 0.01 XDS: funding fee stays 1 atom and settlement fee stays 1 atom. Principal is 1001 atoms with a 1000-atom net payout. No mandatory 0.02 base fee or RBF path is introduced. SOL setup rent, ordinary fee-funding outflows and each receipt's fees are separately recorded in the intent files and case results.

The narrow negative matrix has explicit evidence boundaries:

- **Underconfirmed XDS:** actual prepared claim is refused by `Journal.broadcast` with one confirmation; stage remains prepared, exposure false and claim absent from the node. After ten further blocks, the same bytes undergo fresh admission and are sent.
- **Insufficient actual foreign margin:** abandonment waits real processed slots to the stored budget boundary; actual observations refuse admission while both contracts remain funded. No claim is prepared or sent in abandonment.
- **Absent foreign escrow:** actual finalized RPC absence of this fresh fixture state before account setup is rejected by the snapshot validator. This is the foreign observation predicate before coordinator registration, not a purported journal handoff on a funded swap.
- **Consumed foreign escrow:** actual finalized refunded state is rejected by the exact funded-state predicate. This is the foreign observation predicate, not an attempted secret-bearing claim during abandonment.

Offline tests isolate each policy condition, owner/destination binding, public-witness mismatch, context/commitment/fee evidence and the journal before-send/uncertain-retry properties. Fake observations in those tests are never labeled chain proof. Runtime results record which predicate versus actual handoff was exercised.

## Parent-owned Linux run

Use the already provisioned dedicated Python environment with `solders==0.29.0` and `cryptography`. No install or server command was executed by the author. Set `XDS_DAEMON` and `XDS_WALLET` to the absolute reviewed native binaries before Python imports the path adapter; neither Bitcoin nor its binary is needed. The installed helper/SBF package and expected genesis must correspond to the owned isolated ledger.

Offline, from this directory:

```sh
python -B -m unittest -v test_guards
```

Only after independent review and standalone RPC qualification, the parent may run within the validator's network namespace:

```sh
python -B runner.py --endpoint http://127.0.0.1:8899 \
  --expected-genesis "$EXPECTED_OWNED_GENESIS" \
  --payer-keypair "$OWNED_SYNTHETIC_PAYER_FILE" \
  --run-dir "$NEW_PRIVATE_RUN_DIRECTORY"
```

The endpoint parser accepts only canonical literal `http://127.0.0.1:PORT[/]`. The expected genesis is mandatory; an alias, proxy, URL credential, redirect or public endpoint cannot replace it. Program ID remains bytes `09` x32 and the on-chain immutable/legacy payload must match 32912 bytes / `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`. Existing mint state must match the same configured Bob mint/freeze authority.

The parent plans a bounded systemd service with `PrivateNetwork=yes`, `JoinsNamespaceOf`, `BindsTo` and `After` referring to the owned Solana validator unit, and `PartOf` its target. Retain `KillMode=control-group`, a stop timeout and an overall maximum near 1800 seconds; the validator lifetime must cover this fresh stage too. The runner itself bounds each receipt wait to 180 seconds and each actual-slot wait to 600 seconds. Actual duration depends on the combined CPU load; 768 slots are not a wall-clock promise. No port expansion, namespace fallback or external dial is needed: XDS binds all its ephemeral P2P/RPC/wallet/relay sockets to literal 127.0.0.1 inside the same namespace. A Unix proxy is unnecessary for this runner when it joins that namespace.

Measure the whole shared slice containing validator + runner + four daemons + two wallets: memory.current/peak/events, swap, CPU time and slot progression before and during both cases. The previous Solana-only sample does not prove these processes fit in the 952 MiB host or the proposed 680 MiB shared slice. An OOM, service deadline, stale observation or expired transaction stops qualification; do not lower confirmations, enlarge existing deadlines, clear intents or restart with substitute funds to manufacture PASS.

## Retention, interruption and rollback

Only use a new empty run directory and stage identity. Old signed intents, receipts and results must not be rebound to this new ELF.  Any interrupted run is retained, and the CLI refuses to reuse it. The frozen sender retries identical bytes and stops on expiry without a qualified receipt; it never re-signs or claims non-execution from an absent receipt. Paired process-death/blockhash-renewal recovery is a separate open task. A systemd timeout can leave the report RUNNING; that is incomplete evidence, never PASS. Coordinator DB, per-intent signed wire, private role material, node databases/logs, admission observations and public witness must be retained together for review/recovery.

Rollback of this isolated code is removal from execution of this new candidate directory; frozen dependencies, Core and remote state were not edited. Do not delete retained run directories or journals as part of rollback. Project-wide state/decision documents are parent-owned during this concurrent task; this candidate and its unexecuted runtime status do not independently close the V05 gates.

**Перевірено:** exact five staged dependency bindings and unchanged paired runtime/guard logic; see the staged audit receipt for the separate 20-guard outcome. Historical author logs and pre-review directories are intentionally omitted from this compact package; source-copy-baseline.json identifies the unchanged original manifest containing them.

**Не перевірено:** actual paired RPC execution, Linux process/resource fit, interruption recovery, public-chain finality, production key custody, Circle USDC or mainnet activation.
