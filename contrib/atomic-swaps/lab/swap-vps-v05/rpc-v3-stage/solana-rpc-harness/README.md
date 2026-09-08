# Solana RPC escrow qualification harness — SBPFv3 candidate

This new package copies the reviewed standalone harness and changes only its exact SBF SHA256/size constants. Candidate binding and staged offline results are recorded in the parent stage and audit receipts; no previous RPC result qualifies this new binary. Root owns installation, review and the actual RPC run. The original harness and frozen V04 sources/Core remain unchanged.

This runner exercises the new Rust/SBPFv3 candidate with the V04 instruction and state interface through real Agave JSON RPC and SPL Token instructions. It is limited to the immutable local program ID (`09` repeated 32 bytes), the fixed public synthetic mint seed (`04` repeated 32 bytes), and an explicit genesis hash. This mint is not Circle USDC. No airdrop, remote clone, public endpoint, CLI subprocess or slot-warp operation exists in the driver.

## Profile and inputs

- Agave must report exactly `4.2.2`; solders must be `0.29.0`.
- Endpoint must be canonical `http://127.0.0.1:PORT`, optionally with `/`. Hostnames, IPv6, credentials, other paths and redirects fail. `http.client` does not consult HTTP proxy environment variables. A loopback URL alone does not prove what a locally configured relay serves: the explicit genesis and frozen program gates bind the intended ledger.
- Program payload: 32,912 bytes, SHA256 `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`. The driver reads the actual executable account. It supports legacy BPF loaders and immutable upgradeable-loader Program/ProgramData accounts; an upgrade authority is rejected. Any bytes after the exact payload must be zero padding. Other loaders/layouts fail rather than silently relaxing the gate.
- The payer file is read silently and is never copied into the evidence. On Linux it must be owned by the invoking user with no group/other permissions. The run directory must likewise be owned and mode 0700. It contains synthetic fixture keys and signed intents, written mode 0600; do not publish it wholesale.
- If the fixed mint already exists, it must be initialized SPL Token, six decimals, with the configured payer as both mint and freeze authority. Otherwise the driver creates it. It will not silently adopt another mint authority.
- Required starting SOL is calculated from rent for two states/eight token accounts, optional mint creation, a 0.05 synthetic SOL relayer allocation and 0.001 SOL fee reserve. This is a fixture budget, not a swap base-fee change.

The new `.so` must already be installed at the fixed address in the expected genesis with the exact immutable loader representation required below. A genesis flag on an initialized ledger is not a deployment. The parent verifies actual loader/feature state and owns any program operation; this package never disables a feature or relaxes authority checks. Use a fresh stage/run identity; old signed intents and results must not be relabeled with the new ELF.

## Commands for parent qualification

Use the already selected Python environment with `solders==0.29.0`. Offline guard tests:

```sh
python -m unittest -v test_guards
```

Run against the owned escrow ledger, replacing the placeholders with verified values:

```sh
python driver.py \
  --endpoint http://127.0.0.1:8899 \
  --expected-genesis '<verified-local-genesis-hash>' \
  --payer-keypair '<owned-absolute-key-file>' \
  --run-dir '<new-owned-absolute-run-directory>' \
  --commitment finalized
```

The default refund delay is 160 actual committed slots. Each transaction receipt wait is bounded at 90 seconds; slot waits at 240 seconds. `--wait-seconds`, `--slot-wait-seconds` and `--refund-delay-slots` have explicit bounds. A slow run can fail the early-refund timing assertion; the driver does not move an already stored deadline to manufacture a pass. The six live cases are listed in `test-manifest.json`. Setup transactions are additional, separately journaled operations, not extra advertised live cases.

The duplicate check re-sends the exact claimed transaction and requires an accepted-for-relay response for a new replay attempt. An old receipt plus an uncertain replay delivery cannot qualify this case and stops the run. After acknowledged replay ingress it waits at least two new slots at the chosen commitment with no intervening harness transaction, then verifies the original receipt, unchanged token/state data and no extra relayer debit. This establishes an observed no-extra-debit window, not an unbounded temporal proof.

## Delivery and recovery rules

The runner signs each labeled intent once. It persists the complete wire, signature, blockhash validity height, semantic instruction list and quoted fee using file fsync, atomic replacement and directory fsync. Before every send it durably writes an attempt-started marker. Transport uncertainty only permits identical-byte retries; it never requests another blockhash to replace that intent. A `sendTransaction` response is not settlement evidence. [Solana submission semantics](https://solana.com/docs/rpc/http/sendtransaction)

A transaction passes only when `getSignatureStatuses` has the selected confirmed/finalized status and `getTransaction` returns the exact persisted wire, expected success/error and quoted fee. Every receipt checks the payer's pre/post lamports against that fee plus intended System Program outflow. State/token assertions use a coherent `getMultipleAccounts` snapshot with a minimum context slot at least as new as the relevant receipt. The rejected cases intentionally use `skipPreflight=true` to obtain on-chain failure receipts and fee accounting; a simulation/preflight rejection is not counted as a chain rejection. [Receipt API](https://solana.com/docs/rpc/http/gettransaction), [signature status API](https://solana.com/docs/rpc/http/getsignaturestatuses)

Existing run directories are never automatically replayed from case one. After interruption, review the saved label and reconcile only that immutable intent:

```sh
python driver.py \
  --endpoint http://127.0.0.1:8899 \
  --expected-genesis '<same-verified-local-genesis-hash>' \
  --payer-keypair '<same-owned-absolute-key-file>' \
  --run-dir '<existing-run-directory>' \
  --commitment finalized \
  --recover-intent 15-claim
```

This recovery command does not generate setup accounts, advance the test plan or re-sign. It requires the original run's exact commitment as well as the same genesis and payer; a finalized run cannot silently recover using the confirmed default. Expiry without a qualified receipt stops with the original identity preserved; it is not proof of non-execution and does not authorize a replacement. After manual reconciliation, a complete new test run needs a new directory. The later successful refund is a distinct test operation after the earlier refund has a definitive failed chain receipt, not a replacement for uncertain delivery.

`run.json` records case PASS entries only after their full assertions. Its final status changes to PASS only after all six cases and a final profile check. A remaining `running` status denotes incomplete evidence even if some case entries passed. Top-level failure output is sanitized; arbitrary exception/traceback content and payer bytes are not printed.

## Provenance and limits

The instruction/account layout is derived from frozen V04. The following table names the historical C/SBPFv0 baseline, not the new deployed profile:

| File | SHA256 |
|---|---|
| `test_solana_vm.py` | `48187e48a95a1a94f92ba99e4ea6e3755289e0592c8d94d874c4d4d861892c54` |
| `solana_profile.h` | `cc86c7703a1e7edf9b2ec7c1a8bbcaa60788f5f375b9292cef8207eb56666551` |
| `solana_escrow.c` | `c64e6f25aa506565d553c5959c5fc3a7c27895c7b22ecffc643091d8c9bf2123` |
| `solana_escrow.so` | `91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89` |

Source root: `C:/ChatGPT-Knowledge-Migration/knowledge-base/projects/discrete-core/evidence/swap-localnet-v04`. No VM account mutation, warp or account injection was carried into the live RPC driver. The Python journal is test evidence/retry control, not a replacement for the separately reviewed production swap journal or a proof of production key custody.

**Перевірено:** exact staged artifact/profile bindings and preserved reviewed driver logic; see the separate staged offline receipt for executed guard outcomes. **Не перевірено:** the six actual RPC outcomes against this new ELF, loader finalization on the owned ledger, process-kill recovery, combined resource headroom or XDS/Solana pairing. No production/mainnet or Circle USDC claim follows from this package.
