# Owner lifecycle from unfunded contracts

The owner coordinator advances an agreed, initially unfunded XDS/Bitcoin or
XDS/Solana swap using separately controlled wallets. It funds the foreign leg
first, waits for its qualified public receipt, funds XDS, then admits the first
native claim only after both contracts meet their confirmation and time budgets.
The XDS owner discovers the public witness through the native daemon and claims
the foreign escrow. Each owner can recover its own matured deposit even when the
counterparty never deposits.

This revision adds Python wallet orchestration, signed public transport,
durable native funding preparation and independently anchored recovery. The new
wallet RPC/storage and owner modes do not change the existing native consensus
patch, activation defaults, Solana ELF, or the earlier settlement CLI. Public activation remains
disabled. The maintainer activation decision is separate from this implementation.

## Entry point and ownership

Install the pinned `requirements.txt` into a private environment and run
`python -m swap_runtime.owner_cli --help`. This separate CLI has `init`, `step`,
bounded `run`, `status`, `backup`, `restore` and `cancel` operations. `init` stores
the agreement and private credentials; it does not fund. `step` advances one
state transition. `run` performs the specified number of steps and stops on an
error or interruption. Reopen the retained owner state to reconcile an uncertain
operation; never initialize a replacement trade to recover a lost acknowledgment.

New CLI initialization pins owner configuration version two and requires the
durable preparation RPC below when funding XDS. Reopening preserves that pinned
choice. Existing version-one owners remain readable with their original behavior;
there is no implicit migration of an active trade. Preserve the old client and
pre-upgrade backups, and do not open version-two state with an older client.

Each participant has its own:

- Native wallet and private role seed (`xds_rho`, 32-byte lowercase hex).
- Foreign settlement key (`foreign_key`, 32-byte Bitcoin scalar or 64-byte Solana
  keypair, lowercase hex). It must match the identity in the agreement.
- Encrypted owner database, independent 32-byte encryption key and backup directory.
- RPC credentials supplied through private files. All RPC URLs are explicit
  loopback endpoints; an owned remote node requires an authenticated tunnel.

Only the foreign owner holds `secret` in its initial credentials. Its 32-byte
preimage must hash to the agreed hashlock. The XDS owner has no preimage input
interface. Solana's foreign owner also retains the state/vault/refund auxiliary
keypairs, generated once or supplied in `solana_accounts`. These are encrypted
before planning/signing the funding transaction. The claimant pays its own Solana
settlement fee; it never receives the depositor's private key.

Use a dedicated funding wallet for an active owner operation. Bitcoin input locks
are durable wallet locks; they do not prohibit manual spending by another operator.
Native preparation does not reserve inputs in the wallet. The coordinator checks
their exact authority and current spentness before sending; external interference
stops the deposit. This version does not allocate a shared wallet's funds across
multiple simultaneous trades.

## Agreement and transport

`owner_protocol.validate_offer` defines the strict version-one agreement:
`swap_id`, `foreign_chain`, unfunded `xds`/`foreign` terms, `policy` and `schedule`.
Unknown fields, duplicate JSON fields, nonfinite values, mismatched hashlocks,
incorrect fee arithmetic, insufficient confirmation budgets and role-key aliasing
are rejected. Funded outpoints are learned by the coordinator; they are not
manually pasted into the offer. Price discovery and offer negotiation are outside
this client: each participant must review the amounts, destinations and deadlines
before initializing that exact agreement.

The public mailbox is an existing directory shared through an operator-selected
transport. Each acceptance, funding notice and cancellation is signed by the
agreed foreign role key, domain-separated, and bound to the offer hash, role and
message kind. Messages are published without overwriting an existing message.
The filesystem must support hard links (for example, NTFS or ext4). Incomplete
publication files remain as crash evidence and cause refusal, not assumed absence.
The mailbox can delay or suppress messages; it cannot establish ledger execution.

Funding notices are published only after an adapter has retrieved the exact
signed wire from the public chain or mempool. Receiving owners independently
validate the transaction, economic terms and sufficient current confirmations.
No mailbox message is accepted as proof that a secret has become public.

For Solana, `funding-unknown` or `refund-unknown` retains the exact signed attempt
after an uncertain send or a changing observation. The next step checks that
attempt's receipt before retrying. A send error does not establish blockhash
expiry or authorize a replacement; renewal still requires the existing explicit
expiry and state checks. Keep the owner state and keys while resolving uncertainty.

## Funding and timing

Native funding pays one atom (0.01 XDS). The escrow contains the net payout plus
one atom for the eventual claim/refund. Thus a completed funding-and-exit sequence
pays two ordinary fees; the base fee is still 0.01 XDS. There is no fee doubling,
RBF or implicit change of a signed destination.

Bitcoin funding pins at most eight native P2WPKH inputs, an exact P2WSH output,
change destination and funding fee before obtaining wallet signatures. Its exit
fee is a separate agreed amount. Reopen uses the retained selection and signed
bytes. An insufficient fixed Bitcoin fee can delay inclusion; no future fee-market
guarantee is made by a current node's admission response.

Solana funding creates the escrow state, vault, independent refund token account
and claimant ATA, and deposits the principal in one atomic transaction. Only
legacy SPL Token is supported. The manifest pins the validating program and mint;
rent, fee and retained SOL budgets are bounded. Before revealing the native secret,
the coordinator also reads the separate claimant's fee account and checks its
settlement attempt reserve.

Scheduling uses each chain's own heights/slots. The explicit offer assumptions
include an XDS block-time upper bound, foreign unit-time lower bound and safety
margin. Admission requires both chain-native reserves and a strictly longer
foreign remaining window under those declared assumptions. These are assumptions
about future chain progress, not protocol-enforced bounds. Eleven confirmations
do not make an arbitrary-depth reorganization impossible. Operators must qualify
the chosen timing and confirmation policy for the intended networks; average block
times alone do not establish these bounds.

## Crash, timeout and restoration

The owner log is append-only AES-GCM state with an authenticated chain/head and a
lifetime OS writer lock. Signed funding/settlement artifacts are persisted and a
paired, consistent encrypted backup is written before transmission. The companion
settlement snapshot includes its WAL contents. A backup failure prevents sending.
Keep backup storage outside the live owner directory and keep its encryption key
separately; different directory names alone do not provide independent hardware.

Known pending/confirmed transactions are reconciled before any resend. Unknown
outcomes never select another deposit. Version-two native funding persists a
random operation ID and exact request commitment before wallet RPC. On restart it
first looks up that same operation. A prepared result returns the identical signed
bytes and transaction ID. A retained unsigned draft can finish using only its
original inputs, outputs and terms. It never reselects coins. Changed terms,
interfered inputs, wrong wallet/genesis, invalid signatures or expired deadlines
refuse progress. The owner independently checks the returned transaction and its
current spendability before transmission.

Before beginning a new operation, a read-only preflight compares the native
wallet's last scanned block index with a stable daemon height. A known lag or
changing tip returns `wait-native-wallet-scan` before any plan, operation ID or
prepare-started marker is retained. It can wait and recheck without preparing a
transaction. Native preparation still repeats its own source/scan checks; a later
race or unknown RPC result is not converted into permission for another deposit.
Already-started operations use their exact lookup/reconciliation path even if the
wallet's current scan lags.

The three additive native wallet methods are `swap_funding_capabilities`,
`swap_prepare_funding_once` and `swap_get_funding_preparation`. The last two use a
32-byte lowercase-hex `operation_id`; preparation also takes the original funding
terms. The wallet publishes and flushes its authenticated unsigned Draft before
signing and its immutable Prepared record before responding. A crash before
Prepared publication may require signing the same unsigned draft again; no
previous signed response exists at that stage. The separate encrypted sidecar is
bound to wallet identity and genesis, holds an exclusive writer lock, enforces
private storage permissions, and has explicit operation/wire/storage limits. Do
not delete it, replace it with an older copy or reset operation IDs to bypass a
refusal. Back it up alongside the dedicated native wallet.

If the wallet cannot locate an operation after an uncertain preparation call,
the client stops. This includes a crash after the client saved its intention but
before the wallet received it. Absence does not authorize a replacement deposit.
An old version-one owner retains `native-prepare-response-uncertain` behavior.
The foreign owner can recover its deposited leg at maturity in either case.

For Solana, an RPC acknowledgment does not prove execution or blockhash validity.
The coordinator checks finalized validity before transmitting an unknown retained
settlement. A renewal changes only blockhash/signatures, retains all old attempts
and requires authenticated acquisition metadata, later rooted expiry, and the
same still-unconsumed contract (or the same absent accounts for funding). Missing
transaction history is never sufficient proof. Finalized failed transactions can
renew only through this same qualification; an observed conflict cannot.

`restore` creates a new owner directory. It authenticates the container and binds
its settlement companion to the exact owner agreement. Both journals remain
permanently in protective recovery mode: no new deposits, escrow identities,
economic terms or first native secret disclosure. Existing signed settlement can
be reconciled; an authenticated scanner-acquired public witness can authorize the
protective foreign claim; an owned, currently confirmed and matured deposit can
authorize its refund even if the old backup predates that refund intent.

The owner backup does not replace the native wallet's seed/file backup or the
foreign funding wallet's backup. Preserve those separately. A snapshot from before
an unknown deposit's identity was recorded cannot infer that identity from absent
history. Use the mandatory pre-send checkpoints for recovery. Replacing all owner
storage with an old valid copy outside `restore` is not detected by an ordinary
local authenticated log. The optional anchored owner mode addresses that threat
under the independent-service assumptions below.

## Independent freshness and protective recovery

Provision one external checkpoint stream per participant using [ANCHOR.md](ANCHOR.md).
Pass `--anchor-profile /independent/private/client.json` on initialization and
every subsequent normal command. Keep that pinned profile and service history
outside the owner's backup/restore domain. The service receives signed opaque
commitments, never wallet keys, preimages or wallet database contents. A different
directory on the same rolled-back disk is not an independent service.

This mode uses complete encrypted Owner+Session snapshots as authoritative state.
Every restart materializes only the snapshot matching both the fresh external
head and the locally authenticated accepted head. The local accepted head also
detects rollback of the provider alone. A durable signed pending publication is
reconciled exactly after a lost response; a different or missing current state
stops normal work. The client checkpoints funding plans before wallet reservation
or signing, and checkpoints signed transmissions and possible first disclosure
before network send. Chain admission is checked again after checkpoint latency.
Removing the profile does not downgrade an existing anchored owner to local mode.

Normal restart preserves normal operation. Explicit historical `restore` with the
profile appends a **new protective** checkpoint and prevents old normal copies
from passing their next freshness check. Recovery remains sticky in both journals.
It cannot make a checkpoint update and blockchain transmission atomic: an already
authorized in-flight transmission can cross a concurrent restore boundary. Keep
one active owner process; restoring is not a cancellation of a submitted transaction.

Anchor downtime stops normal work. For an emergency, `restore --offline-protective`
with a retained encrypted backup and owner key creates a new permanently protective
local owner without contacting the service. It permits only the existing qualified
recovery paths: no funding or first secret disclosure. It does **not** advance the
external head or fence another running copy. Preserve independent backups and
wallet credentials before funding; the service cannot reconstruct missing data.
Joint rollback of owner and provider, a malicious trusted provider and compromised
signing hosts remain outside this mechanism's guarantee. Storage bounds refuse
progress instead of pruning live evidence automatically.

## Review and qualification

The original settlement library remains independently testable. New tests cover
funding adapters, signed transport, owner storage, first-exposure gates, atomic
session publication, process restart and protective recovery. The offline
qualification command records source hashes before and after execution, retains
detailed evidence locally, and prints aggregate counters only. Opt-in owned-node
tests exercise native/Bitcoin and native/Solana pairs separately; VM results are
not described as network-finality tests.

Status reports distinguish retained local state, exact observed transactions and
current confirmation/finality. A confirmed local claim proves that owner's receipt;
it is not a blanket assertion that both chains are irrevocable or that public
USDC/mainnet deployment has been qualified.

## Reproduce the owner tests

From the repository root, the offline command is:

```sh
python -B contrib/atomic-swaps/runtime/qualify.py --output /private/new-offline-results
```

The output directory must not already exist. This command sets the committed ELF
fixture explicitly, rejects skipped tests for its selected suite, and checks that
its source/fixture inventory did not change during execution. It does not run the
owned-node suites. A test pass with a changed inventory is retained as development
evidence and is not a qualified immutable-source result.

For owned XDS/Bitcoin integration, set `OWNER_RPC_INTEGRATION=1`, `BITCOIND` to the
Bitcoin Core binary, `SWAP_CORE_DIR` to this checkout, `SWAP_BUILD_DIR` to the
matching native build, and distinct `XDS_TEST_DATA`/`BITCOIN_TEST_DATA` directories.
From `contrib/atomic-swaps/runtime`, run:

```sh
python -B -m unittest discover -s tests -p test_owner_rpc_integration.py -v
python -B -m unittest discover -s tests -p test_owner_hardening_rpc_integration.py -v
```

The native/Core fixtures start isolated synthetic nodes and stop those nodes on
exit. Do not share their data directories or wallets with another fixture run.

For owned XDS/Solana integration, provision the public fixture described in
[solana_fixture/README.md](solana_fixture/README.md). Set
`OWNER_SOLANA_RPC_INTEGRATION=1`, the same `SWAP_CORE_DIR`/`SWAP_BUILD_DIR`, a distinct
`XDS_TEST_DATA`, and `OWNER_SOLANA_RUN_DIR` to that fixture's retained client
directory. Unset the legacy `OWNER_SOLANA_BRIDGE_FACTORY`. Run:

```sh
python -B -m unittest discover -s tests -p test_owner_solana_rpc_integration.py -v
python -B -m unittest discover -s tests -p test_owner_hardening_solana_rpc_integration.py -v
```

The public fixture pins Agave and the committed ELF, creates an immutable program
and synthetic legacy SPL mint in a fresh isolated genesis, and provides the full
ordinary-account provisioning and framed RPC transport implementation. It never
uses a real USDC mint or public validator. It requires Linux network-namespace
isolation because the validator faucet's bind behavior differs from ordinary RPC.
Fresh initialization and explicit resume are distinct; resume verifies the same
ledger and participant identities. This proves genesis-loaded program execution,
not an ordinary program deployment or removal of upgrade authority.

The separate hardening suites enable version-two native preparation and complete
anchored snapshots. Their actual-ledger fixtures use separate in-process signed
checkpoint services; the offline CLI suite independently exercises pinned HTTPS
through fresh client processes. Do not infer independent-host fault isolation from
the in-process checkpoint service used in a financial integration test.

An existing operator-specific fixture remains an explicit legacy option. Its
module exports `create_bridge()` with the following contract:

- `rpc(method, params)` calls the same live, validating synthetic ledger. It must
  include the ordinary Solana methods used by `SolanaAdapter` and
  `SolanaFundingAdapter`, including `getMinimumBalanceForRentExemption`. It must not
  fabricate finality, signatures, account data or transaction results.
- `owner_key` and `claim_key` are distinct local `solders.Keypair` objects, retained
  across child reconnects. Reconnecting must never reset the ledger or regenerate
  the participant identities.
- `setup(hashlock_hex, delay_slots)` returns `{'terms': ..., 'source_balance': ...}`.
  Terms are the complete `SolanaFundingAdapter` field set. Setup provisions only
  an ordinary token source and the two System fee payers, on the declared immutable
  program/mint/genesis. `source_balance` is the initial integer token amount, at
  least the agreed principal. It must not create/fund escrow accounts: the actual
  owner engine performs that atomic transaction.
- `close()` closes only the connection. It must not stop/reset the ledger needed
  by another owner or the recovery subprocess. The module writes no stdout because
  subprocess results are parsed as bounded JSON.

Qualify the bridge and infrastructure separately: retain its source hashes before
and after the run, native binary hashes, Agave version/genesis and immutable
program/mint/ELF profile. Repository `qualify.py` cannot hash or certify an external
module. Keep credentials, raw transactions, owner databases, backup contents and
detailed infrastructure logs in private evidence; public reports use aggregate
results and nonsecret source/fixture hashes.
