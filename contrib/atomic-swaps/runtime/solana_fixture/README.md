# Reproducible owned Agave fixture

This package supplies the public bridge used by
`tests/test_owner_solana_rpc_integration.py`. No private factory, frozen ledger,
SSH helper, old keypair or external Python driver is required. Importing the
package does not start a node. All assets and keys are synthetic test fixtures.

The fixture loads the exact committed 32,960-byte escrow ELF with SHA256
`561e0b7ad5e4be59a3056482ea94370064d201f45a378964d0fdb9f0ff76a901`.
Its fixed program and synthetic mint addresses are retained. A new test mint
authority, funding owner and claim owner are generated in each fresh private
run directory. Reconnecting a client retains its owner identities.

The program is loaded into **genesis** under the upgradeable loader with its
upgrade authority represented by the actual `Option::None` bytes; the synthetic
SPL mint is also genesis-loaded. It uses explicit Program/ProgramData account
dumps because Agave 4.2.2's `--upgradeable-program ... none` shortcut serializes
`Some(default-pubkey)` instead. The strict runtime verifier rejects that shortcut.
The runtime profile changes only the local genesis hash. This qualification
exercises the same ELF and real transactions on a fresh ledger; it is distinct
from normal initial deployment and later authority removal. Those operations
have a separate opt-in test in `tests/test_solana_rpc_integration.py`.

## Dependencies and isolation

- Linux with network namespaces and `iproute2` for the validator. The client
  also runs on Windows. Python 3.11 or 3.12 with `runtime/requirements.txt` installed
  (`solders==0.29.0`, `cryptography==50.0.1`).
- An operator-installed `solana-test-validator` reporting exactly
  `solana-test-validator 4.2.2 (src:c9c6f328; feat:21b0d33a, client:Agave)`.
  The Linux x86_64 executable is pinned to SHA256
  `d723f3a99fa3f5b3df6841fc04ac0d8b5302837689d43a07222aa2125b6713d1`.
  Supply that expected hash explicitly. The supervisor checks hash and version
  before execution and records both. Other builds require a reviewed fixture
  pin update. Obtain and review the executable through
  the [Agave release source](https://github.com/anza-xyz/agave/releases/tag/v4.2.2).
  Merely hashing an arbitrary downloaded executable does not establish trust.
  The fixture neither downloads binaries nor changes the machine's installation.
- For the complete XDS/Solana pair, the native binaries and fixture settings in
  `tests/test_xds_rpc_integration.py` are also required: `SWAP_CORE_DIR`,
  `SWAP_BUILD_DIR`, `XDS_TEST_DATA`, and OpenSSL runtime dependencies.

The supervisor and `serve` command require a network namespace containing only
an enabled `lo` interface. This is mandatory because Agave 4.2.2's faucet
binds to `0.0.0.0` even when validator `--bind-address` is loopback. The namespace
has no external interface or route. No public RPC URL, cloning, public mint,
warp, ledger reset or production activation option is exposed.
The relevant upstream behavior is in the pinned
[CLI](https://github.com/anza-xyz/agave/blob/v4.2.2/validator/src/cli.rs) and
[test-validator entrypoint](https://github.com/anza-xyz/agave/blob/v4.2.2/validator/src/bin/solana-test-validator.rs).

## Same-machine run

From `contrib/atomic-swaps/runtime`, create/activate a Python environment and
install the pinned requirements. Set `PYTHONPATH` to that directory. Enter a
fresh namespace, for example `unshare --user --map-root-user --net bash`, then
enable its loopback with `ip link set lo up`. Some hosts disable unprivileged
namespaces; the operator can instead provide a private systemd network
namespace. The fixture does not change that host policy.

Run the supervisor in that namespace, using a **nonexistent** private run path:

```sh
python -B -m solana_fixture run \
  --run-dir "$RUN" \
  --validator "$AGAVE_VALIDATOR" \
  --validator-sha256 "$AGAVE_VALIDATOR_SHA256" \
  --max-seconds 1800
```

It remains in the foreground and prints a public readiness record only after
finalized account verification confirms the expected genesis, program, mint,
ELF bytes and absent upgrade authority. Its own files include generated test
keys, private validator logs and retained ledger; do not commit the run path.
POSIX permissions are owner-only. On Windows keep a client run directory under
an account-private ACL; Python mode bits do not enforce Windows ACL isolation.

In a second process in the **same namespace**, after readiness:

```sh
export OWNER_SOLANA_RUN_DIR="$RUN"
export OWNER_SOLANA_RPC_INTEGRATION=1
python -B -m solana_fixture info --run-dir "$RUN"
python -B -m unittest discover -s tests -p test_owner_solana_rpc_integration.py -v
```

Configure native fixture paths before that command. The two cases exercise
unfunded agreement through both funding transactions, XDS public-witness claim,
Solana claim and ordinary SPL spending; and foreign-only funding followed by
backup restoration before maturity, natural deadline, refund and ordinary SPL
spending. No ledger responses are simulated in this integration test.

The additional combined-mode case uses the same fixture with durable native
funding preparation and two independent authenticated AnchorStore instances:

```sh
python -B -m unittest discover -s tests -p test_owner_hardening_solana_rpc_integration.py -v
```

It covers both owner stores reopening after settlement and ordinary spending
on both chains. The anchor protocol runs in process with separate directories;
this case does not establish remote HTTPS failure isolation.

To exercise the Solana funding and settlement adapters independently of native
nodes, supply a new private evidence directory and run the two standalone cases:

```sh
export SOLANA_FIXTURE_RPC_INTEGRATION=1
export SOLANA_FIXTURE_EVIDENCE="$NEW_PRIVATE_EVIDENCE"
python -B -m unittest discover -s tests -p test_solana_fixture_rpc_integration.py -v
```

These cases perform atomic funding, claim/refund, reconnect, and ordinary SPL
spending. Their private evidence directory retains signed artifacts; it must
not be committed or treated as a sanitized public report.

Send Ctrl-C/SIGTERM to the supervisor when finished. It terminates and waits for
only the validator process it created. A lifetime limit also stops it. `close()`
on a bridge merely closes its transport. All ledger and identity files remain.
To restart an initialized, stopped ledger, use the same command with `--resume`;
the binary hash, local genesis and immutable program are checked again. A fresh
run refuses existing paths; there is no automatic destructive reset.

## Separate owned node and native-test machine

The public stdio server runs inside the same private namespace as the validator:

```sh
python -B -m solana_fixture serve --run-dir "$RUN"
```

Use an authenticated operator-controlled transport to execute this exact public
entrypoint remotely, for example SSH with a pinned host key, `BatchMode=yes`
and `StrictHostKeyChecking=yes`, entering the already-owned private namespace.
Install this repository's runtime package on both machines. The transport does
not need a private Python helper: it connects the public server's stdin/stdout.
Keep banners and other stdout output off this channel.

On the client, write a private JSON file containing the explicit transport
argument array (executable and arguments, not a shell string), then:

```sh
python -B -m solana_fixture client \
  --run-dir "$CLIENT_RUN" --command-json "$TRANSPORT_ARGV_JSON"
export OWNER_SOLANA_RUN_DIR="$CLIENT_RUN"
export OWNER_SOLANA_RPC_INTEGRATION=1
python -B -m unittest discover -s tests -p test_owner_solana_rpc_integration.py -v
```

This configuration is trusted operator input, equivalent to selecting a local
executable; never derive it from a swap offer, mailbox, downloaded message or
untrusted directory. No password, private key bytes or bearer credential belongs
in the argv file. Configure SSH authentication through the operator's normal
private key/agent. The package executes argv without a local shell and never
imports a configured Python file. `client` pins the server's public readiness
record and creates independent owner/claim keys **on the client**. Child
processes reopen that same private directory and verify the same server record.
Only public owner addresses are sent during synthetic provisioning; signing
keys remain local. Transport errors do not echo arguments, keys or RPC bodies.

## Importable bridge contract

`solana_fixture.create_bridge(run_dir=None)` uses the explicit argument or
`OWNER_SOLANA_RUN_DIR`. It returns:

- `owner_key` and `claim_key`: different retained `solders.Keypair` values.
  The former controls funding/refund custody; the latter controls claim custody.
- `rpc(method, params)`: the actual owned Solana JSON-RPC result. The method
  allowlist is defined in `bridge.py`; simulation and arbitrary RPC methods are
  rejected. A local send checks the pinned genesis before transmission.
- `setup(hashlock_hex, delay_slots)`: a 32-byte public hashlock in canonical
  lowercase hex, and integer delay from 200 through 2500 slots. It submits five
  ordinary System/SPL instructions in one transaction: create/initialize a
  fresh source account, mint synthetic tokens into it, and fund two distinct
  System fee payers. It creates **no escrow state, vault, refund account or ATA**.
  Each explicit setup call provisions a new source; it is a test provisioning
  operation, not owner funding recovery or an idempotent deposit API.
- Its result is `{terms, setup_txid, source_balance, owner_balance_lamports,
  claim_balance_lamports}`. `terms` is the exact `SolanaFundingAdapter` schema:
  `{manifest, owner, source, claim_owner, claim_payer, refund_owner, refund_payer,
  amount, hashlock, deadline_slot, min_context_slot, max_finality_lag_slots,
  min_funding_window_slots, max_funding_fee_lamports, max_rent_lamports,
  owner_reserve_lamports}`. The Owner engine independently verifies the setup
  accounts and creates/persists/signs its own atomic funding transaction.
- `ready`, `manifest`: pinned public fixture identity and derived local profile.
- `close()`: close this transport; never destroy keys, ledger or another process.

`OWNER_SOLANA_BRIDGE_FACTORY` remains an explicit legacy override only when
`OWNER_SOLANA_RUN_DIR` is absent. It is unnecessary for the public fixture.

## Offline checks and evidence limits

```sh
python -B -m unittest discover -s tests -p test_solana_fixture.py -v
```

These checks cover artifact/profile rejection, private identity persistence,
framed subprocess transport, startup/isolation guards, and actual System/SPL/
escrow execution in LiteSVM. VM RPC contexts are controlled test fixtures, not
network finality. The live pair test above is the separate Agave/native gate.
A single private validator does not establish public Solana liveness, realistic
validator disagreement, Circle freeze behavior, real USDC settlement or mainnet
readiness. Operator timing assumptions remain explicit in the pair's offer.
