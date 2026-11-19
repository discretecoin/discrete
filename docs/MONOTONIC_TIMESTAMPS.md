# Monotonic block timestamps

This change prepares a timestamp rule for a coordinated consensus upgrade.
Activation is disabled by default (`UINT32_MAX`). No mainnet or testnet activation
height is selected by this patch. `CurrencyBuilder::monotonicTimestampHeight(H)`
is the explicit configuration boundary; H must be at least 2.

## Consensus rule

At H, the required block major version becomes 9. Its header serializes an
unsigned varint immediately after the timestamp and before the previous hash.
The field is the difference between the public timestamp and the producer's
timing observation. Zero takes one byte. Decoders reject underflow, overflow
and nonminimal varints. Both values are bound by the signed proof and block ID.
Earlier block versions keep their original byte representation. For historical
blocks the single timestamp also supplies the observation.

| Height | Required public timestamp |
| --- | --- |
| Below H | Existing version and timestamp rules |
| H | Maximum of the observation and both preceding public timestamps |
| Above H | Maximum of the observation and the parent's public timestamp |

Each node derives this value from the candidate's own branch. Equality is
valid. Wallet history, block queries and date indexes use the public timestamp.
A reorganization can replace the visible tip with an earlier timestamp from
another valid branch. Existing cumulative-work selection, checkpoints and
operator recovery still apply.

The observation must satisfy the existing branch median and the receiving
node's future-time limit. LWMA uses the observations and previous accumulated
work. A forward-dated parent still contributes its own observation. Descendants
can report their own time without repeating that parent's observation as input
to the difficulty adjustment.

## Clock rollback and branch recovery

The miner chooses the greater of its local time and the required median. It
then derives the public timestamp from that observation and the branch. It
checks the observation against its local future limit before proof work and
before submitting the result. A waiting worker accepts a replacement template.
A backward clock step triggers a new template on the next idle refresh.

If the node already holds a future-dated parent, its child can be valid
immediately after a local clock correction even while repeating the parent's
public timestamp. A node receiving the parent for the first time still checks
the parent's own observation. A sustained clock error can also leave the median
ahead of the local future limit.

After activation, a block rejected only at the local future-time gate is marked
internally as retryable. Full-block, lite-block and synchronization-object paths
still close the connection, but do not add a host failure score for this rejection.
The flag is not a certificate of proof or transaction validity: later checks may
not have run. Immutable median or floor violations take precedence.

Before a work- or checkpoint-driven switch, every block to be connected is checked
against one captured local time. If the clock moves backward after that check,
the captured previously canonical suffix can be restored without applying the
local future-time cap again. All other validation still runs. This exception is
private to restoration and cannot admit a new peer-supplied future block.
The submitted winning tip is removed after a temporary replay failure so the
identical block can be retried; staged ancestors remain available. Recovery also
applies when a shorter winning branch returns below H.

Peer reconnect timers still use wall time. The time when a peer receives a
temporarily rejected block again depends on its clock and its connections.

### Upgrading a node with existing chain data

Historical LMDB metadata records occupy 100 bytes. A V9 record additionally
stores the eight-byte timestamp difference so difficulty queries can read a
single metadata range. Startup verifies the V9 suffix against the stored
headers, branch median, chronological rule and expected accumulated work.
This scan grows with the activated history. Ordinary reopen trusts earlier
transaction and proof validation. Wallet and history queries continue to use the public
timestamp. Open a pre-H database with the agreed activation height and the
node can resume at its existing tip. A legacy post-H block requires a resync
from a compatible prefix. Preserve the original data directory when resyncing.

Legacy block-file import checks compatibility before committing a batch. On
failure the importer preserves its original files and earlier committed batches.

## Reproducible checks

Configure with `BUILD_TESTS=ON`. On Linux, build the complete test suite or these
targets, then run the selected checks:

```sh
cmake --build build --target TimestampLwmaTests TimestampActivationTests \
  TimestampChainTests TimestampProtocolTests TimestampNetworkTests \
  TimestampTransactionsTests TimestampDualTimeTests PqWireTests
ctest --test-dir build --output-on-failure \
  -R '^(TimestampLwmaTests|TimestampActivationTests|TimestampChainTests|TimestampProtocolTests|TimestampTransactionsTests|TimestampDualTimeTests|PqWireTests)$'
sudo unshare -n -- sh -c 'ip link set lo up; exec "$1" --data-dir "$2"' sh \
  "$PWD/build/tests/timestamp_network_tests" "$PWD/fresh-network-fixture"
build/tests/timestamp_lwma_tests --output-dir fresh-lwma-traces
```

The chain, protocol, transaction and TCP clock-injection fixtures require Linux.
`TimestampActivationTests` and fixed-input `TimestampLwmaTests` are portable and
are included in Windows and macOS CI. Activation tests exercise paired old/new
versions on both sides of H, the activation boundary, two reorganizations across H, restart, exact
synthetic-chain replay, and a checkpoint-selected branch with less accumulated
work. A disabled-policy transcript can also be replayed against pristine upstream
with the fixture compiled using `TIMESTAMP_LEGACY_BASELINE`.

`TimestampHistoryTests` is an explicit offline tool, not a default CTest case.
It requires an immutable, consistent LMDB snapshot and a fresh destination:

```sh
build/tests/timestamp_history_tests --snapshot-dir /absolute/immutable-snapshot \
  --data-dir /absolute/fresh-upgrade-copy --check-upgrade
build/tests/timestamp_history_tests --snapshot-dir /absolute/immutable-snapshot \
  --data-dir /absolute/fresh-replay --stop-after 5000
build/tests/timestamp_history_tests --snapshot-dir /absolute/immutable-snapshot \
  --data-dir /absolute/fresh-replay --resume
```

Never point the snapshot reader at a live database. It replays original block and
transaction bytes through Core without a prevalidated-proof shortcut, compares
each canonical hash, accumulated work and emission, and checks a clean restart.
Historical replay uses disabled activation; synthetic fixtures exercise activation.

## Integration and activation

Review this implementation separately from selecting H. Before scheduling H,
integrate with the exact planned fork release, rerun the platform and consensus
gates, and coordinate the same height across validating nodes and producers.
Legacy nodes require the old block version. V9 nodes require the new one from
H onward. Upgrade validators, miners and clients decoding block bytes before
selecting H. Reverting software after H requires a compatible chain and
database. A later change to the rule requires its own coordinated decision.

For independent local builds, export a signed transcript with the first
executable and replay it against a fresh database with the second:

```sh
build-a/tests/timestamp_dual_time_tests --data-dir "$PWD/run-a" --export-script "$PWD/blocks.txt"
build-b/tests/timestamp_dual_time_tests --data-dir "$PWD/run-b" --replay-script "$PWD/blocks.txt"
```
