# Monotonic block timestamps

This change prepares a timestamp rule for a coordinated consensus upgrade.
Activation is disabled by default (`UINT32_MAX`). No mainnet or testnet activation
height is selected by this patch. `CurrencyBuilder::monotonicTimestampHeight(H)`
is the explicit configuration boundary; H must be at least 2.

## Consensus rule

For the actual stored ancestry of each branch:

| Block height | Additional timestamp lower bound |
| --- | --- |
| Below H | None |
| H | Maximum of the parent's and grandparent's timestamps |
| Above H | Parent's timestamp |

Equality is valid. A burst of blocks in one second therefore does not accumulate
an artificial one-second offset per block. The existing median of 11 blocks and
local future-time limit remain in force. The 60-block LWMA calculation, rounding,
header layout, serialization, block hash and transaction formats are unchanged.

This is a branch invariant. A reorganization can replace the visible tip with a
lower timestamp from another valid branch. It does not change cumulative-work
selection, checkpoints, finality admission or the guarded manual recovery command.
In particular, it does not establish an unconditional common-ancestor reorg-depth
bound: existing alternative-block staging can outlive the admission window.

The bundled miner already uses the parent as a template lower bound. At H, its
template also accounts for the grandparent when the two legacy timestamps are
inverted. Difficulty can respond differently to that changed input history even
though the LWMA implementation is identical. Model results are scenario evidence,
not universal bounds on difficulty or block production.

## Clock rollback and branch recovery

A nondecreasing timestamp cannot also allow the next block to move back toward
a slow local clock. A node that is too far behind a valid parent's timestamp must
wait for its local future-time window or correct its clock. Keeping the median
does not remove this consequence of adding the parent floor.

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

There is no pending-block queue or new scheduling guarantee. Existing miner
refresh and peer reconnect timers use wall time and can be delayed by rollback.
Do not infer bounded recovery latency from one successful reconnect rehearsal.

## Returned transaction fee repair

A disconnected PQ transaction can be returned to the pool while its old nullifier
is still marked spent. That leaves an unresolved zero cached fee. Before selecting
transactions for a template, the pool now validates such retained transfers and
resolves their fee before fee ordering and paid-transaction size limits. A repeated
negative result is reused only at the same canonical tip; a new tip or same-height
reorg permits another attempt. Unknown, partially funded and conflicting inputs
remain excluded. Free-registration zero-fee behavior is unchanged.

This repairs the first automatic miner template after a reorg, including after
restart. It is independent of timestamp activation, changes no consensus fee and
introduces no persistent format. It adds a pool scan per template and input
validation for unresolved retained transfers when the canonical tip changes.

## Reproducible checks

Configure with `BUILD_TESTS=ON`. On Linux, build the complete test suite or these
targets, then run the selected checks:

```sh
cmake --build build --target TimestampLwmaTests TimestampActivationTests \
  TimestampChainTests TimestampProtocolTests TimestampNetworkTests \
  TimestampTransactionsTests UnitTests
ctest --test-dir build --output-on-failure \
  -R '^(TimestampLwmaTests|TimestampActivationTests|TimestampChainTests|TimestampProtocolTests|TimestampTransactionsTests)$'
build/tests/unit_tests --gtest_filter='ReturnedPqFee.*'
sudo unshare -n -- sh -c 'ip link set lo up; exec "$1" --data-dir "$2"' sh \
  "$PWD/build/tests/timestamp_network_tests" "$PWD/fresh-network-fixture"
build/tests/timestamp_lwma_tests --output-dir fresh-lwma-traces
```

The chain, protocol, transaction and TCP clock-injection fixtures require Linux.
`TimestampActivationTests` and fixed-input `TimestampLwmaTests` are portable and
are included in Windows and macOS CI. Activation tests exercise paired old/new
policy, the activation boundary, two reorganizations across H, restart, exact
synthetic-chain replay, and a checkpoint-selected branch with less accumulated
work. A disabled-policy transcript can also be replayed against pristine upstream
with the fixture compiled using `TIMESTAMP_LEGACY_BASELINE`.

`TimestampHistoryTests` is an explicit offline tool, not a default CTest case.
It requires an immutable, consistent LMDB snapshot and a fresh destination:

```sh
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
Old nodes can accept a backward-time branch that upgraded nodes reject at H;
mixed versions are not a safe permanent deployment strategy.

Before H, the consensus floor is inactive. After H, reverting to a binary without
the rule removes a consensus restriction and is not an ordinary safe rollback.
Use a corrected binary preserving the activated rule or a separately coordinated
network decision. No database migration or automatic finality-policy override is
part of this patch.
