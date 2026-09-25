# Discrete finality/recovery audit for an evidence-only QRE proposal

Audit date: 2026-09-25. Scope: source tracing and existing offline tests; no
production node, wallet, funds, deployment or recovery operation was exercised.

**Conclusion:** authenticated witness observations can improve an operator's
recovery decision without changing consensus. They must not be treated as
rollback authority. The current online recovery path also has guard and
validation gaps relative to the proposed invariants. A quorum does not close
those gaps. PR 1 should be documentation only.

## Provenance

- Correct upstream: [`discretecoin/discrete`](https://github.com/discretecoin/discrete),
  default branch `master`, read back at
  `eadc76cdaa6355f7600b95ee096593de07e22707`.
- Operator documentation: [`discretecoin/discrete-docs`,
  `1c9e4e1ee9dd07d4c20cf0e08e3bf6b9543908bc`](https://github.com/discretecoin/discrete-docs/blob/1c9e4e1ee9dd07d4c20cf0e08e3bf6b9543908bc/operators/finality-recovery.md).
  This is a separate canonical documentation repository. The operator guide
  requires deliberate, explicitly confirmed recovery. A Core RFC does not
  supersede that guide or authorize its proposed future interfaces.
- These are pinned source facts, not a claim about software deployed on peers.

## A. Implementation map

### A1. Exact finality rule and ordinary fork choice

[`src/CryptoNoteConfig.h:38-46`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CryptoNoteConfig.h#L38-L46)
defines `CryptoNote::parameters::CRYPTONOTE_FINALITY_DEPTH = 10` as a `uint32_t`
consensus parameter, not a runtime option.

[`Checkpoints::is_finality_violation`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/Checkpoints/Checkpoints.cpp#L116-L151)
evaluates:

```cpp
uint64_t(block_height) + CRYPTONOTE_FINALITY_DEPTH < blockchain_height
  && !is_in_checkpoint_zone(block_height)
```

`blockchain_height` is chain **length** L (tip+1); `block_height` is candidate
alternative height h. Outside the checkpoint zone, L=100/h=90 passes the depth
gate; L=100/h=89 fails. Depth ten is allowed; depth eleven is refused. The widened
addition avoids young-chain underflow. Height zero is rejected separately.
`is_alternative_block_allowed` then applies its separate checkpoint constraint.
The checkpoint-zone exemption is not unconditional permission for a deep fork.

[`Blockchain::handle_alternative_block`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CryptoNoteCore/Blockchain.cpp#L1390-L1427)
applies this gate before the later alternative-chain cumulative-work comparison.
The existing admitted-checkpoint switch and ordinary strictly-higher-cumulative-
difficulty switch are at
[`Blockchain.cpp:1568-1600`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CryptoNoteCore/Blockchain.cpp#L1568-L1600).
QRE must change neither. This trace and existing tests are not a fresh exhaustive
proof of every possible alternate-chain lifecycle in the whole implementation.

`RpcServer::on_get_info` reports `finalized_height = L - 1 - 10` when L>10.
With inclusion counted as confirmation one, a block is past this local boundary
at **11 confirmations**, not ten. This is node-local finality, not a globally
authenticated settlement guarantee. An offline node on the same prefix only
needs forward sync, not recovery.

### A2. Refusal, warning arming and diagnostic state

On refusal, `handle_alternative_block` can set `bvc.m_finality_fork` and call
`recordFinalityFork` only when `validateCompetingBlock` succeeds. The block is
still refused. The separate protocol/RPC peer-split calculation is diagnostic;
it does not authorize a rollback or determine block validity.

[`validateCompetingBlock`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CryptoNoteCore/Blockchain.cpp#L3121-L3179)
checks a stored main/alternative parent, derives height from that parent, and
checks version, parent-block size, miner transaction structure, identity-bound
block signature and proof of work at the derived difficulty. It can skip a
candidate already covered by an existing deeper/higher diagnostic snapshot.

**Important limit:** this helper does not validate the complete competing branch,
its non-coinbase transactions/spentness, or the full timestamp/cumulative-size
checks from ordinary alternative admission. It also does not prove that the
competing branch has higher cumulative work. A header/PoW check is not a full
branch validity result. Descriptive comments saying "valid" or "higher work"
must not be promoted into stronger evidence than the executed checks provide.

[`FinalityForkState`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CryptoNoteCore/FinalityForkState.h#L17-L30)
is explicitly operator-messaging state, never a block accept/reject input.
`recordFinalityFork` takes `validatedHeight-1` as divergence and retains the
minimum divergence and highest competing block across observations. These fields
can describe an aggregate, not one fully validated alternative history. For an
alternative parent, its immediate height is not necessarily the actual main-chain
last common ancestor. The helper does not walk the full ancestry to establish it.
This is a source limitation; no live exploitation is claimed.

The state lives in memory (`m_finalityForkState`), is cleared by successful chain
switch/recovery, and is not a durable recovery journal. It must remain diagnostic.
A new QRE incident/validation result must not turn this structure into consensus
state or assume that it is a trustworthy recovery plan.

### A3. Confirmed recovery call chains and guards

| Entry point | Current checks and effect |
| --- | --- |
| `DaemonCommandsHandler::resync_to_majority` | Requires an active warning; accepts `--confirm` or `yes`; otherwise displays out-of-band verification guidance. Calls Core's recovery wrapper. |
| `RpcServer::on_resync_to_majority` | Refuses restricted RPC; requires `confirm=true`; calls Core's recovery wrapper. |
| `Core::resyncToMajority` | Delegates to `Blockchain::resyncToMajority`. |
| `Blockchain::resyncToMajority` | Holds blockchain lock, requires active warning and `divergenceHeight < current tip`, pops to that target, clears warning. **No checkpoint-zone guard or full candidate-branch validation in this function.** |
| Offline `--rollback-to-height H` | Requires H below tip; rejects `isInCheckpointZone(H)`; requires `--confirm` or interactive `yes`; invokes raw Core rollback. |
| Developer `--rollback H` | Separate raw/unguarded path. Must not be used by QRE tooling or presented as recovery evidence enforcement. |

Source entry points:
[`DaemonCommandsHandler.cpp:200`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/Daemon/DaemonCommandsHandler.cpp#L200-L234),
[`RpcServer.cpp:1783`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/Rpc/RpcServer.cpp#L1783-L1802),
[`Blockchain.cpp:3210`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CryptoNoteCore/Blockchain.cpp#L3210-L3250),
[`Daemon.cpp:363`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/Daemon/Daemon.cpp#L363-L420).

`rollbackBlockchainTo(H)` retains H and removes blocks **above** it. The code
does not pop one extra block "below divergence" despite some existing prose.
It uses storage block removal and retries LMDB map-full after map growth; it does
not establish a complete atomic, resumable recovery transaction. Block removal
does not itself perform orphan-transaction salvage. After recovery, ordinary
sync resumes from peers without a QRE-bound destination contract.

### A4. Checkpoint interactions

`is_in_checkpoint_zone(h)` means h is at or below the **highest loaded**
checkpoint, not just an exact pinned height. The loaded map can contain built-in,
DNS-fetched and operator-file checkpoints. The built-in list at this revision
ends at height 30000; that does not prove the effective runtime map ends there.

The offline check guards the retained target, so equality with the highest
checkpoint also refuses rollback. The online path lacks this check. The
alternative finality exemption checks the **candidate** height; it is not an
equivalent check on a recovery target one or more blocks earlier. Do not infer
the online guard from the finality gate. This discrepancy needs a dedicated
regression fixture before any mutating integration is proposed.

Existing [`CheckpointsDns/DnsCheckpoint.h`](https://github.com/discretecoin/discrete/blob/eadc76cdaa6355f7600b95ee096593de07e22707/src/CheckpointsDns/DnsCheckpoint.h)
and `.cpp` authenticate genesis-bound checkpoint files using **any-of-N** approved
ML-DSA signers. This is a different trust purpose. QRE must not call
`add_checkpoint`, extend the checkpoint zone, reuse its signature domain or
inherit its signer authority. Such reuse would affect admission/validation trust.

### A5. Tests run and coverage limits

Fresh MSVC x64 Release build of the pinned source and local CTest run:

| Existing suite | Observed result | What it covers |
| --- | --- | --- |
| `PqFinalityTests` | Pass, 9 cases | Depth ten/eleven, shallow forks, young chains, checkpoint exemption/list shape, deterministic predicate, configured signer-address decoding. |
| `PqChainTests` | Pass, integration executable | Includes `runFinalityForkArming`: invalid/stranger signature and unknown parent do not arm; a constructed competitor is refused yet arms with its stored main-parent height. Also exercises existing PQ chain paths. |
| `PqPowTests` | Pass, 12 cases | Existing DiscretePower/PQ proof behavior. |
| `PqDnsCheckpointTests` | Pass, 24 cases | Existing signed DNS checkpoint format/verification behavior. |

No test in this run performs the full confirmed recovery command, verifies its
checkpoint-zone protection, proves a partially validated competing branch cannot
steer it, tests an alternative-parent LCA, or exercises process/power loss during
rollback. QRE does not exist upstream. Passing these four suites does not prove
the requested future security invariants or production safety.

## B. Findings and required decisions before implementation

1. **Keep the current consensus model.** Depth=10, PoW, shallow forks, difficulty,
   transaction ordering and checkpoint admission must remain unchanged. More work
   never becomes evidence-tooling authority for a deep reorg.
2. **Close the online/manual guard gap before integrating executable QRE plans.**
   A shared guard in the confirmed recovery path must reject a retained target
   in the effective checkpoint zone and stale/mismatched local state. Both bare
   manual and QRE-assisted confirmation should pass it. This is proposed future
   work, not a fix delivered by this docs-only PR.
3. **Separate warning from readiness.** The current warning arming is partial
   validation. It may report a conflict but cannot supply a trusted target. A
   future prepared plan needs locally validated ancestry and consensus state.
   The literal requirement that no partially validated branch can arm current
   recovery is **not established by this baseline**. QRE must not obscure that.
4. **Compute and bind the real LCA.** Derive it from validated local/candidate
   chains, compare the witness assertion to it, and reject disagreement. Neither
   a claimed height nor an authenticated witness statement sets a rollback target.
5. **Retain one explicit recovery workflow.** Extend `resync_to_majority --confirm`
   with optional binding to a displayed plan; do not add QRE-triggered rollback or
   a second chain-adoption engine. The current unrestricted post-pop sync does not
   promise the planned destination. Until execution can enforce/read back that
   contract through the existing path, evidence remains informational and a plan
   must not be advertised as executable/verified recovery.

The companion [QRE RFC](QRE_RECOVERY_RFC.md) defines the threat model, invariants,
signed evidence, equivocation handling, validation gates and pre-implementation
test matrix. There is no code change in this PR and no automatic recovery phase.
