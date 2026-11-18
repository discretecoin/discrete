# Discrete finality/recovery audit for an evidence-only QRE proposal

The September 25 audit traced the recovery paths and recorded four offline
test suites. The November 17 review traced the same paths on current upstream
source. Neither review exercised production recovery.

**Conclusion:** authenticated witness observations can improve an operator's
recovery decision without changing consensus. They must not be treated as
rollback authority. The current online recovery path also has guard and
validation gaps relative to the proposed invariants. A quorum does not close
those gaps. The standalone QRE verifier inspects supplied observations offline.

## Provenance

- The original Core audit and test run used [`eadc76cd`](https://github.com/discretecoin/discrete/commit/eadc76cdaa6355f7600b95ee096593de07e22707).
  The source links below use upstream `master` at [`0ccd60a0`](https://github.com/discretecoin/discrete/commit/0ccd60a015bf8e84d3b9d285678fd158450e4d73),
  checked on 2026-11-17. The incoming-height predicate, alternative promotion,
  warning aggregation and confirmed recovery target retain the behavior traced
  at the original revision.
- Operator documentation: [`discretecoin/discrete-docs`,
  `1c9e4e1ee9dd07d4c20cf0e08e3bf6b9543908bc`](https://github.com/discretecoin/discrete-docs/blob/1c9e4e1ee9dd07d4c20cf0e08e3bf6b9543908bc/operators/finality-recovery.md).
  The guide had the same Git blob (`b18f8fec093271d2c1cc26d9ddc5bc436f99ac73`)
  on documentation `main` at [`fe08d53b`](https://github.com/discretecoin/discrete-docs/blob/fe08d53b57a62e5cde87ac9b8ad5320e42ea90ec/operators/finality-recovery.md)
  on 2026-11-17. The operator guide
  requires deliberate, explicitly confirmed recovery. A Core RFC does not
  supersede that guide or authorize its proposed future interfaces.
- These are pinned source facts, not a claim about software deployed on peers.

## A. Implementation map

### A1. Exact finality rule and ordinary fork choice

[`src/CryptoNoteConfig.h:38-46`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteConfig.h#L38-L46)
defines `CryptoNote::parameters::CRYPTONOTE_FINALITY_DEPTH = 10` as a `uint32_t`
consensus parameter, not a runtime option.

[`Checkpoints::is_finality_violation`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Checkpoints/Checkpoints.cpp#L123-L149)
evaluates:

```cpp
uint64_t(block_height) + CRYPTONOTE_FINALITY_DEPTH < blockchain_height
  && !is_in_checkpoint_zone(block_height)
```

`blockchain_height` is chain **length** L (tip+1); `block_height` is candidate
alternative height h. Outside the checkpoint zone, L=100/h=90 passes the depth
gate and L=100/h=89 fails. Here depth means L-h for the incoming block. The widened
addition avoids young-chain underflow. Height zero is rejected separately.
`is_alternative_block_allowed` then applies its separate checkpoint constraint.
The checkpoint-zone exemption is not unconditional permission for a deep fork.

[`Blockchain::handle_alternative_block`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L1384-L1421)
applies the predicate to the incoming block. A previously admitted alternative
may later reach the [checkpoint or cumulative-work promotion path](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L1562-L1595).
At promotion, [`switch_to_alternative_blockchain`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L1259-L1308)
uses the first stored alternative block's height as the split height. It does
not reapply the depth predicate at the last common ancestor (LCA). Ordinary fork
choice can therefore detach more than ten main-chain blocks after alternatives
have been admitted. QRE preserves both paths. A work advantage never authorizes
QRE-assisted rollback.

[`get_info`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Rpc/RpcServer.cpp#L1350-L1359)
reports `finalized_height = L - 1 - 10` when L>10. A block at that height has
**11 confirmations**, counting its inclusion. This field describes the local
depth boundary. The promotion path above limits the guarantee an operator can
infer from it. A node behind on the same prefix only needs forward sync.

### A2. Refusal, warning arming and diagnostic state

On refusal, `handle_alternative_block` can set `bvc.m_finality_fork` and call
`recordFinalityFork` only when `validateCompetingBlock` succeeds. The block is
still refused. The separate protocol/RPC peer-split calculation is diagnostic;
it does not authorize a rollback or determine block validity.

[`validateCompetingBlock`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L3100-L3158)
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

[`FinalityForkState`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/FinalityForkState.h#L17-L30)
is explicitly operator-messaging state, never a block accept/reject input.
[`recordFinalityFork`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L3160-L3182) takes `validatedHeight-1` as divergence and retains the
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

Source entry points include the [console handler](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Daemon/DaemonCommandsHandler.cpp#L200-L229),
[RPC handler](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Rpc/RpcServer.cpp#L1635-L1654),
[Core wrapper](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Core.h#L154), [online recovery](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L3189-L3227)
and [offline rollback options](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Daemon/Daemon.cpp#L350-L407).

The current console scans for confirmation tokens and ignores extra arguments.
The [RPC request](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Rpc/CoreRpcServerCommandsDefinitions.h#L399-L406)
reads only the `confirm` member through the [typed deserializer](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/Serialization/SerializationTools.h#L87-L90).
Adding a plan ID alongside legacy confirmation cannot protect a caller connected
to an older daemon. Any future plan-bound form must be refused by legacy
handlers and must never fall back to a bare confirmation.

[`rollbackBlockchainTo(H)`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L3077-L3096)
retains H and removes blocks **above** it. Each [block removal](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CryptoNoteCore/Blockchain.cpp#L2989-L3060)
can commit separately. Interruption can leave a partially shortened chain.
The loop retries a map-full exception after growing the map. Certain block-read
or decode errors return without removing a block, and the caller has no check
for an unchanged height. A future executor must verify per-step progress,
preserve the last committed tip on failure and reconcile it before retry.
Storage block removal itself does not salvage orphaned transactions. Ordinary
post-pop peer sync has no contract to reach the reviewed branch. The online
success response only reports rollback and the intent to resync.

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

Existing [`CheckpointsDns/DnsCheckpoint.h`](https://github.com/discretecoin/discrete/blob/0ccd60a015bf8e84d3b9d285678fd158450e4d73/src/CheckpointsDns/DnsCheckpoint.h)
and `.cpp` authenticate genesis-bound checkpoint files using **any-of-N** approved
ML-DSA signers. This is a different trust purpose. QRE must not call
`add_checkpoint`, extend the checkpoint zone, reuse its signature domain or
inherit its signer authority. Such reuse would affect admission/validation trust.

### A5. Tests run and coverage limits

The original 2026-09-25 audit recorded the following MSVC x64 Release and
CTest results at `eadc76cd`. The November source review did not rerun them.

| Existing suite | Observed result | What it covers |
| --- | --- | --- |
| `PqFinalityTests` | Pass, 9 cases | Depth ten/eleven, shallow forks, young chains, checkpoint exemption/list shape, deterministic predicate, configured signer-address decoding. |
| `PqChainTests` | Pass, integration executable | Includes `runFinalityForkArming`: invalid/stranger signature and unknown parent do not arm; a constructed competitor is refused yet arms with its stored main-parent height. Also exercises existing PQ chain paths. |
| `PqPowTests` | Pass, 12 cases | Existing DiscretePower/PQ proof behavior. |
| `PqDnsCheckpointTests` | Pass, 24 cases | Existing signed DNS checkpoint format/verification behavior. |

No test in this run performs the full confirmed recovery command, verifies its
checkpoint-zone protection, proves a partially validated competing branch cannot
steer it, tests an alternative-parent LCA, or exercises process/power loss during
rollback. These four historical suites did not exercise a QRE verifier.

## B. Findings and required decisions before implementation

1. **Keep the current consensus model.** Depth=10, PoW, shallow forks, difficulty,
   transaction ordering and checkpoint admission must remain unchanged. More work
   never becomes evidence-tooling authority for a deep reorg.
2. **Close the online/manual guard gap before integrating executable QRE plans.**
   A shared guard in the confirmed recovery path must reject a retained target
   in the effective checkpoint zone and stale/mismatched local state. Both bare
   manual and QRE-assisted confirmation should pass it. This is proposed future
   work. The offline verifier has no recovery entry point.
3. **Separate warning from readiness.** The current warning arming is partial
   validation. It may report a conflict but cannot supply a trusted target. A
   future prepared plan needs locally validated ancestry and consensus state.
   The literal requirement that no partially validated branch can arm current
   recovery is **not established by this baseline**. QRE must not obscure that.
4. **Compute and bind the real LCA.** Witnesses independently look up the
   block IDs at the common requested observation and reference heights on their
   validated histories. The receiver checks those IDs against the validated
   candidate and derives the LCA from its own active chain and that candidate.
   Witnesses never assert the receiver's LCA or select its rollback target.
5. **Retain one explicit recovery workflow.** A future plan-bound confirmation
   must route through the existing recovery workflow and be distinguishable
   from a legacy manual confirmation, including at an older daemon. The current unrestricted post-pop sync does not
   promise the planned destination. Until execution can enforce/read back that
   contract through the existing path, evidence remains informational and a plan
   must not be advertised as executable/verified recovery.

The companion [QRE RFC](QRE_RECOVERY_RFC.md) defines the threat model, invariants,
signed evidence, equivocation handling, validation gates and pre-implementation
test matrix. The standalone verifier leaves consensus and operator recovery intact.
