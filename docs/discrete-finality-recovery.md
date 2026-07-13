# Recovering from a First-Seen Finality Fork

## Operator guide and tooling specification

Discrete enforces **node-local first-seen finality**: each node refuses a
reorganisation deeper than `CRYPTONOTE_FINALITY_DEPTH` blocks. This protects the network
from deep-reorg and selfish-mining attacks, at a known cost — a node that stayed isolated
while producing blocks past the finality depth can end up on a divergent minority fork
that its own node will refuse to abandon automatically. This document specifies how such a
node is detected, what it must tell the operator, and how the operator returns it to the
majority chain.

The guiding rule, which shapes every design choice below:

> **Recovery is deliberate and operator-confirmed. It is never automatic.** A node that
> silently followed the longer chain would re-introduce exactly the deep-reorg
> vulnerability that first-seen finality exists to close. The tooling therefore *detects*
> and *assists*, but a human confirms the majority chain out-of-band before any rollback.

---

## 1. When a wedge happens (and when it does not)

A wedge requires a node to have **continued producing or accepting blocks on a divergent
history past the finality depth.** In practice this means one of:

- a sustained network partition (the node was cut off from the majority for longer than
  `CRYPTONOTE_FINALITY_DEPTH` blocks while its local segment kept mining), or
- a long-disconnected miner that kept mining to its own tip while offline.

It does **not** happen to:

- a node that simply went offline and stopped — it holds a prefix of the true chain and
  syncs forward normally when it reconnects;
- a node whose divergence is shallower than the finality depth — that self-heals via
  normal reorg, accelerated by LWMA retargeting.

So the affected population is narrow: nodes that were both *isolated* and *actively
extending* their own fork for a meaningful length of time.

---

## 2. Detection and messaging (the daemon's job)

When a node refuses a reorg because it exceeds the finality depth, it must surface the
event clearly rather than failing silently. The same refusal covers two very different
situations, and the messaging must not presume which one the operator is in:

1. **The node is honest and the deep alt-chain is an attack.** Refusing is correct; no
   action is needed. This is the common, healthy case.
2. **The node is itself on the minority fork.** Refusing is what wedges it; the operator
   must recover.

The node cannot always distinguish these from the refusal alone, but the **peer split** is
the key diagnostic: if the deeper chain is being offered by the large majority of the
node's peers and the node's own tip is being rejected by them, the node is likely on the
minority fork.

### Required log line

On refusing a finality-depth-exceeding reorg, emit at `WARNING`:

```
FINALITY: ignored a deeper competing chain (depth <D>; local tip <hHi>:<hashLocal>,
offered tip <hHo>:<hashOther>, seen from <Npeers>/<Ntotal> peers). Usually nothing
to worry about - most likely this node briefly lost connectivity and ended up on a
side chain, and funds are unaffected. Nothing to do if it is in sync; if it is
behind, check the current tip on the official block explorer and run
'resync_to_majority --confirm' to rejoin the main chain. See: <recovery-docs-url>
```

The message is deliberately low-key: it treats the common case (a brief
connectivity hiccup that left the node on a side chain) as the routine, no-big-deal
event it usually is, and never asserts the node *is* on a minority fork. It points
the operator at the out-of-band check (the official explorer) and the one command
that returns a genuinely-behind node to the main chain. That explorer check is the
safeguard: a node that is correctly refusing an attacker's chain must not be rolled
back onto it.

### Required status flag

`discreted status` (and the equivalent RPC field) must expose a persistent flag while the
condition holds, so operators and monitoring see it without grepping logs:

```
finality_fork_warning : TRUE
  local_tip            : <height>:<hash>
  competing_tip        : <height>:<hash>   (higher cumulative work, refused)
  peer_split           : <Npeers_on_competing>/<Ntotal> peers on competing chain
  divergence_height    : <height>          (last common ancestor)
```

The status line adds a low-key, actionable hint whenever the flag is set: `usually
just a brief connectivity hiccup; check the tip on the official block explorer, and
if this node is behind run resync_to_majority --confirm to rejoin the main chain`.
It is guidance, not an assertion that the node is on a minority fork.

### Wallet-facing message

Wallets connected to a wedged node, and wallets recovering after a node rollback, must
show a non-technical banner:

```
Your node briefly ended up on a side chain, most likely a short connectivity
hiccup. This is nothing to worry about and your funds are safe. If your balance
looks off, your node may just be a little behind - you can check the official block
explorer, and it will rejoin the main chain with the recovery command.
```

Keep it casual and reassuring: treat it as the routine, no-big-deal event it usually
is, point the user at the official explorer to check, and at the one command that
fixes a genuinely-behind node. Do not tell users their transactions were reversed or
that they are "on a minority fork" - most nodes that see this are simply refusing an
attacker's chain and need to do nothing.

---

## 3. Recovery tooling (implemented daemon interface)

Two operator-facing entry points, both of which pop the local chain back below the
divergence height and re-sync forward from the majority:

- **CLI (offline / one-shot):**
  `discreted --rollback-to-height <H>` — pops all blocks above `H`, then starts and syncs
  normally. `H` should be at or below `divergence_height`.
- **RPC / interactive console (online):**
  `resync_to_majority` — convenience wrapper that reads `divergence_height` from the
  detected fork state, pops to just below it, and resumes sync. Refuses to run unless the
  `finality_fork_warning` flag is set, so it cannot be used to force an ordinary deep
  reorg by hand.

Both must:

- require explicit confirmation (a `--confirm` flag or interactive `yes`), never run
  unattended;
- refuse to operate below the divergence height by more than a small safety margin (do
  not let an operator accidentally nuke the whole chain);
- log the before/after tips and the number of blocks popped.

Underlying block-pop capability is inherited from the CryptoNote/Karbo storage layer; this
tooling is the guarded, well-messaged wrapper around it plus the fork-state detection in
§2.

---

## 4. Procedure by node role

### Solo miner (the most likely to wedge)

1. See `FINALITY FORK` warning / `finality_fork_warning: TRUE`.
2. **Confirm the majority chain out-of-band** — check the block explorer, a public seed
   node, or two independent nodes for the current tip hash at your `competing_tip` height.
   Do not skip this; it is the human step that keeps recovery safe.
3. If the competing chain is confirmed as the majority: run
   `resync_to_majority --confirm` (or `--rollback-to-height <divergence_height>` offline).
4. Let the node sync to the majority tip.
5. Rescan the mining wallet. Blocks you mined on the minority fork are orphaned — their
   coinbase rewards do not exist on the majority chain. This is the accepted cost of having
   mined while isolated.
6. **Prevent recurrence:** do not mine while disconnected from peers (see §5).

### Exchange / payment service

1. Monitoring should alert on `finality_fork_warning` immediately.
2. **Pause deposits and withdrawals** until resolved — a wedged node may show balances that
   the majority chain does not agree with.
3. Confirm the majority chain out-of-band, then `resync_to_majority --confirm`.
4. After resync, re-derive deposit confirmations from the majority chain. Any deposit that
   was confirmed only on the minority fork must be treated as reverted.
5. Resume once the node tracks the majority tip with normal confirmations.

Services should additionally run with a **confirmation count at or above the finality
depth**, so that a deposit they consider settled is one the whole network has finalised —
making the wedge case affect only in-flight deposits, never settled ones.

### Ordinary wallet user

Most users are never affected — a light or standard wallet follows whatever majority chain
its node serves. If a user's own node was wedged:

1. The wallet shows the §2 banner.
2. After the node recovers (steps above), the wallet rescans from `divergence_height`.
3. Any transaction confirmed only on the minority fork returns to pending; re-send if it
   does not re-confirm on the majority chain.

---

## 5. Prevention

The built-in miner stops when its peer count falls to zero. This prevents the simplest
case: a lone miner continuing to extend a private tip after total disconnection. It does
not reliably detect a partition in which the node retains one or more peers, because a
permissionless node cannot infer global majority connectivity from local peer count alone.
Operators must therefore monitor tip freshness and independent peers; a stronger
partition detector would be an operational heuristic, never a consensus input.

Residual guidance for operators and for any non-built-in miner:

- **Do not mine while isolated.** External or modified miners that do not honor the
  stop-on-partition behaviour can still wedge; only the built-in miner enforces it.
- **Run more than one well-connected peer / seed** so a single link failure does not
  isolate you.
- **Watch `finality_fork_warning`** in monitoring; the earlier a partition is caught, the
  shallower the divergence and the cheaper the recovery.

With the built-in miner handling total disconnection in code, the residual wedge surface
includes a **sustained multi-node partition** or an eclipsed miner that retains stale
peers. The recovery path in §§2–4 exists to handle those cases.

---

## 6. Summary

First-seen finality trades a rare, recoverable liveness event for immunity to the
irreversible safety event of a deep reorg. This document is the other half of that trade:
the detection, messaging, and one-command recovery that make the liveness event routine.
No confirmed-on-majority transaction is ever lost to a wedge; the only casualties are
blocks and transactions that existed *solely* on a minority fork, which by definition were
never part of the chain the network agreed on. Recovery is always operator-confirmed
against an out-of-band majority signal — the one rule that keeps the recovery path from
becoming the very attack surface finality closes.
