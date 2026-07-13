# Mining Security in Discrete

## Scope

Discrete combines identity-bound signed yespower with a local depth-10 reorganization
limit. These mechanisms narrow several attack paths, but they do not make a small
proof-of-work network immune to pooling, partitions, eclipse attacks, or a self-funded
majority. This document states the implemented guarantees and residual risks.

## Identity-bound signed proof of work

Every nonce candidate is signed with ML-DSA-65 by the spend key committed in the
coinbase. yespower hashes the block hashing blob plus `cn_fast_hash(signature)`, and
consensus verifies the full signature and reward commitment. See [POW.md](POW.md) for
the exact byte sequence.

This provides:

- reward-identity binding: a relayer cannot redirect a signed candidate's reward;
- per-attempt signer involvement: every varied nonce needs a fresh signature;
- friction against generic stateless rental and conventional unsigned Stratum jobs;
- an ~8 MiB yespower working set per active attempt.

It is not a proof of strong non-outsourceability. A custodial operator can retain the
reward key, sign candidate nonces at aggregate rate, distribute the resulting jobs, and
pay lower-difficulty shares off-chain. The operator's signing service is a bottleneck,
not a cryptographic impossibility. Dedicated mining wallets also weaken any argument
that rational miners will never expose a reward key.

Consequently, Discrete should call this mechanism **identity-bound signed PoW** or
**delegation-resistant PoW**, not claim that pools and rental are closed by construction.

## First-seen depth limit

Each node rejects a competing chain whose fork point is more than
`CRYPTONOTE_FINALITY_DEPTH = 10` blocks behind its current tip, regardless of cumulative
work. A connected node that has already accepted the honest history therefore refuses a
late private deep rewrite.

This state is local and weak-subjective, not a globally objective finality certificate.
During a partition or eclipse, different node groups can finalize incompatible histories.
Offline and newly bootstrapped nodes may not share the same observation order. Recovery
requires an operator to identify the majority history through independent, out-of-band
signals and explicitly run `resync_to_majority --confirm`.

The rule therefore trades availability and automatic convergence for protection of a
node's already-observed deep history. It narrows withheld-chain attacks against connected
victims; it does not eliminate majority censorship, partitions, eclipse attacks, social
coordination, or conflicting finalized views.

## Miner isolation behavior

The built-in miner stops when all peers disconnect. This prevents the simplest lone-miner
offline fork. It does not prove majority connectivity when one or more stale or adversarial
peers remain. Tip-age and independent-peer monitoring are operational safeguards, not
consensus rules.

## Blockchain scratchpads

Karbo's whole-history sampling and Discrete's experimental bounded trailing-window sampler
are evaluated in [POW.md](POW.md). They can require recent chain data and complicate
commodity rental, but public scratchpad data do not prevent a purpose-built pool from
outsourcing work. The bounded `dev/pow-window` design is the better engineering experiment
for full-node mining; neither design upgrades signed yespower into a strong
non-outsourceable puzzle.

## Residual attack surface

- A custodial pool can build a signing service and pay shares off-chain.
- A self-funded majority can censor or slow new blocks for as long as it persists.
- Partitions and eclipses can create conflicting locally finalized histories.
- Botnets and farms can run the same CPU algorithm and public working set.
- yespower's memory hardness is an engineering cost asymmetry, not a proof of permanent
  ASIC resistance or egalitarian hardware.
- Finality recovery depends on correct out-of-band operator judgment.

These limits should appear in every public protocol description until stronger mechanisms
are designed, independently reviewed, benchmarked, and deployed.
