# Mining Security in Discrete

## Non-Outsourceable Proof-of-Work and First-Seen Finality

### The problem specific to small proof-of-work chains

A proof-of-work chain is secured by hashrate, and hashrate is mercenary. It flows to
whatever pays most and leaves when something pays more. For a large chain this is
tolerable, because the honest hashrate is too expensive to out-bid or out-rent. For a
young or small chain it is the whole security problem: the attacker does not need to
invent anything, only to *assemble* more hashrate than the honest network for a few
hours — by renting it, by incentivising others to point theirs at a hostile pool, or by
bringing their own.

This is not hypothetical. It is the failure mode that has actually taken down small
proof-of-work coins, and in 2025 it reached the largest ASIC-resistant chain in
existence: an external pool assembled a majority of Monero's hashrate — mined openly,
incentivised with a second token paid on top of ordinary rewards — and used it to
reorganise the chain, including a deep reorg that invalidated already-confirmed
transactions. The pool did not break any cryptography. It simply out-bid the honest
network for rented and volunteered hashrate.

Discrete's mining design begins from a single principle drawn from that history:

> **51% resistance cannot come from inside proof-of-work.** A unique algorithm, a
> decentralised pool, or any rule verifiable purely from hashrate can always be
> satisfied by whoever holds the most hashrate — because hashrate is the only
> Sybil-resistant resource proof-of-work exposes, and the attacker has a majority of it.

Real resistance requires two things that proof-of-work alone does not give: a way to
stop hashrate from being *aggregated* against the chain, and a resource *outside*
hashrate that an attacker cannot obtain merely by having more of it. Discrete addresses
these with two mechanisms — non-outsourceable proof-of-work (SPow) and first-seen
finality — and deliberately declines a third that would undo the first.

---

### SPow: mining bound to key ownership

The mercenary-hashrate attack has a precondition that is easy to overlook: it requires
hashrate to be *delegable*. Rental markets, hostile pools, and incentive schemes all
work by letting one party direct hashrate that belongs to others. Remove delegation and
the attack loses its supply chain.

Discrete uses **SPow**, a non-outsourceable proof-of-work in which valid work is
cryptographically bound to a key the miner must hold. A share of work that is not signed
by the miner's own key is not valid work. There is no way to hand the search to a pool
or a rental service without also handing over the key — which no rational miner does,
because the key controls the reward and, ultimately, the funds.

The consequence is structural, not economic: a miner cannot point hashrate at a hostile
aggregator, because the aggregator cannot produce valid blocks without each
contributor's key. The pool-aggregation and hashrate-rental vectors — the exact vectors
that assembled a majority against Monero and, years earlier, against this design's
predecessor — are closed by construction rather than discouraged by policy.

Concretely, Discrete's proof-of-work is yespower computed over the block's *signed*
hashing blob: the miner signs the block header — which includes the nonce — with the
ML-DSA-65 spend key that controls the coinbase reward, and yespower then hashes the
signed blob. Because the signature covers the nonce, the block must be re-signed on every
attempt, and consensus additionally requires the single coinbase output to pay the same
key that signed the block (the recipient commitment is publicly recomputable from the
signer's public key, height, and output index). Mining to a key you do not hold is
therefore rejected, and delegating the search to a pool or rental service requires
handing over the spend secret that controls the funds.

This is not a new or untested mechanism. SPow was developed for Karbo in response to
real hashrate-rental attacks under a commodity algorithm, and it has run on mainnet for
several years since, through which the attacks that motivated it have not recurred. In
Discrete it is layered over a memory-hard yespower core — the 8 MiB scratchpad is the
actual ASIC-resistance mechanism — whose personalization is fixed to a Discrete-specific
domain tag, so that work produced for any other chain cannot be reused, precompute-shared,
or merge-mine confused with Discrete's. The algorithm is deliberately CPU-egalitarian;
hardware-scarcity exclusion of farms and botnets is a separate, GPU-bound or capital
question that this proof-of-work does not attempt and does not claim to solve.

---

### Why Discrete does not use a decentralised pool

Decentralised pooling (p2pool and its relatives) is frequently proposed as a
decentralisation measure, and it is a genuinely good solution — to a different problem.
A p2pool smooths *payout variance*: instead of a solo miner waiting a long time for a
whole block, contributors share each block in proportion to recent work. That is
valuable, and Discrete takes the variance problem seriously. But a decentralised pool is
not a security mechanism, and adopting one would directly weaken the security mechanism
Discrete does rely on.

A pool — decentralised or not — works by *sharing* a block's reward across everyone who
contributed recent work. Sharing work is delegation of work. It is precisely the thing
SPow forbids. A block whose reward is split across a pool's recent contributors cannot
also be a block whose work is bound to a single miner's key; the two rules compete for
the same coinbase. To ship a pool is to give back the non-outsourceability that closes
the aggregation vector — and the empirical record is unambiguous about the cost:
the one major chain that relied on decentralised pooling for its mining decentralisation
is the one that was reorganised in 2025, through exactly the aggregation door that SPow
keeps shut.

Nor can the pool be rescued by making membership a consensus rule or by applying
Discrete's first-seen finality (below) to a share-chain. A consensus membership rule is
still verifiable only from hashrate, so a majority attacker satisfies it by running their
own share-chain. And first-seen finality only rejects history that appears *late*: an
attacker who mines a hostile share-chain openly and continuously — as the 2025 attacker
in fact did — is first-seen-valid at every height and is never flagged. The mechanism
that defends the main chain does not transfer to a layer whose stakes are only the
reward split.

Discrete therefore handles variance where it can be handled without reopening the attack
surface: on the solo side. A deliberately chosen block interval and reward granularity
keep solo payouts on a human timescale, and the reference full-node wallet surfaces
accumulated progress so that steady work reads as steady progress even between blocks.
This is a weaker variance tool than a shared pool, and Discrete accepts that trade
knowingly — because the security it protects is ranked above the convenience it costs,
and because the mining base a post-quantum, correctness-first chain attracts is precisely
the base that has historically tolerated solo variance as a lottery.

---

### First-seen finality: a resource outside hashrate

SPow closes hashrate *aggregation*. It does not close the residual case of an attacker
who funds their own majority outright and mines to their own keys. Nothing inside
proof-of-work can, because that attacker is playing proof-of-work by its own rules and
winning on raw work. Closing this case requires a resource the attacker cannot obtain by
having more hashrate.

Discrete uses the resource its predecessor already proved in production: **observation
order**. Honest nodes watch the chain grow in real time and record which block they saw
first at each height. An attacker's advantage — a longer or heavier chain — is a
statement about *cumulative work*, which the attacker controls. It is not a statement
about *what was seen first*, which the attacker cannot forge, because the honest network
already witnessed a different history at those heights.

Discrete enforces a **network-wide first-seen finality rule**: every node refuses a
reorganisation deeper than a bounded number of blocks — one that would rewrite
already-witnessed history and "emerge from nowhere." A private chain withheld and
published late, the classic deep-reorg and selfish-mining attack, is rejected by the
whole network on the ground that it was not seen first, however much work it carries. This
is the mechanism that refuses precisely the kind of deep reorg that rewrote confirmed
history elsewhere in 2025 — and because the rule is enforced by every node rather than
only by those who opt in, immutability is a property of the chain itself, not a service
sophisticated parties buy for themselves while ordinary users remain exposed.

This is a deliberate consistency-over-availability choice, and Discrete states its cost
plainly. Enforced network-wide, the rule means that a node which stayed isolated while
continuing to produce blocks past the finality depth — a sustained network partition, or a
long-disconnected miner — can build a divergent fork that its own node will then refuse to
abandon in favour of the majority chain, requiring a manual resync. Discrete accepts this
trade because the failure it prevents and the failure it introduces are not of equal
weight: a refused deep reorg is a *recoverable liveness* event in which no confirmed
transaction is reversed and no funds are lost, whereas an accepted deep reorg is an
*irreversible safety* event — double-spends against every user who did not individually
harden. A correctness-first chain prefers the recoverable failure every time.

The cost is bounded in both scope and handling. It falls only on nodes that kept mining
while isolated *past* the finality depth; a node that merely went offline holds a prefix
of the true chain and syncs forward with no wedge, and any divergence shallower than the
depth self-heals, aided by LWMA difficulty retargeting that reconverges the network
quickly after a hashrate swing. For the residual case, Discrete ships first-class recovery
tooling and explicit messaging: a node that refuses a deep reorg logs that it is on a
minority fork and points to a documented, single-command procedure for returning to the
majority chain. The wedge is treated as a routine, well-signposted operator action rather
than manual surgery — finality as a first-class node behaviour, in keeping with the
predecessor chain from which the mechanism is inherited.

---

### Summary

Discrete's mining security is a division of labour, with each mechanism carrying exactly
one job and none overloaded beyond what it can bear:

- **SPow** binds work to key ownership, closing hashrate aggregation and rental — the
  vector that most reliably defeats small chains — by construction rather than by
  incentive.
- **First-seen finality** adds observation order, a resource outside hashrate, closing
  the residual deep-reorg case that proof-of-work alone cannot.
- **Solo-side variance management** smooths miner income without reintroducing the
  delegation that a shared pool would, keeping the security guarantee intact.

The design deliberately omits a decentralised pool, not because variance does not matter,
but because the one job a pool uniquely performs — sharing, and therefore delegating,
work — is the one job that would undo non-outsourceability. Every element here is either
battle-tested on a live predecessor chain or composed from vetted primitives; none of it
asks the reader to trust an unproven mechanism with the chain's security.
