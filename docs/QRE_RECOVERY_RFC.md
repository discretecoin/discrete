# RFC: Quorum Recovery Evidence for explicit operator recovery

Status: proposed recovery protocol and an [offline evidence verifier](QRE_OFFLINE_VERIFIER.md).
The verifier inspects a supplied snapshot. Witness services, a live incident
manager, branch validation and operator-confirmed plan execution are design work.

Quorum Recovery Evidence (QRE) authenticates what independently configured
witnesses observed. It informs an operator decision; it is **not a finality
override, a consensus certificate, or authority to roll back**. The current
security model remains the default. Automatic QRC-authorized recovery is outside
this proposal and would require a separate trust-model proposal.

Read the [pinned upstream audit](QRE_UPSTREAM_AUDIT.md) first. In particular,
the current online recovery path lacks the offline path's checkpoint-zone
guard, and warning-state arming is only partial branch validation. This RFC
does not claim those gaps are already fixed.

## 1. Purpose and unchanged boundaries

Today an operator compares independent nodes/explorers out of band and explicitly
confirms recovery. QRE makes the observations attributable, context-bound and
auditable. It does not determine a global majority or tell an operator which
economically conflicting history ought to win.

```
alternative block refused by the existing candidate-height gate
  -> diagnostic conflict reported if its separate checks pass
  -> gather authenticated observations under a local witness policy
  -> verify signatures, context, freshness, quorum and conflicts
  -> display QUORUM VERIFIED (evidence only)
  -> independently validate candidate branch and compute a local recovery plan
  -> display the exact plan and unresolved risks
  -> operator explicitly invokes the existing confirmed recovery workflow
```

Evidence collection and branch inspection may run independently. Neither one
calls a mutating recovery function. Peer count/split remains diagnostic only.
No stake, validator consensus, protocol-wide federation, on-chain witness set,
blockchain bloat, block ordering or mining role is introduced.

### Security invariants

1. `CRYPTONOTE_FINALITY_DEPTH = 10` and normal PoW/shallow-reorg behavior stay
   unchanged. Work gives QRE no authority to start recovery. Ordinary fork
   choice can promote an already admitted alternative with a deeper split.
2. QRE never participates in block/transaction validity, difficulty or ordinary
   fork choice. `FinalityForkState` stays operator-messaging state.
3. No evidence, absent/insufficient quorum, malformed input, stale context,
   conflict or verification failure changes the chain, warning target, pool,
   miner state or existing manual recovery availability.
4. A quorum authenticates observations only. All branch data required for a
   prepared plan must pass local validation; no supplied height, header, peer
   message, witness statement or evidence bundle determines the rollback target.
5. Authenticated equivocation, conflicting quorums or unresolved candidate ancestry mean no ready plan and no
   QRE-assisted recovery. A manual incident decision remains an explicit human
   action, subject to the same chain/checkpoint guards.
6. No rollback into the effective protected checkpoint zone. Check the actual
   retained target, including equality, under the lock used for recovery.
7. QRE never initiates a chain change. Recovery requires a separate, explicit
   operator decision for the displayed plan.
8. A changed tip, policy, checkpoint set, validation context or new conflict
   invalidates a displayed plan. Fail closed and show the reason.

The plan and execution guards are future integration requirements. The upstream audit documents
why current warning arming and online rollback are insufficient to establish them.

## 2. Local witness policy and threat model

The operator explicitly configures full witness public keys, a threshold t,
network/genesis, policy generation and freshness/resource limits. No default
global roster is installed. Endpoint/DNS/peer identity is not a witness key and
cannot enroll one. Separate operators/providers/key stores matter; many keys on
one host do not establish independent observations.

For a conservative fixed-set profile, evaluate n=7, t=5, f=2, with
`2*t > n+f` and `t <= n-f`. Two five-member subsets overlap in at least three
keys. This limits incompatible same-context quorums **only** if at most f
witnesses are faulty and honest witnesses do not sign incompatible statements
in that context. It is not a finality or liveness theorem across time, policy
changes, or different local rosters. Three equivocating members can violate the
f=2 assumption; five compromised keys can fabricate a quorum without honest help.

There is no globally ordered certificate chain, witness election, permanent
checkpoint lock, quorum-chosen recovery epoch or automatic re-anchoring. A witness
may report changed observations in a new context; those observations never gain
consensus authority. Retain the history so an operator can investigate changes.

| Threat | Response / unavoidable limit |
| --- | --- |
| Temporary 51% hashpower | The existing candidate-height gate and fork-choice rules still apply. Extra work gives QRE no recovery authority. |
| Private deep fork | A previously unseen alternative block can fail the admission gate. An already admitted alternative can later win ordinary fork choice. Neither path calls QRE. |
| Eclipse attack | Query independently pinned witnesses; authenticate context/freshness. A total eclipse may suppress evidence or deceive correlated observers. Hold; no global-connectivity claim. |
| Prolonged partition | Gather observations from both sides when possible; validate candidate ancestry locally; operator decides. Quorum does not erase orphaned payments or external liabilities. |
| 50/50 partition | For a 3/3 split plus one offline witness under 5/7, neither side qualifies. If two local policies disagree, QRE does not force convergence. |
| Malicious witness minority | Invalid/duplicate signatures do not count; equivocation is retained/reported. Withholding or conflicts can reduce availability. Never shrink the denominator automatically. |
| Malicious witness quorum | Can lie coherently or endorse a harmful but valid history. Local validation rejects invalid data, not every economically malicious valid fork. The operator remains responsible. |
| Witness equivocation | Deterministic same-context checks below; retain signed evidence, do not silently select one vote. |
| Stale/replayed evidence | Bind a receiver-generated nonce, incident epoch, fixed window and local snapshot; reject expired, used, foreign or restart-invalidated contexts. |
| Key compromise | Revoke via explicit local policy change, preserve incident evidence and invalidate pending plans. Dedicated witness keys prevent signing-tool exposure of spend/mining keys. |
| Witness key rotation | Explicit out-of-band approval and new policy hash/generation; no certificate-driven key replacement and no combining old/new votes. |
| Conflicting quorum evidence | Display conflict and stop preparing/using plans. Never resolve by arrival, height, timestamp, work or larger signer count. |
| Evidence for an unvalidated branch | Display authenticated observations with `BRANCH UNVALIDATED`; no prepared/executable plan until required local validation succeeds. |
| Misidentified fork point | The receiver derives the last common block from both validated histories. Witnesses supply only the two block IDs they observed at the requested heights. |
| Different operators/witness sets | Distinct policies may produce incompatible conclusions indefinitely. No protocol-wide federation or global-majority proof is implied. |

## 3. Signed evidence: proposed format for review

This profile defines the bytes accepted by the offline verifier. Changing their
interpretation requires a new version.
Use t individual **ML-DSA-65** signatures with the existing `CryptoPQ::dsa_sign`
and `dsa_verify` backend. This is threshold counting, not a novel aggregated
signature/DKG construction. Current constants in `PqDsa.h` are public key 1952,
secret key 4032 and signature **3309 bytes**, statically checked against vendored
liboqs. ML-KEM-768 does not sign observations. QRE is not an independent remedy
for a break of ML-DSA or recovery of coin ownership.

Use separate witness keys and explicit domain separation. Never reuse wallet
message, mining or `discrete-dns-checkpoint-v1` signature domains. In particular,
the existing any-of-N DNS checkpoint verifier is not a QRE quorum verifier, and
QRE must never be imported into `Checkpoints::m_points`.

### Context shared by every observation in one collection

| Field | Purpose |
| --- | --- |
| Domain/version and suite | Literal `discrete-qre-observation-v1`; explicit ML-DSA-65 suite ID. Unknown version/suite fails, no downgrade. |
| Network and genesis block ID | Bind exactly one network/chain; human network label alone is insufficient. |
| Local policy ID/generation | Commit to sorted full witness keys, n/t/f and selected freshness/size rules. Keys never come from the bundle itself. |
| Incident epoch and receiver nonce | Local monotonic incident counter plus unpredictable 32-byte CSPRNG nonce, persisted before collection; not a chain-wide consensus epoch. |
| Requesting node snapshot | Local tip height/hash and an independently validated local anchor height/hash; identifies the history being compared. |
| Observation height B and reference height R | The receiver selects two fixed heights in one round, with `R >= B + 10` in widened arithmetic. It requests no particular hash at either height. |
| Window start/end | Fixed UTC collection interval selected by the receiver, constrained by its configured maximum duration; not witness-controlled indefinite validity. |

`context_id = SHA3-256("discrete-qre-context-v1" || canonical_context)`.
Public local-tip data may reveal operational timing to witnesses; use explicit
operator configuration and avoid including account, balance, wallet or key data.

### Observation statement and signer envelope

| Field | Purpose / verification rule |
| --- | --- |
| Context ID | Exact match to the receiver's locally selected challenge. An active collector must also establish that this challenge is still open. |
| Observed block ID | Read the hash at B from the witness's own fully validated active history. This observation never becomes a Core checkpoint. |
| Reference block ID | Read the hash at R from the same consistent view. Abstain if the witness has not validated through R or cannot obtain a consistent pair. |
| Witness observation time | Signed UTC instant within the requested interval; receiver also checks its own collection deadline, maximum age and bounded clock skew. A signature is not a trustworthy clock. |
| Witness key ID | Full 32-byte SHA3-256 commitment with a separate `discrete-qre-key-v1` domain to the pinned full ML-DSA public key. Reject duplicate public keys/IDs; no short fingerprint authority. |
| Signature | Covers the complete canonical context, statement, observation time and key ID with the observation domain. No unsigned field can alter interpretation. |

The common **statement ID** binds the context and the two observed hashes.
For example, five honest witnesses with tips 126 through 130 can all report
the same blocks at B=115 and R=125. A tip at 124 must abstain. The receiver
may use discovery to select heights, then fixes them for the round. No votes
carry over if it later opens a round with different heights. A witness needs
no access to the receiver's divergent branch to answer this question.

### Proposed v1 byte profile

Juxtaposition concatenates bytes. `u8/u32/u64` are unsigned little-endian.
Times are Unix seconds (UTC). Block IDs are the 32 raw hash bytes in displayed
hex order. The network UUID is the 16 network-ID octets in protocol order.
`V = 01 01` denotes version 1 and ML-DSA-65. `D(x)` is ASCII
`discrete-qre-` + x + `-v1`, without a terminator. `H(x,b) = SHA3-256(D(x) || b)`.
All digests and the nonce are 32 raw bytes.

```text
P = V n:u8 t:u8 f:u8 window:u32 age:u32 skew:u32 records:u32 checks:u32 keys
policy_id = H("policy", P)                key_id = H("key", full_public_key)
C = V network_uuid genesis policy_id generation:u64 epoch:u64 nonce
    local_tip_height:u32 local_tip_hash local_anchor_height:u32 local_anchor_hash
    observation_height:u32 reference_height:u32 window_start:u64 window_end:u64
context_id = H("context", C)
S = observation_hash reference_hash
statement_id = H("statement", context_id || S)
M = D("observation") context_id statement_id observed_at:u64 key_id
E = key_id observed_at:u64 signature[3309]
bundle = C S count:u8 E[count]
```

`keys` is exactly `n` distinct 1,952-byte public keys in unsigned
lexicographic byte order. Reject duplicate key IDs. `window/age/skew` bound
the collection duration, observation age and clock skew in seconds.
`records` caps distinct authenticated (statement, signer) pairs per inspection
and `checks` caps supplied signatures per inspection, including duplicates.
Both budgets must accommodate at least one quorum.
The verifier additionally limits one invocation to 64 bundles and 256 envelopes.
Saturation rejects the snapshot. A future receiver would need a persistent
incident log and its own intake rate limit. Each signed `M` is the raw
131-byte message passed directly to the ML-DSA-65 message-signing API.

Require a known version/suite and `1 <= count <= n <= 32`. The single-statement
bundle must be exactly `291 + 3349 * count` bytes, at most 107,459 bytes.
Check the cap, exact length and strictly increasing key IDs before signature
work. The independent challenge must satisfy `start <= now < end`.
Observation times must be in `[start, end)` and at most `skew` seconds ahead
of the receiver. An authentic observation older than `age` can still establish
equivocation in that challenge. Only fresh observations count for quorum.
Invalid framing, context or signatures reject the supplied inspection as a
whole. Rejection creates no incident state.

Accumulate verified envelopes across supplied bundles by statement and signer.
Use each signer's earliest fresh timestamp on the statement, and show signers
with only stale observations separately. For fresh support,
`H("evidence", statement_id || count:u8 ||
(key_id || observed_at:u64)[count])` uses the same sorted order. It binds who
observed what and when, with a zero count if all signers have aged out.
Retransmission, arrival order and signature randomness at the same evaluation
time do not change this identity. Retain the actual signed envelopes for audit.

**Transcript fixture.** For hashing only, use four 1,952-byte keys filled with
`01`, `02`, `03`, `04` respectively. Use `n/t/f = 4/3/1` and the five policy
limits `60,60,5,64,32` in wire order. Fill UUID, genesis, nonce, tip hash,
anchor hash, observation hash and reference hash with hex bytes `11,22,33,44,55,66,77`
respectively. Set generation/epoch to `1/7`, heights in wire order to
`130,90,115,125`, and start/end/observed times to `1800000000,1800000060,1800000030`.
For the first key, the expected hex outputs are:

```text
policy_id    dd62157cafd49d714504526897585e80819083da0c2d6d5727be3c3bc105c0bf
context_id   71ed68a51e926b02f9a982866c7a8fe81abd3cbb53298548c2fa29263d0db18d
statement_id 04a4aca6bb9ed1b5d40bac4ca0df026ace440fb8d06e27ff0ea26f26fdff4dbc
SHA3-256(M)  c1b18a6867359df3a279f621cfd441e4b0799bdea12a49c9199587dc67317d8b
```

The last digest checks the signature input bytes. Signature interoperability
also requires a valid ML-DSA-65 signature over the raw message.

### Cumulative work

Do not include cumulative work in the initial signed v1 statement. Display any
locally computed work separately as a diagnostic. If a future format signs it,
bind its encoding/context and independently recompute it; the value still cannot
authorize recovery, rank conflicting evidence or bypass finalized history.

### Freshness, replay and rotation

An active incident manager would require both an open, receiver-owned nonce/context and the configured time checks.
Use a local monotonic deadline to prevent wall-clock rollback extending an open
collection. If time is unreliable, classify freshness as unknown and refuse a
ready plan. Restart invalidates pending contexts; recollect with a new random
nonce. Stored evidence remains viewable but cannot silently become current.
Consumed/aborted contexts and conflicts are journaled; opening a new nonce does
not silently resolve an outstanding conflicting incident.

Policy/key changes invalidate pending collections/plans. Keys are provisioned
out of band; a signature from an old key does not auto-authorize its replacement.
Never combine generations. Restoring an old witness/receiver backup requires
explicit reconciliation of policy generation and incident history. These are
operator-tooling persistence requirements, not new chain state.

## 4. Deterministic equivocation and conflict handling

One key can contribute one vote per statement in an exact context. A witness
must persist its chosen statement before releasing the first signature. A retry
returns the recorded envelope. An unavailable or unreconciled journal requires
abstention. Another randomized signature for the same statement adds no vote.
Two authenticated statements by the same key in that context disagreeing at B
or R establish equivocation. Different keys voting for different histories
show dissent. Report both groups with their signers. A minority alone cannot
veto a quorum of distinct signers who have not equivocated.

Any authenticated equivocation freezes QRE plan readiness for that incident,
even if a remaining apparent quorum exists. This intentionally permits a faulty
member to force human review; it does not promise liveness. Never silently
remove the member and recalculate t. Wrong-context data is not a valid vote;
retain bounded audit metadata without letting unauthenticated garbage fabricate
equivocation or trigger chain changes.

Show every authenticated group, including any conflicting quorums. Within a
valid fixed-height context two different quorums imply a double vote in the
intersection. Across rounds, different heights or new tips are separate
observations. An incident manager must compare ancestry, retain unresolved or
conflicting evidence, and require operator reconciliation before planning.
The offline verifier sees only files supplied together. Its result cannot
clear a prior incident hold or establish that other evidence was available.

## 5. Local validation, status and one confirmed recovery path

Keep evidence status separate from branch/plan status:

```
Evidence: QUORUM VERIFIED — 5 of 7 configured keys, context X, expires at T
Branch:   UNVALIDATED / VALIDATING / DATA UNAVAILABLE / VALIDATED / INVALID
Plan:     NOT READY / READY FOR OPERATOR REVIEW / STALE / BLOCKED
Action:   No rollback performed. Explicit operator confirmation required.
```

`QUORUM VERIFIED` in the offline tool means a threshold agreed on one
statement at inspection time with no observed double vote in the supplied
snapshot. A majority-chain, funds-safety or recovery claim would need different
evidence. `BRANCH UNVALIDATED` cannot become a ready plan because signatures pass.
Status/RPC reading and evidence submission must have no chain-mutation side effects.

### Validate the branch and display the retained target

Fetch bounded candidate blocks and transactions into isolated scratch state
derived from verified shared history, or replay from genesis. Apply Core's
consensus checks at each height, including parent-derived height, block IDs,
PoW/difficulty, signatures, sizes, timestamps, versions, fees/rewards, referenced
outputs, spentness and all applicable loaded checkpoints. Fetching and validation
cannot insert blocks into the active chain. Missing bytes or exhausted local
resources give `DATA UNAVAILABLE` and allow a retry for the same reference. A
proven consensus violation gives `INVALID`. Neither result permits a plan.

Verify the local snapshot and trace both histories back to their last common
block. Record its locally derived height `L` and ID. The signed observation
block at height `B` must lie on the candidate path to the exact signed
reference at height `R`. Both histories must contain the context's anchor.
Require `L < B` and `R >= B + 10` using widened arithmetic. An observation at
or below the split would also describe the receiver's chain. If one history is
a prefix of the other, report that relationship and leave ordinary sync alone.
Shallow forks remain with ordinary fork choice. A fork warning supplies neither
an LCA nor permission to remove a block.

For an active warning, establish independently that the first differing block
at `L + 1` meets the finality-refusal predicate at the pinned local snapshot.
An unrelated warning cannot qualify an ordinary branch for recovery.
Show the original local tip, retained block
`L` (height and ID), number of local blocks to discard, observed block `B`,
approved destination `R` (heights and IDs), expiry and the effects of detaching
local history. Reject a retained target in the effective protected checkpoint
zone, including equality with its highest loaded checkpoint. Entries above or
below `L` in a warning snapshot cannot substitute for this calculation.

### Confirm and reconcile one exact plan

A future assisted CLI would submit `resync_to_majority --confirm-plan ID`.
The corresponding unrestricted RPC would send a dedicated plan-confirmation
field with the same ID and omit the legacy boolean. Neither form may carry
legacy `--confirm`, `yes` or `confirm=true`: older handlers recognize those
even alongside unrecognized fields. A client must fail on an unsupported server
and never retry with a legacy confirmation. The ID identifies an immutable plan binding the displayed fields,
network and database snapshot, context and statement, evidence and validation
digests, policy and effective checkpoint-set digests. Assisted clients must
always supply it. Missing, malformed, unknown or stale IDs in assisted requests
cannot fall back to bare manual recovery. An operator can separately invoke the
ordinary manual command without witness evidence. A future integration that
strengthens that path must apply the same locally derived target and checkpoint
guards and document the resulting change in admission. Today's bare command
uses the warning-derived target described in the audit.

Before the first pop, pin the validated blocks and transactions through `R`
locally, preserve a recoverable copy of the displaced local suffix and verify
capacity and integrity. Under a single recovery writer, recheck the active
warning, exact tip, plan inputs, expiry and conflict state. Durably record the
confirmed plan and intended transition before modifying the active chain.
If any precondition fails, leave the original tip intact. Fetching missing data
from peers after the first pop cannot be an execution prerequisite.

Keep ordinary tip writers fenced across the transition, including on restart.
If execution is interrupted, first reconcile the durable intent with the
actual chain and staged data. Distinguish unchanged original state, an
identified partial transition, and the completed approved prefix. If the state
is ambiguous, data is lost or the policy acquires a new conflict, hold for
operator reconciliation. Expiry before the first mutation cancels approval.
Expiry during a partial transition cannot release the fence or authorize
another destination. A duplicate confirmation returns the recorded progress
or outcome. It cannot initiate a second detach or select another plan.

To record success, verify the installed tip is exactly `R`, with the signed
block at `B` and the retained block at `L`, then durably mark completion before
releasing ordinary sync. The confirmation covers that prefix only. Later
descendants follow normal consensus independently of this observation.

The shipped command provides no such staging, binding or restart contract.
Keep plans non-executable until the existing confirmed path demonstrates these
properties without changing consensus or adding a second adoption engine.

The witness service's signing path must validate what it attests and persist
same-context observations before releasing signatures. It must not sign arbitrary
caller-provided digests or treat a remote RPC claim as full local validation.
Key custody, intake authentication/rate limits, record retention and crash handling
need implementation review. Witness observations do not authorize external service
settlement; exchanges still pause/reconcile deposits and withdrawals manually.

## 6. Acceptance tests for verification and future recovery

Exercise ingestion, verification, inspection and status against real Core state.
Assert unchanged active chain tip/height, chain database, pool, miner state and
warning-derived target, and **zero calls** to mutating recovery APIs. Keep
evidence-journal and isolated scratch writes outside the active chain database.
Status reads must also leave the evidence journal unchanged.

| Test group | Required result |
| --- | --- |
| Existing boundary and PoW regressions | Test depth ten/eleven at candidate admission, young chains and promotion of a previously admitted alternative. No ordinary switch may invoke QRE. |
| Malformed/oversized evidence | All truncation lengths, length/count overflow, duplicate fields/signers/keys, trailing bytes, unknown version/suite, bad signature and wrong key reject; no state mutation. |
| Replay/domain/context | Wrong network/genesis, policy/generation, local tip, nonce, epoch, expired/future window, clock rollback and restored/restarted context cannot create a ready plan or invoke/steer rollback. |
| Threshold | 0, t-1, exactly t, n; duplicated identities and repeated signatures do not inflate count. Any-of-N DNS checkpoint evidence cannot pass as QRE. |
| Equivocation/conflict | Growing witness tips yield the same fixed-height vote. A single signer contradicting either hash in one context blocks the snapshot. Distinct minority signers are reported. A future collector must also preserve holds across restarts. |
| Partitions/rosters | 3/3/offline under 5/7 holds; disjoint local policies remain explicitly subjective; no auto-convergence or threshold reduction. |
| Branch validation | A valid quorum can coexist with missing block or transaction data (`DATA UNAVAILABLE`) or invalid PoW, timestamp, signature, transaction, spend, reward, size or checkpoint (`INVALID`). Both block planning. Restoring missing bytes permits revalidation of the same reference. |
| Claimed-height manipulation | Coinbase/parent mismatch, alternate-parent ancestry, accumulated warning snapshots and LCA off-by-one cannot alter target; derive target only from validated chains. |
| Checkpoint boundary | Shared manual/assisted recovery guards reject retained targets below or equal to the highest loaded checkpoint, even if the next candidate block is above it. Test the immediately higher target and DNS/file checkpoint changes after preparation. |
| Manual availability | With QRE disabled, absent or insufficient, a deliberate bare command can proceed when independently derived manual guards pass. Missing confirmation, inactive warning or restricted RPC refuses recovery. |
| Plan/execution race | Change one bound input, remove the warning, expire approval or import a conflict between display and first mutation. Each invalidates the assisted request with zero pops. Competing confirmations cannot both acquire the writer. |
| Exact command/RPC behavior | Assisted CLI and RPC require the displayed ID. Exercise old servers, omitted/malformed/stale IDs and blocked downgrade retries; each leaves the original tip intact. Verify retained L, observed B and exact destination R before success, even if a peer advertises a descendant or another fork. |
| Failure/retry/durability | Lose the last supplying peer before/after complete staging. Exhaust disk or fail a write before intent, during detach/apply or at completion. Interrupt at each durable boundary, restart and repeat confirmation. Require original state, exact verified completion or an explicit fenced reconciliation state, with no second detach or foreign-chain sync. |
| Wallet/service adjacent paths | Existing detach/rescan notifications and transaction/account state remain coherent; no automatic payment re-send, deposit credit or withdrawal resume. |

The audit dates the earlier Core test results. The [verifier guide](QRE_OFFLINE_VERIFIER.md)
identifies the executable coverage in this PR. Checks involving a live incident
manager, branch validation, storage failure or chain mutation remain acceptance
criteria for a future implementation.

## 7. Scope and possible follow-up work

This PR includes the audit, protocol design, and a standalone offline verifier
with tests. The verifier has no daemon endpoint. Existing nodes and wallets
need no migration. The operator chooses the policy and expected challenge.

Witness enrollment, durable collection and conflict history, isolated branch
validation, and exact-plan manual recovery each need implementation and review
before an operator can use the full workflow. Orphan-transaction salvage and
automatic chain adoption are outside the proposal.
