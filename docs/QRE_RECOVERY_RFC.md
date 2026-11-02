# RFC: Quorum Recovery Evidence for explicit operator recovery

Status: **PR 1, design/docs only**. No consensus, daemon, wallet, RPC, storage,
mining or build changes. No parser/verifier implementation in this PR.

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
normal consensus / unchanged PoW and first-seen finality
  -> deep fork rejected; diagnostic conflict reported
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
   unchanged. More cumulative work never authorizes a deep reorg.
2. QRE never participates in block/transaction validity, difficulty or ordinary
   fork choice. `FinalityForkState` stays operator-messaging state.
3. No evidence, absent/insufficient quorum, malformed input, stale context,
   conflict or verification failure changes the chain, warning target, pool,
   miner state or existing manual recovery availability.
4. A quorum authenticates observations only. All branch data required for a
   prepared plan must pass local validation; no supplied height, header, peer
   message, witness statement or evidence bundle determines the rollback target.
5. Conflicting evidence or unresolved ancestry means no ready plan and no
   QRE-assisted recovery. A manual incident decision remains an explicit human
   action, subject to the same chain/checkpoint guards.
6. No rollback into the effective protected checkpoint zone. Check the actual
   retained target, including equality, under the lock used for recovery.
7. The node never silently changes chains. `resync_to_majority` remains
   operator-confirmed. QRE status is not a confirmation flag or standing consent.
8. A changed tip, policy, checkpoint set, validation context or new conflict
   invalidates a displayed plan. Fail closed and show the reason.

Items 4 and 6 are future integration requirements. The upstream audit documents
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
| Temporary 51% hashpower | Normal finality refusal remains. Work or a work advantage never substitutes for evidence, local validation or confirmation. |
| Private deep fork | Reject in normal consensus. Even a consensus-valid staged fork cannot trigger recovery by itself. |
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
| Malicious divergence-height manipulation | Derive actual LCA from validated ancestry and compare every claimed value. Mismatch rejects the candidate for planning. |
| Different operators/witness sets | Distinct policies may produce incompatible conclusions indefinitely. No protocol-wide federation or global-majority proof is implied. |

## 3. Signed evidence: proposed format for review

This is a candidate schema, not an activated or frozen wire format. Any later
implementation would need canonical encoding vectors and rejection tests before
any intake is wired.
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
| Window start/end | Fixed UTC collection interval selected by the receiver, constrained by its configured maximum duration; not witness-controlled indefinite validity. |

`context_id = SHA3-256("discrete-qre-context-v1" || canonical_context)`.
Public local-tip data may reveal operational timing to witnesses; use explicit
operator configuration and avoid including account, balance, wallet or key data.

### Observation statement and signer envelope

| Field | Purpose / verification rule |
| --- | --- |
| Context ID | Exact match to the locally opened, unused context. |
| Claimed divergence height and last common ancestor hash | Signed assertion for audit; must later equal the LCA independently computed from fully validated branch data. Never copied into rollback state. |
| Observed checkpoint height/hash | Exact block ID on the witness's validated history, past that witness's local finality boundary. A witness must check `height + 10 < chain_length` in widened arithmetic. |
| Candidate reference tip height/hash | A fixed branch reference useful for local validation; may be older than a witness's moving head. Witness confirms it is on its validated branch and has enough depth beyond the observed checkpoint. |
| Witness observation time | Signed UTC instant within the requested interval; receiver also checks its own collection deadline, maximum age and bounded clock skew. A signature is not a trustworthy clock. |
| Witness key ID | Full 32-byte SHA3-256 commitment with a separate `discrete-qre-key-v1` domain to the pinned full ML-DSA public key. Reject duplicate public keys/IDs; no short fingerprint authority. |
| Signature | Covers the complete canonical context, statement, observation time and key ID with the observation domain. No unsigned field can alter interpretation. |

The common **statement ID** hashes context ID, divergence/LCA, observed
checkpoint and candidate reference tip under `discrete-qre-statement-v1`.
Threshold counts distinct pinned keys on one exact statement ID; per-witness
observation times/key IDs/signatures need not be identical. Multiple observations
by one key never add votes. Authenticate the full envelope before counting.

Proposed encoding rules: fixed field order; unsigned fixed-width little-endian
integers (heights uint32; epoch/timestamps uint64); 32-byte raw hashes/nonces;
ASCII domains without NUL; explicit bounded counts; sorted distinct key IDs;
no optional ignored fields, alternate integer encodings or trailing bytes.
An implementation would need to freeze the complete field widths and policy
encoding, produce an independent cross-implementation transcript vector and
bound input before allocation/crypto. Suggested review bounds are n<=32,
a bundle<=256 KiB and bounded per-incident history/CPU. These are proposal
limits, not network rules.

### Cumulative work

Do not include cumulative work in the initial signed v1 statement. Display any
locally computed work separately as a diagnostic. If a future format signs it,
bind its encoding/context and independently recompute it; the value still cannot
authorize recovery, rank conflicting evidence or bypass finalized history.

### Freshness, replay and rotation

Require both an active local nonce/context and the configured time checks.
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

Compare authenticated observations for the same full key and exact context:

1. Byte-identical statement with another randomized signature is a duplicate.
2. Different signed hashes asserted at an identical checkpoint/tip/LCA height
   prove incompatibility. Report `WITNESS EQUIVOCATION`, both signed envelopes,
   key ID, context and the contradictory height/hash values.
3. Different heights are not automatically equivocation. If locally validated
   ancestry shows incompatible branches, report equivocation with that ancestry
   evidence. If ancestry is insufficient, report `COMPATIBILITY UNRESOLVED` and
   hold planning; do not falsely accuse a witness or assume compatibility.
4. Observations proved to be consistent prefixes/descendants are retained as
   updates; still count at most one vote per key per exact statement. They do
   not authorize switching statement groups automatically.

Any authenticated equivocation freezes QRE plan readiness for that incident,
even if a remaining apparent quorum exists. This intentionally permits a faulty
member to force human review; it does not promise liveness. Never silently
remove the member and recalculate t. Wrong-context data is not a valid vote;
retain bounded audit metadata without letting unauthenticated garbage fabricate
equivocation or trigger chain changes.

Multiple quorum statement groups must be shown together. Incompatible groups
produce `CONFLICTING QUORUM EVIDENCE`. If compatibility cannot be locally proved,
hold. Even compatible groups require an explicit operator-selected reference
for planning rather than an implicit height/work tie-break. Seeing only one
quorum does not prove that another was not withheld during an eclipse.

## 5. Local validation, status and one confirmed recovery path

Keep evidence status separate from branch/plan status:

```
Evidence: QUORUM VERIFIED — 5 of 7 configured keys, context X, expires at T
Branch:   UNVALIDATED / VALIDATING / VALIDATED / INVALID
Plan:     NOT READY / READY FOR OPERATOR REVIEW / STALE / BLOCKED
Action:   No rollback performed. Explicit operator confirmation required.
```

`QUORUM VERIFIED` means valid, current, nonconflicting observations under the
local policy; it does not mean majority-chain proof, funds safety or successful
recovery. `BRANCH UNVALIDATED` cannot become a ready plan because signatures pass.
Status/RPC reading and evidence submission must have no chain-mutation side effects.

Before preparation, fetch bounded full candidate data through a separate
inspection path that does not insert rejected blocks into the active chain or
weaken its finality checks. Use existing consensus validation against isolated
scratch state derived from validated local history, or replay from genesis.
Validate ancestry, parent-derived heights, exact block IDs, PoW/difficulty,
signatures, block/transaction structure, timestamps, applicable versions,
rewards/fees, referenced outputs, spentness and every loaded checkpoint. The
candidate reference tip must contain the observed checkpoint at the claimed
height; that checkpoint must be past depth ten in the locally validated branch.

Compute the actual main-chain LCA from this validation. Compare all signed
divergence/anchor/checkpoint/tip assertions to locally derived data. Reject any
mismatch. A normal prefix or shallow fork uses existing sync/fork choice, not
recovery. A checkpoint conflict or unavailable transaction/state data means hold.
"As far as possible" validation means explicitly reporting what is missing;
it never permits a partially validated executable plan.

The displayed plan binds at least local tip/database state, validated LCA/target,
candidate checkpoint/tip, exact evidence/validation digests, policy and effective
checkpoint-set digests, discard depth, expiry, and orphaned-history impact.
The retained target must be outside the protected checkpoint zone. A warning's
aggregate `divergenceHeight` is an input to investigation, not the plan target.

Prefer extending **`resync_to_majority --confirm`** with optional `--plan-id`
binding (RPC equivalent explicitly confirmed), using its existing core recovery
path. No new QRE rollback function or automatic invocation. Bare manual recovery
remains available without QRE, but must pass the same locally derived target and
checkpoint guards; absence of QRE is not itself a reason to disable it.

Under the existing recovery lock, a future implementation must recheck plan/tip,
policy, checkpoints, expiry and conflict status before the first pop. Stale state
invalidates approval. The shared path must bind synchronization to the approved,
locally validated branch and verify the resulting checkpoint/tip before reporting
success. More work must never replace that binding. It must preserve rollback
evidence and resolve crashes/retries without silently continuing on another branch.

**Implementation gate:** today's confirmed path does not provide these guarantees.
Any later implementation would need separate review of its shared guards and
expected-branch checks. If that integration cannot be qualified without changing
consensus semantics, ship evidence/status/inspection only and keep plans
non-executable. Do not solve
the gap by adding an automatic second adoption engine. Document any intentional
change to manual admission behavior and test the exact confirmed command/RPC.

The witness service's signing path must validate what it attests and persist
same-context observations before releasing signatures. It must not sign arbitrary
caller-provided digests or treat a remote RPC claim as full local validation.
Key custody, intake authentication/rate limits, record retention and crash handling
need implementation review. Witness observations do not authorize external service
settlement; exchanges still pause/reconcile deposits and withdrawals manually.

## 6. Required tests before implementation

Define the negative oracle first: evidence ingestion/verification/status must
leave chain tip/height, database contents, pool and warning-derived rollback
target unchanged, and make **zero calls** to mutating recovery APIs. Future
integration tests must assert this on real Core state, not just mock return codes.

| Test group | Required result |
| --- | --- |
| Existing boundary and PoW regressions | Depth ten allowed/eleven refused outside checkpoint rules; young-chain and shallow switches preserved; high-work private fork cannot invoke recovery. |
| Malformed/oversized evidence | All truncation lengths, length/count overflow, duplicate fields/signers/keys, trailing bytes, unknown version/suite, bad signature and wrong key reject; no state mutation. |
| Replay/domain/context | Wrong network/genesis, policy/generation, local tip, nonce, epoch, expired/future window, clock rollback and restored/restarted context cannot create a ready plan or invoke/steer rollback. |
| Threshold | 0, t-1, exactly t, n; duplicated identities and repeated signatures do not inflate count. Any-of-N DNS checkpoint evidence cannot pass as QRE. |
| Equivocation/conflict | Same-height conflicts, differing-height incompatible ancestry, unresolved ancestry, duplicate randomized signatures and compatible growing tips produce the specified distinct statuses. Conflicts persist across retries/restarts. |
| Partitions/rosters | 3/3/offline under 5/7 holds; disjoint local policies remain explicitly subjective; no auto-convergence or threshold reduction. |
| Signed invalid branch | Valid quorum over unknown/missing parent, false LCA, bad timestamp, insufficient PoW, wrong signature, invalid tx/spentness/reward/size/checkpoint cannot arm a plan or steer a rollback. |
| Claimed-height manipulation | Coinbase/parent mismatch, alternate-parent ancestry, accumulated warning snapshots and LCA off-by-one cannot alter target; derive target only from validated chains. |
| Checkpoint boundary | All confirmed recovery entry points reject retained targets below or equal to the highest effective checkpoint, including a candidate just above it; include DNS/file checkpoint changes after plan creation. |
| Manual availability | QRE disabled/absent/insufficient leaves ordinary manual recovery available under the shared validation/checkpoint guards; missing confirmation and restricted RPC still refuse. |
| Plan/execution race | Changed local tip, candidate, policy, checkpoint set, expiry or new conflict invalidates plan under lock before any pop. Operator confirms the exact displayed plan. |
| Exact command/RPC behavior | Status/import alone never invokes recovery; explicit confirmed existing path reaches only the validated target/branch; malformed `--plan-id` never falls back to unbound recovery. |
| Failure/retry/durability | Fetch/validation failure is read-only; disk full, failed writes, process death at each recovery phase, restart and repeated confirmation cannot silently double-execute or resume arbitrary sync. |
| Wallet/service adjacent paths | Existing detach/rescan notifications and transaction/account state remain coherent; no automatic payment re-send, deposit credit or withdrawal resume. |

Existing finality/chain/PoW/DNS suites pass at the audited revision. The new QRE,
recovery-command, hostile-branch and durability tests above are **requirements**,
not tests implemented or passed by this docs-only proposal. Native signature
unit tests alone cannot establish any recovery execution claim.

## 7. Scope and possible follow-up work

**This proposal alone:** audit, evidence-only RFC, threat model and test plan.
No source/build changes, runtime interfaces, hard fork, migration or operational
action. Existing manual confirmation and consensus remain exactly as shipped.

**A possible separate implementation, if requested after review:** bounded
parsing/signature/context verification, witness observation tooling and
status/RPC/plan inspection. It would be optional, disabled by default and
configured locally, with no network-wide roster. Any executable integration
would require the existing explicitly confirmed recovery path and separately
reviewed shared guards and branch validation/binding. It could not silently add
automated QRE-authorized rollback. The canonical operator guide would need
updating in its own repository only for behavior actually shipped.

**A separate optional idea, only if requested:** orphan-transaction salvage.
It would need its own threat model, implementation and tests and is excluded
from this proposal and any initial evidence tooling. Its review would cover
coinbase exclusion, normal post-recovery transaction validation, conflicts,
missing dependencies, bounded/idempotent retries and rebroadcast privacy.
No automatic re-signing, replacement payments or promises of restored balances.

These possible follow-ups are discussion topics, not approved work or a
commitment to produce two additional pull requests. Scope and authorization
would be decided separately after maintainers review this proposal.

Old nodes/wallets need no changes for PR 1. Proposed operator evidence does not
change the validity of any block and requires no on-chain bytes. A later mandatory
witness set or automatic finality override would change the trust model and must
be a separate proposal, not a hidden extension of this one.

Maintainer decisions before code: accept the evidence-only scope; select the
policy/format/freshness limits; choose the minimum local branch-inspection path;
agree the shared manual recovery guard and exact-plan execution contract; define
key enrollment/rotation and persistence requirements. Do not implement the
mutating portion until its required negative tests and invariants are agreed.
