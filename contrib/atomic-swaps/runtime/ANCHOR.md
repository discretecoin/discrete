# Independent owner checkpoints

`swap_runtime.anchor` provides one externally provisioned append-only stream for
one owner. It stores public identities, signatures and opaque SHA-256 commitments.
It receives no wallet database, spend key, wallet RPC credential or swap preimage.
Its separate TLS key authenticates the service only.

The checkpoint database, client profile and pinned service identity must remain
outside the owner's backup/restore domain. Keep the service on an independently
administered host or storage system whose monotonic history is protected. Rolling
back both the owner and this service is **not detected** by this implementation.
A copied local service beside a copied wallet does not satisfy this assumption.
The trusted provider can deny availability or lie about its history; TLS does not
remove that trust. This component does not make a blockchain broadcast atomic
with an external database update.

## Exact protocol and integration

`AnchorStore(path, *, service_id, stream_id, writer_public_key, create=False)`
holds an OS writer lock for its lifetime. Creation is exclusive; missing state
never initializes automatically. SQLite uses WAL and `synchronous=FULL`. Reopening
verifies the pinned profile, every retained signature, sequence, predecessor,
record hash, recovery transition and current head. It supports one stream and at
most 100,000 records / 128 MiB; exhausting a bound refuses further progress.

`AnchorClient(transport, *, service_id, stream_id, writer_key)` exposes:

- `read()` returns the current authenticated `Head`.
- `prepare(previous, commitment, recovery)` returns a signed `Pending` without I/O.
- `submit(pending)` makes one CAS request and returns only its exact current head.
- `reconcile(pending)` makes one fresh read and returns `{status, head}`. Status is
  `committed`, `not-committed` or `conflict`; a transport failure remains unknown.

`Head` has exactly `version:1`, `service_id`, `stream_id`, `sequence`, `record_hash`,
`commitment`, `recovery`. `Pending` has exactly `checkpoint` and `signature`.
Its checkpoint has exactly `version:1`, `service_id`, `stream_id`, `sequence`,
`previous`, `commitment`, `recovery`. IDs/hashes are 32-byte lowercase hex;
Ed25519 signatures are 64-byte lowercase hex. Sequence is a bounded integer;
recovery is a boolean and cannot change from true to false.

The signature covers `b'xds-external-checkpoint-v1\0' + canonical(checkpoint)`;
the record hash is SHA-256 of the canonical checkpoint. Canonical JSON sorts
keys, omits whitespace and rejects duplicate fields/nonfinite numbers. Genesis
has sequence zero, zero commitment and false recovery. Its record hash covers
canonical `['xds-anchor-genesis-v1', service_id, stream_id, writer_public_key]`.

Each transport request separately signs its operation, pinned identities, exact
pending payload and fresh random 32-byte nonce under
`b'xds-external-checkpoint-request-v1\0'`. The authenticated TLS response must echo
that nonce and both identities. An exact duplicate append is idempotent, but an
old entry after another advance is not accepted as authority to publish old
local state. There is no reset, force-CAS, unsigned append or retry loop.

The owner integration must durably stage the **complete** encrypted Owner and
Session state and its exact signed `Pending` before external CAS. The commitment
must bind both journals, including signed intents, funding plans and sticky
possible-disclosure state. Only matching fresh current external evidence allows
publication of that local snapshot and continuation of the separately validated
financial operation. Never generate a replacement transaction or checkpoint
because an acknowledgment was lost. A retained previous head permits only an
explicit retry of the same staged pending operation. A missing current snapshot,
remote rollback or different head must refuse ordinary progress.

Ordinary restart materializes only the exact authenticated current snapshot.
The owner also retains an AEAD-authenticated accepted head outside its mutable
working databases. After exact remote acceptance it durably replaces this local
head before removing the pending file. A remote head behind or different from
that retained acceptance refuses ordinary restart, even if an older snapshot is
still available. A lost response can recover only the exact retained successor;
an already accepted pending record cannot authorize replay into an older provider.
Historical restore must advance from the current remote head to a **new**
recovery=true checkpoint, preserving protective restrictions in both journals.
The anchor cannot reconstruct a missing pre-send snapshot or missing credentials.
The integration must repeat fresh-head and chain-admission checks before sending.
The remaining CAS-to-chain transmission gap must not be described as atomic.

Unchanged polling does not create another encrypted backup or external record.
Before reusing the current snapshot, the wrapper compares the complete logical
Owner and Session schemas/rows and persistent format versions, authenticates the
retained snapshot and accepted head, and reads the fresh external head. Changed
intents, signatures, status, history, recovery flags or exposure markers require
a new full checkpoint. The restart cache derives from the authenticated snapshot
before lifecycle construction, so constructor changes also need a checkpoint.
Storage remains bounded for actual state changes; no history is pruned.

## Private lab service setup

These are operator instructions, not an automatic deployment. Run as a dedicated
unprivileged service account with a private directory on the independent host.
Install the reviewed runtime and its pinned `requirements.txt` in a virtual
environment. The commands assume the current directory contains `swap_runtime/`.
Do not copy owner credentials to this host.

Create a private public-profile JSON file named `/srv/swap-anchor/profile.json`:

```json
{
  "version": 1,
  "service_id": "<independently generated 32-byte lowercase hex>",
  "stream_id": "<this owner's 32-byte lowercase hex>",
  "writer_public_key": "<owner checkpoint Ed25519 public key, 32-byte lowercase hex>"
}
```

The IDs/public writer must match the owner configuration. The owner supplies only
its checkpoint **public** key to this service. Provision the signing seed on the
owner host through the owner's key management flow; do not generate or send a
wallet spend key as a checkpoint service credential.

Generate a service TLS credential in the dedicated private directory, pin it
through a trusted administrative channel, and initialize the stream once:

```sh
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -noenc -days 365 -subj /CN=owned-checkpoint -keyout /srv/swap-anchor/tls.key -out /srv/swap-anchor/tls.pem
chmod 600 /srv/swap-anchor/profile.json /srv/swap-anchor/tls.key /srv/swap-anchor/tls.pem
openssl x509 -in /srv/swap-anchor/tls.pem -outform DER | openssl dgst -sha256
python -m swap_runtime.anchor init --database /srv/swap-anchor/history.db --profile /srv/swap-anchor/profile.json
python -m swap_runtime.anchor serve --database /srv/swap-anchor/history.db --profile /srv/swap-anchor/profile.json --certificate /srv/swap-anchor/tls.pem --tls-key /srv/swap-anchor/tls.key --port 9443
```

`serve` binds only `127.0.0.1`. An operator-controlled SSH tunnel can forward a
local owner port to the independent host's `127.0.0.1:9443`; authenticate and pin
the SSH host normally. Do not expose this serial reference HTTP service directly
to the public network. Service restarts use the same database and public profile;
never rerun initialization or restore an older anchor database to make an owner
backup appear current. Certificate renewal changes the exact DER pin and requires
an explicit independently authenticated profile update.

On the owner host, store an owner-only client profile **outside the owner
directory and its backup domain**:

```json
{
  "version": 1,
  "service_id": "<same service identity>",
  "stream_id": "<same stream identity>",
  "endpoint": "https://127.0.0.1:9443",
  "certificate_sha256": "<64 lowercase hex digits from the DER fingerprint>",
  "writer_key_file": "checkpoint.seed",
  "timeout": 5
}
```

`client_from_profile(path)` constructs the client without network I/O. The seed
file holds 32-byte lowercase hex, optionally followed by a newline. A relative
seed path resolves beside the profile. The seed never enters the public service
profile. `timeout` is optional, defaults to five seconds and accepts integers
1–60. Profile/key files must be regular owner-only files on POSIX; Windows ACLs
remain an operator responsibility. Do not place secrets in command arguments.

`PinnedHTTPS` creates a fresh TLS 1.2+ connection, checks the exact DER certificate
fingerprint and validity period **before sending** the signed request, ignores
environment proxies and follows no redirects. The exact certificate pin replaces
CA/hostname trust. Request/response bodies are limited to 4 KiB; socket operations
have bounded timeouts. Errors do not expose raw requests or RPC diagnostics.
An unavailable service stops normal progress. There is no local fallback.
An explicitly requested offline protective restore is a separate path: it
authenticates the backup, marks both journals permanently protective and permits
only qualified recovery of already known contracts. It does not advance the
external stream or fence another running copy. It cannot fund a new deposit or
make a first secret disclosure.

## Local qualification

```sh
python -B -m unittest discover -s tests -p test_anchor.py -v
```

The suite starts only temporary loopback HTTPS listeners and synthetic child
processes. It covers actual exits before/after SQLite commit, restart, OS locking,
competing CAS, current-head idempotency, lost HTTPS acknowledgment, nonce replay,
pin/expiry checks, strict profiles, input bounds and authenticated history damage.
It does not prove independent host administration, provider rollback resistance,
power-loss behavior of a particular disk, production availability or blockchain
broadcast atomicity. The owner integration has separate end-to-end tests.
