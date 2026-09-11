"""Owner lifecycle backed by independently anchored, complete encrypted snapshots.

The external stream and its pinned client profile belong outside this directory's
backup domain. A process loads ONLY the full snapshot committed by the fresh
external head. Leftover working databases are never authoritative. Publication is
snapshot fsync -> signed Pending fsync -> external CAS -> exact head confirmation.
Historical restoration instead appends a new permanently protective checkpoint.

This is a rollback detector, not distributed atomicity between CAS and a chain.
An unavailable anchor stops this mode. Keep ordinary protective backups and their
keys independently; an offline protective restore remains a separate procedure.
"""
import hashlib
import os
from pathlib import Path
import sqlite3
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .anchor import AnchorConflict, AnchorError, MAX_WIRE, _from_checkpoint
from .common import SessionLock, canonical, new_private_file, private_read, strict_json, sync_directory
from .lifecycle import Owner
from .lifecycle_store import OwnerStore, MAX_CONTAINER


MAX_SNAPSHOTS = 4096
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
BINDING_FIELDS = {'version', 'service_id', 'stream_id', 'writer_public_key'}


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _atomic_new(path, raw):
    """Publish immutable private bytes; no existing file may be replaced."""
    path = Path(path)
    temporary = path.with_name('.stage-' + uuid.uuid4().hex)
    new_private_file(temporary, raw)
    try:
        os.link(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink()
        sync_directory(path.parent)


def _binding(client):
    return dict(version=1, service_id=client.service_id, stream_id=client.stream_id,
                writer_public_key=client.writer_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())


def _logical_fingerprint(owner, companion=None):
    """Hash every persisted schema/row without SQLite's physical page counters.

    The digest stays in memory. Dumps contain encrypted records and are never
    retained or logged. No status, signature, exposure or history is excluded.
    """
    digest = hashlib.sha256(b'discrete-owner-logical-state-v1\x00')
    def frame(raw):
        digest.update(len(raw).to_bytes(8, 'little'))
        digest.update(raw)
    for name, db in ((b'owner', owner), (b'companion', companion)):
        frame(name)
        frame(b'absent' if db is None else b'present')
        if db is None:
            continue
        if db.in_transaction:
            raise AnchorError('Checkpoint requires committed journal transactions')
        # These persistent format properties are not emitted by iterdump().
        frame(canonical([db.execute('PRAGMA ' + pragma).fetchone()[0]
                         for pragma in ('user_version', 'application_id', 'encoding')]))
        for line in db.iterdump():
            frame(line.encode('utf-8'))
    return digest.digest()


class _AnchoredLifecycle(Owner):
    """Route every lifecycle checkpoint through the same exact-state gate."""
    def __init__(self, *args, checkpoint_commit, **kwargs):
        self._checkpoint_commit = checkpoint_commit
        super().__init__(*args, **kwargs)

    def _checkpoint(self):
        return self._checkpoint_commit()


class AnchoredOwner:
    """An authoritative checkpoint coordinator for one already-provisioned stream."""
    def __init__(self, directory, key, daemon, foreign, wallet=None, foreign_wallet=None,
                 exchange_dir=None, backup_dir=None, offer=None, role=None, credentials=None,
                 durable_funding=False, anchor_client=None):
        self.directory = Path(directory).absolute()
        self.client = anchor_client
        self.key = key
        self.owner = self.lock = self.work = None
        self.head = None
        self._logical_accepted = None
        self.failed = False
        self.pending_path = self.directory / 'pending.json'
        self.accepted_path = self.directory / 'accepted.bin'
        self.snapshots = self.directory / 'snapshots'
        if anchor_client is None or type(key) is not bytes or len(key) != 32:
            raise ValueError('Independent checkpoint client and owner key required')
        if self.directory.is_symlink():
            raise ValueError('Anchored owner directory must not be a symlink')
        creating = offer is not None
        if creating:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            self.snapshots.mkdir(mode=0o700)
        elif not self.directory.is_dir() or not self.snapshots.is_dir() or self.snapshots.is_symlink():
            raise ValueError('Anchored owner directory absent or invalid')
        try:
            self.lock = SessionLock(self.directory / 'checkpoint-owner')
            self.binding = _binding(self.client)
            metadata = self.directory / 'anchor-binding.json'
            if creating:
                _atomic_new(metadata, canonical(self.binding))
            elif strict_json(private_read(metadata, MAX_WIRE)) != self.binding:
                raise ValueError('Owner checkpoint identity differs from the external profile')
            if creating:
                genesis = self.client.read()
                if genesis['sequence'] != 0:
                    raise AnchorConflict('Cannot initialize over an existing external owner history')
                self._accept(genesis)
            self.head = self._accepted()
            self._recover_pending()
            if self.client.read() != self.head:
                raise AnchorConflict('External head differs from the last locally accepted checkpoint')
            if not creating and self.head['sequence'] == 0:
                raise AnchorError('Owner initialization has no committed external snapshot')
            self.work = self._new_work()
            if not creating:
                raw = self._snapshot(self.head['commitment'])
                self._materialize_current(raw)
            options = dict(exchange_dir=exchange_dir, backup_dir=backup_dir,
                           checkpoint_sink=self._publish, durable_funding=durable_funding)
            if creating:
                options.update(offer=offer, role=role, credentials=credentials)
            elif role is not None or credentials is not None:
                raise ValueError('Existing anchored owner uses its retained identity')
            self.owner = _AnchoredLifecycle(self.work, key, daemon, foreign, wallet, foreign_wallet,
                                           checkpoint_commit=self._commit_current, **options)
            if creating:
                self.owner.store.once('freshness.binding', self.binding)
                self._commit_current()
            else:
                self._check_binding()
        except BaseException:
            self.close()
            raise

    def _new_work(self):
        path = self.directory / ('work-' + uuid.uuid4().hex)
        path.mkdir(mode=0o700)
        return path

    def _accepted(self):
        raw = private_read(self.accepted_path, MAX_WIRE)
        if len(raw) < 29:
            raise AnchorError('Local accepted checkpoint is incomplete')
        return strict_json(AESGCM(self.key).decrypt(raw[:12], raw[12:],
            b'discrete-owner-accepted-v1\x00' + canonical(self.binding)))

    def _accept(self, head):
        # Persist the authenticated local high-water mark BEFORE removing the
        # signed pending intent. Provider-only rollback must also fail closed.
        nonce = os.urandom(12)
        raw = nonce + AESGCM(self.key).encrypt(nonce, canonical(head),
            b'discrete-owner-accepted-v1\x00' + canonical(self.binding))
        stage = self.directory / ('.accepted-' + uuid.uuid4().hex)
        new_private_file(stage, raw)
        os.replace(stage, self.accepted_path)
        sync_directory(self.directory)

    def _snapshot(self, digest):
        if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Canonical anchored snapshot digest required')
        path = self.snapshots / (digest + '.backup')
        raw = private_read(path, MAX_CONTAINER)
        if _hash(raw) != digest:
            raise AnchorError('Current anchored snapshot missing or modified; possible storage rollback')
        OwnerStore._decode_backup(raw, AESGCM(self.key))
        return raw

    def _materialize_current(self, raw):
        # This path has just established exact fresh anchor equality. It is NOT
        # a historical restore and must not invent a recovery marker.
        owner, companion = OwnerStore._decode_backup(raw, AESGCM(self.key))
        new_private_file(self.work / 'owner.db', owner)
        if companion is not None:
            new_private_file(self.work / 'settlement.db', companion)
        # Fingerprint the exact authenticated pair BEFORE Owner construction:
        # a constructor may durably fill in a missing binding/configuration.
        owner_db = sqlite3.connect(self.work / 'owner.db', isolation_level=None)
        companion_db = None
        try:
            if companion is not None:
                companion_db = sqlite3.connect(self.work / 'settlement.db', isolation_level=None)
            self._logical_accepted = _logical_fingerprint(owner_db, companion_db)
        finally:
            if companion_db is not None:
                companion_db.close()
            owner_db.close()

    def _check_binding(self):
        if self.owner.store.get('freshness.binding') != self.binding:
            raise AnchorError('Snapshot belongs to another external checkpoint stream')
        recovery = self.owner.store.recovery_required()
        if recovery != self.head['recovery']:
            raise AnchorError('Owner recovery mode differs from the external checkpoint')
        if self.owner.session is not None and recovery != self.owner.session.journal.recovery_required():
            raise AnchorError('Paired journals disagree about protective recovery')

    def _pending(self):
        if not self.pending_path.exists():
            return None
        value = strict_json(private_read(self.pending_path, MAX_WIRE + 256))
        if type(value) is not dict or set(value) != {'version', 'pending', 'snapshot'} or type(value['version']) is not int or value['version'] != 1:
            raise AnchorError('Invalid retained external publication')
        if value['snapshot'] != value['pending'].get('checkpoint', {}).get('commitment'):
            raise AnchorError('Pending publication does not bind its snapshot')
        self._snapshot(value['snapshot'])
        return value

    def _recover_pending(self):
        value = self._pending()
        if value is None:
            return
        pending = value['pending']
        expected = _from_checkpoint(pending['checkpoint'])
        previous = pending['checkpoint']
        if self.head != expected and (previous['sequence'] != self.head['sequence'] + 1
                or previous['previous'] != self.head['record_hash']):
            raise AnchorConflict('Pending checkpoint does not follow the accepted local head')
        result = self.client.reconcile(pending)
        if result['status'] == 'not-committed':
            if self.head == expected:
                raise AnchorConflict('External history rolled behind a locally accepted checkpoint')
            # Only this exact, already durable stage may be submitted once.
            self.client.submit(pending)
            result = self.client.reconcile(pending)
        if result['status'] != 'committed' or result['head'] != expected:
            raise AnchorConflict('External history differs from the retained publication')
        self._accept(expected)
        self.head = expected
        self.pending_path.unlink()
        sync_directory(self.directory)

    def _fresh(self):
        if self.failed or self.owner is None or self.pending_path.exists():
            raise AnchorError('External checkpoint outcome unresolved; reopen before continuing')
        current = self.client.read()
        if current != self.head:
            raise AnchorConflict('External owner history advanced; this writer must reopen')
        self._check_binding()

    def _retain_snapshot(self, raw):
        # Bound storage without deleting user backups or silently pruning history.
        digest = _hash(raw)
        target = self.snapshots / (digest + '.backup')
        if target.exists():
            if self._snapshot(digest) != raw:
                raise AnchorError('Immutable snapshot differs')
            return digest
        entries = list(self.snapshots.iterdir())
        if (len(entries) >= MAX_SNAPSHOTS
                or any(p.is_symlink() or not p.is_file() for p in entries)
                or sum(p.stat().st_size for p in entries) + len(raw) > MAX_SNAPSHOT_BYTES):
            raise AnchorError('Checkpoint storage bound reached; no transaction was authorized')
        _atomic_new(target, raw)
        return digest

    def _publish(self, snapshot):
        if self.failed or self.pending_path.exists():
            raise AnchorError('Prior external publication remains unresolved')
        try:
            current = self.client.read()
            if current != self.head:
                raise AnchorConflict('External owner head changed before publication')
            raw = private_read(snapshot, MAX_CONTAINER)
            owner, companion = OwnerStore._decode_backup(raw, AESGCM(self.key))
            # Authenticate the snapshot's binding and recovery flag independently
            # of mutable in-memory objects before signing the opaque commitment.
            temporary = self.work / ('check-' + uuid.uuid4().hex + '.db')
            companion_path = self.work / ('check-companion-' + uuid.uuid4().hex + '.db')
            companion_db = None
            new_private_file(temporary, owner)
            try:
                if companion is not None:
                    new_private_file(companion_path, companion)
                    companion_db = sqlite3.connect(companion_path, isolation_level=None)
                with OwnerStore(temporary, self.key) as saved:
                    if saved.get('freshness.binding') != self.binding:
                        raise AnchorError('Checkpoint snapshot binding differs')
                    recovery = saved.recovery_required()
                    logical = _logical_fingerprint(saved.db, companion_db)
            finally:
                if companion_db is not None:
                    companion_db.close()
                self._remove_database(companion_path)
                self._remove_database(temporary)
            digest = self._retain_snapshot(raw)
            pending = self.client.prepare(current, digest, recovery)
            _atomic_new(self.pending_path, canonical(dict(version=1, pending=pending, snapshot=digest)))
            expected = _from_checkpoint(pending['checkpoint'])
            if self.client.submit(pending) != expected or self.client.read() != expected:
                raise AnchorConflict('Checkpoint publication lacks exact current readback')
            self._accept(expected)
            self.head = expected
            self.pending_path.unlink()
            sync_directory(self.directory)
            # Cache the actual published pair, never an assumed live equivalent.
            self._logical_accepted = logical
        except BaseException:
            self.failed = True
            raise

    def _logical_current(self):
        companion = None if self.owner.session is None else self.owner.session.journal.db
        return _logical_fingerprint(self.owner.store.db, companion)

    def _commit_current(self):
        try:
            if self.failed or self.owner is None or self.pending_path.exists():
                raise AnchorError('External checkpoint outcome unresolved; reopen before continuing')
            if self._accepted() != self.head or self.client.read() != self.head:
                raise AnchorConflict('External checkpoint differs from the accepted local head')
            if self._logical_accepted is not None and self._logical_current() == self._logical_accepted:
                self._check_binding()
                self._snapshot(self.head['commitment'])
                return self.snapshots / (self.head['commitment'] + '.backup')
            # The base implementation first writes the complete independent
            # backup, then publishes it. Bypass our subclass to avoid recursion.
            return Owner._checkpoint(self.owner)
        except BaseException:
            self.failed = True
            raise

    def step(self):
        self._fresh()
        try:
            result = self.owner.step()
            self._commit_current()
            return result
        except BaseException:
            self.failed = True
            raise

    def cancel(self):
        self._fresh()
        try:
            result = self.owner.cancel()
            self._commit_current()
            return result
        except BaseException:
            self.failed = True
            raise

    def status(self):
        self._fresh()
        return dict(self.owner.status(), externally_anchored=True,
                    checkpoint_sequence=self.head['sequence'], checkpoint_recovery=self.head['recovery'])

    def backup(self, destination):
        self._fresh()
        # Export the authoritative full snapshot, not uncommitted working files.
        _atomic_new(Path(destination).absolute(), self._snapshot(self.head['commitment']))
        return Path(destination)

    @classmethod
    def restore_offline(cls, snapshot, directory, key):
        """Explicit availability escape: new protective journals, never normal work.

        This does not advance the unavailable external stream or fence another
        running copy. It authorizes only the base Owner's qualified recovery
        actions on currently observed contracts, never funding/first disclosure.
        """
        result = Owner.restore(snapshot, directory, key)
        with OwnerStore(Path(directory) / 'owner.db', key) as restored:
            if restored.get('freshness.binding') is None or not restored.recovery_required():
                raise AnchorError('Offline recovery requires an authenticated anchored backup')
            restored.once('freshness.offline-recovery', True)
        return dict(result, externally_anchored=False, offline_protective=True)

    @classmethod
    def restore(cls, snapshot, directory, key, *, anchor_client):
        """Fence all older normal writers with a new protective checkpoint."""
        target = Path(directory).absolute()
        target.mkdir(mode=0o700, parents=True, exist_ok=False)
        (target / 'snapshots').mkdir(mode=0o700)
        obj = cls.__new__(cls)
        obj.directory, obj.key, obj.client = target, key, anchor_client
        obj.owner = obj.lock = obj.work = None
        obj.failed = False
        obj._logical_accepted = None
        obj.pending_path, obj.snapshots = target / 'pending.json', target / 'snapshots'
        obj.accepted_path = target / 'accepted.bin'
        try:
            obj.binding = _binding(anchor_client)
            obj.lock = SessionLock(target / 'checkpoint-owner')
            obj.head = anchor_client.read()
            if obj.head['sequence'] == 0:
                raise AnchorError('Historical restore requires an established external history')
            _atomic_new(target / 'anchor-binding.json', canonical(obj.binding))
            obj._accept(obj.head)
            obj.work = target / ('work-' + uuid.uuid4().hex)
            # Restore authenticates both journals and marks each protective.
            Owner.restore(snapshot, obj.work, key)
            def offline(*_):
                raise ValueError('Historical restore cannot contact a wallet or chain')
            obj.owner = _AnchoredLifecycle(obj.work, key, offline, offline,
                checkpoint_sink=obj._publish, checkpoint_commit=obj._commit_current)
            if obj.owner.store.get('freshness.binding') != obj.binding or not obj.owner.store.recovery_required():
                raise AnchorError('Historical snapshot does not bind this protected stream')
            obj._commit_current()
            return dict(action='restored-protective', recovery_required=True,
                        externally_anchored=True, checkpoint_sequence=obj.head['sequence'], directory=str(target))
        finally:
            obj.close()

    @staticmethod
    def _remove_database(path):
        for suffix in ('', '-wal', '-shm', '.lock'):
            candidate = Path(str(path) + suffix)
            if candidate.exists() and candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()

    def close(self):
        if self.owner is not None:
            self.owner.close()
            self.owner = None
        if self.work is not None and self.work.exists():
            # Only this instance's fresh direct-child working directory is ours.
            if self.work.parent != self.directory or not self.work.name.startswith('work-') or self.work.is_symlink():
                raise ValueError('Refusing cleanup outside the private working directory')
            entries = list(self.work.iterdir())
            if all(p.is_file() and not p.is_symlink() for p in entries):
                for path in entries:
                    path.unlink()
                self.work.rmdir()
            self.work = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
