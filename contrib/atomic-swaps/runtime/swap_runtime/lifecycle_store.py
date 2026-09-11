"""Encrypted append-only state for one owner, under a lifetime OS writer lock.

Open and backup authenticate the full record chain; operations use the verified
in-memory state and check the authenticated database head. The chain/head detect
interior deletion, substitution, truncation and metadata tampering. Replacing
the entire store with a valid old copy is outside this local freshness model.

Values are canonical JSON, encrypted with AES-256-GCM. Labels, revision numbers,
immutability and ciphertext sizes are public metadata. ``once`` permanently pins
a label; ``put`` appends a revision; identical writes do nothing. ``batch`` commits
all label/value/pinning changes together. The config label is always immutable.

Backup accepts optional bytes of a consistent, already-locked Session SQLite
snapshot. The encrypted versioned container binds both snapshots and their sizes
and hashes. Restore publishes a NEW database only after authentication, full
chain verification and a durable sticky recovery marker. The owner coordinator
must enforce that marker; this storage primitive never transmits transactions.
"""

import hashlib
import os
from pathlib import Path
import re
import sqlite3
import struct
import tempfile
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .common import SessionLock, canonical, new_private_file, strict_json, sync_directory


MAX_VALUE = 262144
MAX_RECORDS = 100000
MAX_BATCH = 128
MAX_DATABASE = 64 * 1024 * 1024
MAX_CONTAINER = 2 * MAX_DATABASE + 8192
ZERO = '00' * 32
MAGIC = b'XDS-OWNER-BACKUP\x00\x01'
HEAD_AAD = b'xds-owner-store-head-v1'
RECORD_AAD = 'xds-owner-store-record-v1'


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _label(name):
    if type(name) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}', name) is None:
        raise ValueError('Bounded ASCII owner-state label required')


def _value(value):
    raw = canonical(value)
    if len(raw) > MAX_VALUE:
        raise ValueError('Owner-state value exceeds size bound')
    decoded = strict_json(raw)
    if canonical(decoded) != raw:
        raise ValueError('Canonical owner-state JSON required')
    return raw


def _sqlite_bytes(raw):
    if not isinstance(raw, bytes) or not 100 <= len(raw) <= MAX_DATABASE or raw[:16] != b'SQLite format 3\x00':
        raise ValueError('Bounded consistent SQLite snapshot required')
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(raw)
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite snapshot integrity failed')
    finally:
        db.close()


def _reserve(path):
    path = Path(path).absolute()
    new_private_file(path, b'')
    temporary = path.with_name(path.name + '.pending-' + uuid.uuid4().hex)
    new_private_file(temporary, b'')
    return path, temporary


def _publish(temporary, destination):
    with temporary.open('r+b') as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    sync_directory(destination.parent)


class OwnerStore:
    def __init__(self, path, key, create=None):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('Owner store requires a 32-byte encryption key')
        if create is not None and type(create) is not dict:
            raise ValueError('New owner store requires configuration mapping')
        self.path = Path(path).absolute()
        if self.path.is_symlink():
            raise ValueError('Owner database must not be a symlink')
        self.aead = AESGCM(key)
        self.lock = SessionLock(self.path)
        self.db = None
        self._state = {}
        self._head = None
        try:
            if create is not None:
                new_private_file(self.path, b'')
            elif not self.path.is_file():
                raise FileNotFoundError('Owner store absent; cannot infer unused funding or private secret')
            self.db = sqlite3.connect(self.path, isolation_level=None, timeout=15)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            if create is not None:
                self.db.executescript('''BEGIN IMMEDIATE;
                    CREATE TABLE owner_meta(id INTEGER PRIMARY KEY CHECK(id=1), encrypted BLOB NOT NULL);
                    CREATE TABLE owner_records(seq INTEGER PRIMARY KEY, name TEXT NOT NULL,
                      immutable INTEGER NOT NULL CHECK(immutable IN(0,1)), previous TEXT NOT NULL,
                      record_hash TEXT NOT NULL, encrypted BLOB NOT NULL);
                    CREATE TRIGGER immutable_record BEFORE UPDATE ON owner_records
                      BEGIN SELECT RAISE(ABORT,'owner record immutable'); END;
                    CREATE TRIGGER no_record_delete BEFORE DELETE ON owner_records
                      BEGIN SELECT RAISE(ABORT,'owner history immutable'); END;
                    CREATE TRIGGER no_meta_delete BEFORE DELETE ON owner_meta
                      BEGIN SELECT RAISE(ABORT,'owner metadata immutable'); END;
                    PRAGMA user_version=1;
                    COMMIT;''')
                self._head = {'version': 1, 'store_id': uuid.uuid4().hex, 'seq': 0, 'hash': ZERO, 'recovery': False}
                self.db.execute('INSERT INTO owner_meta VALUES(1,?)', (self._seal(canonical(self._head), HEAD_AAD),))
                self.once('config', create)
            self._audit()
            if 'config' not in self._state or not self._state['config'][1]:
                raise ValueError('Authenticated immutable owner configuration missing')
        except BaseException:
            self.close()
            raise

    def _seal(self, raw, aad):
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, raw, aad)

    def _open(self, encrypted, aad, maximum):
        if not isinstance(encrypted, bytes) or not 28 <= len(encrypted) <= maximum + 28:
            raise ValueError('Encrypted owner record size rejected')
        return self.aead.decrypt(encrypted[:12], encrypted[12:], aad)

    def _read_head(self):
        rows = self.db.execute('SELECT id,encrypted FROM owner_meta').fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise ValueError('Owner metadata missing or ambiguous')
        raw = self._open(rows[0][1], HEAD_AAD, 1024)
        head = strict_json(raw)
        if (type(head) is not dict or set(head) != {'version', 'store_id', 'seq', 'hash', 'recovery'}
                or canonical(head) != raw or type(head['version']) is not int or head['version'] != 1
                or type(head['seq']) is not int or not 0 <= head['seq'] <= MAX_RECORDS
                or type(head['recovery']) is not bool
                or type(head['store_id']) is not str or re.fullmatch('[0-9a-f]{32}', head['store_id']) is None
                or type(head['hash']) is not str or re.fullmatch('[0-9a-f]{64}', head['hash']) is None):
            raise ValueError('Owner authenticated head rejected')
        return head

    def _record_aad(self, head, seq, name, immutable, previous):
        return canonical([RECORD_AAD, head['store_id'], seq, name, immutable, previous])

    def _audit(self):
        if self.db.execute('PRAGMA page_count').fetchone()[0] * self.db.execute('PRAGMA page_size').fetchone()[0] > MAX_DATABASE:
            raise ValueError('Owner database size bound reached')
        if (self.db.execute('PRAGMA user_version').fetchone()[0] != 1
                or self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok'):
            raise ValueError('Owner database schema/integrity rejected')
        head, state, previous, count = self._read_head(), {}, ZERO, 0
        for seq, name, immutable, prior, recorded, encrypted in self.db.execute('SELECT * FROM owner_records ORDER BY seq'):
            count += 1
            _label(name)
            if seq != count or count > MAX_RECORDS or type(immutable) is not int or immutable not in (0, 1) or prior != previous:
                raise ValueError('Owner record chain gap or metadata mismatch')
            aad = self._record_aad(head, seq, name, bool(immutable), previous)
            raw = self._open(encrypted, aad, MAX_VALUE)
            value = strict_json(raw)
            if _value(value) != raw or _hash(aad + encrypted) != recorded:
                raise ValueError('Owner record authentication/hash mismatch')
            if name in state and ((state[name][1] and not immutable)
                    or ((state[name][1] or immutable) and state[name][0] != raw)):
                raise ValueError('Owner immutable record changed in history')
            state[name] = (raw, bool(immutable))
            previous = recorded
        if count != head['seq'] or previous != head['hash']:
            raise ValueError('Owner authenticated head differs from record history')
        self._head, self._state = head, state

    def _check_head(self):
        if self.db is None or self._read_head() != self._head:
            raise ValueError('Owner store changed outside its active writer')
        count, latest = self.db.execute('SELECT COUNT(*),COALESCE(MAX(seq),0) FROM owner_records').fetchone()
        if count != self._head['seq'] or latest != count:
            raise ValueError('Owner history was truncated or deleted')

    def _write_head(self, head):
        self.db.execute('UPDATE owner_meta SET encrypted=? WHERE id=1', (self._seal(canonical(head), HEAD_AAD),))

    def get(self, name, default=None):
        _label(name)
        self._check_head()
        return strict_json(self._state[name][0]) if name in self._state else default

    def once(self, name, value):
        self.batch([(name, value, True)])
        return self.get(name)

    def put(self, name, value):
        self.batch([(name, value, False)])
        return self.get(name)

    def batch(self, entries):
        if type(entries) is not list or not 1 <= len(entries) <= MAX_BATCH:
            raise ValueError('Bounded nonempty owner batch required')
        updates, staged = [], dict(self._state)
        for entry in entries:
            if not isinstance(entry, (tuple, list)) or len(entry) != 3:
                raise ValueError('Owner batch requires name, value and immutable flag')
            name, value, immutable = entry
            _label(name)
            if type(immutable) is not bool:
                raise ValueError('Owner immutability flag must be boolean')
            immutable = immutable or name == 'config'
            raw = _value(value)
            old = staged.get(name)
            if old is not None:
                if (old[1] or immutable) and old[0] != raw:
                    raise ValueError('Owner value is immutable')
                if old[0] == raw and (old[1] or not immutable):
                    continue
            staged[name] = (raw, immutable)
            updates.append((name, raw, immutable))
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._check_head()
            head = dict(self._head)
            if head['seq'] + len(updates) > MAX_RECORDS:
                raise ValueError('Owner record count bound reached')
            for name, raw, immutable in updates:
                seq = head['seq'] + 1
                aad = self._record_aad(head, seq, name, immutable, head['hash'])
                encrypted = self._seal(raw, aad)
                recorded = _hash(aad + encrypted)
                self.db.execute('INSERT INTO owner_records VALUES(?,?,?,?,?,?)',
                    (seq, name, int(immutable), head['hash'], recorded, encrypted))
                head.update(seq=seq, hash=recorded)
            if self.db.execute('PRAGMA page_count').fetchone()[0] * self.db.execute('PRAGMA page_size').fetchone()[0] > MAX_DATABASE:
                raise ValueError('Owner database size bound reached')
            if updates:
                self._write_head(head)
            self.db.execute('COMMIT')
            self._head, self._state = head, staged
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def recovery_required(self):
        self._check_head()
        return self._head['recovery']

    def _mark_recovery(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._check_head()
            head = dict(self._head, recovery=True)
            self._write_head(head)
            self.db.execute('COMMIT')
            self._head = head
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def _snapshot_bytes(self):
        self._check_head()
        self._audit()
        if self.db.execute('PRAGMA page_count').fetchone()[0] * self.db.execute('PRAGMA page_size').fetchone()[0] > MAX_DATABASE:
            raise ValueError('Owner database size bound reached')
        # A serialized WAL-mode database cannot be independently deserialized
        # without a WAL file. SQLite produces a complete DELETE-mode copy first.
        fd, name = tempfile.mkstemp(prefix='.owner-snapshot-', dir=self.path.parent)
        os.close(fd)
        copy = sqlite3.connect(name)
        try:
            self.db.backup(copy)
            copy.execute('PRAGMA journal_mode=DELETE')
            raw = copy.serialize()
        finally:
            copy.close()
            os.unlink(name)
        _sqlite_bytes(raw)
        return raw

    def backup(self, destination, companion=None):
        owner = self._snapshot_bytes()
        if companion is not None:
            _sqlite_bytes(companion)
        manifest = {'version': 1, 'owner_size': len(owner), 'owner_sha256': _hash(owner),
                    'companion_size': 0 if companion is None else len(companion),
                    'companion_sha256': None if companion is None else _hash(companion)}
        encoded = canonical(manifest)
        payload = struct.pack('<I', len(encoded)) + encoded + owner + (companion or b'')
        wire = MAGIC + self._seal(payload, MAGIC)
        # Validate the complete encrypted container before reserving publication.
        self._decode_backup(wire, self.aead)
        target, temporary = _reserve(destination)
        with temporary.open('wb') as stream:
            stream.write(wire)
            stream.flush()
            os.fsync(stream.fileno())
        _publish(temporary, target)
        return target

    @staticmethod
    def _decode_backup(wire, aead):
        if not isinstance(wire, bytes) or not len(MAGIC)+32 <= len(wire) <= MAX_CONTAINER or not wire.startswith(MAGIC):
            raise ValueError('Owner backup container/version rejected')
        sealed = wire[len(MAGIC):]
        payload = aead.decrypt(sealed[:12], sealed[12:], MAGIC)
        if len(payload) < 4:
            raise ValueError('Owner backup payload truncated')
        length = struct.unpack('<I', payload[:4])[0]
        if not 1 <= length <= 1024 or 4+length > len(payload):
            raise ValueError('Owner backup manifest size rejected')
        encoded = payload[4:4+length]
        manifest = strict_json(encoded)
        fields = {'version', 'owner_size', 'owner_sha256', 'companion_size', 'companion_sha256'}
        if type(manifest) is not dict or set(manifest) != fields or canonical(manifest) != encoded or type(manifest['version']) is not int or manifest['version'] != 1:
            raise ValueError('Owner backup manifest rejected')
        for name in ('owner_size', 'companion_size'):
            if type(manifest[name]) is not int or not 0 <= manifest[name] <= MAX_DATABASE:
                raise ValueError('Owner backup component size rejected')
        start, middle = 4+length, 4+length+manifest['owner_size']
        if middle+manifest['companion_size'] != len(payload):
            raise ValueError('Owner backup component boundaries rejected')
        owner, companion = payload[start:middle], payload[middle:] or None
        if (_hash(owner) != manifest['owner_sha256']
                or (None if companion is None else _hash(companion)) != manifest['companion_sha256']):
            raise ValueError('Owner backup component digest mismatch')
        _sqlite_bytes(owner)
        if companion is not None:
            _sqlite_bytes(companion)
        return owner, companion

    @classmethod
    def restore(cls, snapshot, destination, key):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('Owner store requires a 32-byte encryption key')
        source = Path(snapshot).absolute()
        if source.is_symlink() or not source.is_file() or source == Path(destination).absolute():
            raise ValueError('Distinct regular owner backup required')
        with source.open('rb') as stream:
            wire = stream.read(MAX_CONTAINER+1)
        owner, companion = cls._decode_backup(wire, AESGCM(key))
        destination_lock = SessionLock(destination)
        try:
            target, temporary = _reserve(destination)
            temporary.write_bytes(owner)
            with cls(temporary, key) as restored:
                restored._mark_recovery()
                restored._audit()
                restored.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                restored.db.execute('PRAGMA journal_mode=DELETE')
            _publish(temporary, target)
            return {'store_path': target, 'companion': companion}
        finally:
            destination_lock.close()

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if getattr(self, 'lock', None) is not None:
            self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
