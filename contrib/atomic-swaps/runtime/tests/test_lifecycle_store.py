"""Owner storage integrity, atomicity, lock and backup/recovery tests, offline.

Abrupt exits use real child processes. No node, wallet key or network is used.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from swap_runtime.common import canonical
from swap_runtime.journal import Journal
from swap_runtime.lifecycle_store import MAGIC, MAX_VALUE, OwnerStore
import swap_runtime.lifecycle_store as store_module


KEY = bytes([37]) * 32  # Public deterministic laboratory fixture, not a wallet key.
SECRET = 'private-owner-secret-fixture-0123456789abcdef'


class OwnerStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-store-test-')
        self.root = Path(self.temp.name)
        self.path = self.root / 'owner.db'
        self.store = OwnerStore(self.path, KEY, create={'network': 'offline-test', 'secret': SECRET})
        self.opened = [self.store]

    def tearDown(self):
        for store in reversed(self.opened):
            store.close()
        self.temp.cleanup()

    def reopen(self, path=None):
        self.store.close()
        reopened = OwnerStore(path or self.path, KEY)
        self.opened.append(reopened)
        return reopened

    def count(self, store=None):
        return (store or self.store).db.execute('SELECT COUNT(*) FROM owner_records').fetchone()[0]

    def alter(self, sql, params=()):
        self.store.close()
        db = sqlite3.connect(self.path)
        try:
            db.execute(sql, params)
            db.commit()
        finally:
            db.close()

    def child(self, stage, *paths):
        result = subprocess.run([sys.executable, '-B', __file__, '--child', stage,
                                 *map(str, paths)], cwd=ROOT, timeout=20, capture_output=True,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors='replace'))

    def test_config_immutable_values_copied_and_plaintext_secrets_absent(self):
        config = self.store.get('config')
        config['secret'] = 'changed-copy'
        self.assertEqual(self.store.get('config')['secret'], SECRET)
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.store.put('config', config)
        self.store.put('secret-material', {'value': SECRET})
        on_disk = b''.join(p.read_bytes() for p in self.root.glob('owner.db*') if not p.name.endswith('.lock'))
        self.assertNotIn(SECRET.encode(), on_disk)
        self.assertFalse(self.store.recovery_required())

    def test_put_once_pin_transition_and_identical_noop_survive_restart(self):
        self.store.put('cursor', {'height': 10})
        count = self.count()
        with self.assertRaises(ValueError):
            self.store.once('cursor', {'height': 11})
        self.assertEqual(self.store.get('cursor'), {'height': 10})
        self.store.put('cursor', {'height': 10})
        self.assertEqual(self.count(), count)
        self.store.once('cursor', {'height': 10})
        self.assertEqual(self.count(), count + 1)
        self.store.once('cursor', {'height': 10})
        self.store.put('cursor', {'height': 10})
        self.assertEqual(self.count(), count + 1)
        reopened = self.reopen()
        with self.assertRaises(ValueError):
            reopened.put('cursor', {'height': 11})
        self.assertEqual(reopened.get('cursor'), {'height': 10})
        self.assertEqual(reopened.get('missing', 'default'), 'default')

    def test_atomic_cursor_public_proof_batch_and_immutable_failure(self):
        self.store.once('funding', {'txid': '01' * 32})
        self.store.batch([('cursor', 20, False), ('public-proof', {'txid': '02' * 32}, True)])
        self.assertEqual(self.store.get('cursor'), 20)
        self.assertEqual(self.store.get('public-proof'), {'txid': '02' * 32})
        count = self.count()
        with self.assertRaises(ValueError):
            self.store.batch([('cursor', 21, False), ('funding', {'txid': 'ff' * 32}, True)])
        self.assertEqual(self.store.get('cursor'), 20)
        self.assertEqual(self.count(), count)

    def test_batch_duplicate_label_cannot_bypass_new_pin(self):
        with self.assertRaises(ValueError):
            self.store.batch([('new-proof', 1, True), ('new-proof', 2, False)])
        self.assertIsNone(self.store.get('new-proof'))

    def test_labels_json_value_and_batch_bounds(self):
        for label in ('', '_reserved', 'a' * 129, 'не-ascii', 'with space'):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.store.put(label, 1)
        for value in ('x' * (MAX_VALUE+1), float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                self.store.put('invalid', value)
        for batch in ([], [('flag', 1, 1)], [('wrong-tuple', 1)], [('x', 1, False)] * 129):
            with self.assertRaises(ValueError):
                self.store.batch(batch)
        self.assertIsNone(self.store.get('invalid'))

    def test_missing_wrong_key_and_existing_create_fail_without_overwrite(self):
        self.store.close()
        before = self.path.read_bytes()
        with self.assertRaises(Exception):
            OwnerStore(self.path, bytes([38]) * 32)
        with self.assertRaises(FileExistsError):
            OwnerStore(self.path, KEY, create={'new': 'config'})
        with self.assertRaises(FileNotFoundError):
            OwnerStore(self.root / 'missing.db', KEY)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.reopen().get('config')['secret'], SECRET)

    def test_lifetime_single_writer_in_process_and_child_releases_after_close(self):
        with self.assertRaisesRegex(ValueError, 'already open'):
            OwnerStore(self.path, KEY)
        self.child('locked', self.path)
        self.store.close()
        self.child('open', self.path)
        self.assertEqual(self.reopen().get('config')['secret'], SECRET)

    def test_sql_triggers_block_record_change_and_delete(self):
        self.store.put('cursor', 1)
        for sql in ("DELETE FROM owner_records WHERE name='cursor'",
                    "UPDATE owner_records SET name='other' WHERE name='cursor'",
                    'DELETE FROM owner_meta'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.db.execute(sql)
        self.assertEqual(self.store.get('cursor'), 1)

    def test_ciphertext_tamper_is_rejected_on_reopen(self):
        self.store.put('proof', {'secret': SECRET})
        encrypted = self.store.db.execute("SELECT encrypted FROM owner_records WHERE name='proof'").fetchone()[0]
        self.store.db.execute('DROP TRIGGER immutable_record')
        changed = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        self.store.db.execute("UPDATE owner_records SET encrypted=? WHERE name='proof'", (changed,))
        self.store.close()
        with self.assertRaises(Exception):
            OwnerStore(self.path, KEY)

    def test_interior_deletion_is_detected_live_and_on_reopen(self):
        self.store.put('cursor', 1)
        self.store.put('cursor', 2)
        self.store.db.execute('DROP TRIGGER no_record_delete')
        self.store.db.execute('DELETE FROM owner_records WHERE seq=2')
        with self.assertRaisesRegex(ValueError, 'truncated or deleted'):
            self.store.get('cursor')
        self.store.close()
        with self.assertRaises(ValueError):
            OwnerStore(self.path, KEY)

    def test_truncation_cannot_match_authenticated_head(self):
        self.store.put('cursor', 1)
        self.store.db.execute('DROP TRIGGER no_record_delete')
        self.store.db.execute('DELETE FROM owner_records WHERE seq=2')
        self.store.close()
        with self.assertRaisesRegex(ValueError, 'head differs'):
            OwnerStore(self.path, KEY)

    def test_encrypted_head_tamper_cannot_reset_recovery_or_revision(self):
        encrypted = self.store.db.execute('SELECT encrypted FROM owner_meta').fetchone()[0]
        self.store.db.execute('UPDATE owner_meta SET encrypted=?',
                              (encrypted[:-1] + bytes([encrypted[-1] ^ 1]),))
        with self.assertRaises(Exception):
            self.store.recovery_required()
        self.store.close()
        with self.assertRaises(Exception):
            OwnerStore(self.path, KEY)

    def test_cross_store_record_substitution_is_rejected_even_with_same_key(self):
        other = OwnerStore(self.root / 'other.db', KEY, create={'network': 'offline-test', 'secret': SECRET})
        self.opened.append(other)
        foreign = other.db.execute('SELECT record_hash,encrypted FROM owner_records WHERE seq=1').fetchone()
        self.store.db.execute('DROP TRIGGER immutable_record')
        self.store.db.execute('UPDATE owner_records SET record_hash=?,encrypted=? WHERE seq=1', foreign)
        self.store.close()
        with self.assertRaises(Exception):
            OwnerStore(self.path, KEY)

    def companion(self):
        journal = Journal(self.root / 'session.db', KEY, create=True)
        try:
            journal.register('s', {'network': 'offline'})
            journal.prepare('s', 'foreign-refund', b'signed-offline-refund-fixture', 'fixture-txid')
            return journal.snapshot(self.root / 'session-snapshot.db').read_bytes()
        finally:
            journal.close()

    def test_wal_consistent_encrypted_backup_with_exact_companion_and_sticky_restore(self):
        self.store.batch([('cursor', 45, False), ('public-proof', {'secret': SECRET}, True)])
        companion = self.companion()
        snapshot = self.store.backup(self.root / 'backup.bin', companion=companion)
        original = snapshot.read_bytes()
        self.assertNotIn(SECRET.encode(), original)
        self.assertNotIn(b'SQLite format 3', original)
        self.store.put('cursor', 46)
        result = OwnerStore.restore(snapshot, self.root / 'restored.db', KEY)
        self.assertEqual(result['companion'], companion)
        with OwnerStore(result['store_path'], KEY) as restored:
            self.assertEqual(restored.get('cursor'), 45)
            self.assertEqual(restored.get('public-proof'), {'secret': SECRET})
            self.assertTrue(restored.recovery_required())
            restored.put('recovery', False)
            self.assertTrue(restored.recovery_required())
            second_snapshot = restored.backup(self.root / 'second.bin')
        with OwnerStore(result['store_path'], KEY) as restarted:
            self.assertTrue(restarted.recovery_required())
        second = OwnerStore.restore(second_snapshot, self.root / 'second-restored.db', KEY)
        with OwnerStore(second['store_path'], KEY) as restored:
            self.assertTrue(restored.recovery_required())
        self.assertFalse(self.store.recovery_required())
        self.assertEqual(snapshot.read_bytes(), original)
        self.assertEqual(self.store.get('cursor'), 46)

    def test_backup_and_restore_destinations_are_exclusive(self):
        snapshot = self.store.backup(self.root / 'backup.bin')
        original = snapshot.read_bytes()
        with self.assertRaises(FileExistsError):
            self.store.backup(snapshot)
        with self.assertRaises(Exception):
            self.store.backup(self.path)
        result = OwnerStore.restore(snapshot, self.root / 'restored.db', KEY)
        restored_bytes = result['store_path'].read_bytes()
        with self.assertRaises(FileExistsError):
            OwnerStore.restore(snapshot, result['store_path'], KEY)
        self.assertEqual(result['store_path'].read_bytes(), restored_bytes)
        self.assertEqual(snapshot.read_bytes(), original)

    def test_backup_container_key_ciphertext_and_version_tamper_are_rejected(self):
        snapshot = self.store.backup(self.root / 'backup.bin')
        with self.assertRaises(Exception):
            OwnerStore.restore(snapshot, self.root / 'wrong-key.db', bytes([38])*32)
        original = snapshot.read_bytes()
        for index, content in enumerate((original[:-1], original[:-1]+bytes([original[-1]^1]), b'Z'+original[1:])):
            damaged = self.root / ('damaged-'+str(index)+'.bin')
            damaged.write_bytes(content)
            with self.assertRaises(Exception):
                OwnerStore.restore(damaged, self.root / ('damaged-'+str(index)+'.db'), KEY)
        self.assertFalse((self.root / 'wrong-key.db').exists())

    def test_authenticated_container_still_checks_component_hashes(self):
        snapshot = self.store.backup(self.root / 'backup.bin')
        wire = snapshot.read_bytes()
        sealed = wire[len(MAGIC):]
        payload = self.store.aead.decrypt(sealed[:12], sealed[12:], MAGIC)
        length = struct.unpack('<I', payload[:4])[0]
        manifest = json.loads(payload[4:4+length])
        manifest['owner_sha256'] = '00' * 32
        encoded = canonical(manifest)
        altered = struct.pack('<I', len(encoded))+encoded+payload[4+length:]
        damaged = self.root / 'wrong-components.bin'
        damaged.write_bytes(MAGIC+self.store._seal(altered, MAGIC))
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            OwnerStore.restore(damaged, self.root / 'wrong-components.db', KEY)

    def test_backup_refuses_corrupt_history_and_non_database_companion(self):
        with self.assertRaises(ValueError):
            self.store.backup(self.root / 'invalid-companion.bin', companion=b'arbitrary bytes')
        self.store.db.execute('DROP TRIGGER immutable_record')
        self.store.db.execute("UPDATE owner_records SET record_hash=? WHERE seq=1", ('ff' * 32,))
        with self.assertRaises(ValueError):
            self.store.backup(self.root / 'corrupt-history.bin')
        self.assertFalse((self.root / 'corrupt-history.bin').exists())

    def test_record_and_database_size_limits_leave_no_partial_batch(self):
        with patch.object(store_module, 'MAX_RECORDS', self.count()+1):
            with self.assertRaisesRegex(ValueError, 'count bound'):
                self.store.batch([('cursor', 1, False), ('public-proof', True, True)])
        with patch.object(store_module, 'MAX_DATABASE', 1):
            with self.assertRaisesRegex(ValueError, 'size bound'):
                self.store.put('cursor', 1)
            with self.assertRaisesRegex(ValueError, 'size bound'):
                self.store._audit()
        self.assertEqual(self.count(), 1)
        self.assertIsNone(self.store.get('cursor'))
        self.assertIsNone(self.store.get('public-proof'))

    def test_restore_authenticates_inner_record_chain_before_publication(self):
        raw = self.store._snapshot_bytes()
        copy = sqlite3.connect(':memory:')
        try:
            copy.deserialize(raw)
            copy.execute('DROP TRIGGER immutable_record')
            copy.execute('UPDATE owner_records SET encrypted=? WHERE seq=1', (b'x'*64,))
            copy.commit()
            damaged_owner = copy.serialize()
        finally:
            copy.close()
        manifest = canonical({'version': 1, 'owner_size': len(damaged_owner),
                              'owner_sha256': hashlib.sha256(damaged_owner).hexdigest(),
                              'companion_size': 0, 'companion_sha256': None})
        payload = struct.pack('<I', len(manifest))+manifest+damaged_owner
        snapshot = self.root / 'valid-envelope-corrupt-inner.bin'
        snapshot.write_bytes(MAGIC+self.store._seal(payload, MAGIC))
        target = self.root / 'must-not-publish.db'
        with self.assertRaises(Exception):
            OwnerStore.restore(snapshot, target, KEY)
        self.assertEqual(target.read_bytes(), b'')
        with self.assertRaises(Exception):
            OwnerStore(target, KEY)

    def test_fault_before_commit_rolls_back_cursor_and_public_proof_together(self):
        with patch.object(self.store, '_write_head', side_effect=OSError('fixture write interruption')):
            with self.assertRaises(OSError):
                self.store.batch([('cursor', 1, False), ('public-proof', {'txid': 'public'}, True)])
        self.assertIsNone(self.store.get('cursor'))
        self.assertIsNone(self.store.get('public-proof'))
        self.assertEqual(self.count(), 1)

    def test_actual_process_exit_before_and_after_commit_preserves_atomic_batch(self):
        for stage in ('before-commit', 'after-commit'):
            path = self.root / (stage+'.db')
            with OwnerStore(path, KEY, create={'fixture': stage}):
                pass
            self.child(stage, path)
            with OwnerStore(path, KEY) as reopened:
                self.assertEqual(reopened.get('cursor'), 99 if stage=='after-commit' else None)
                self.assertEqual(reopened.get('public-proof'), {'observed': True} if stage=='after-commit' else None)

    def test_actual_backup_exit_before_and_after_atomic_publication(self):
        self.store.close()
        for stage in ('backup-before', 'backup-after'):
            target = self.root / (stage+'.bin')
            self.child(stage, self.path, target)
            if stage == 'backup-before':
                self.assertEqual(target.read_bytes(), b'')
                with self.assertRaises(ValueError):
                    OwnerStore.restore(target, self.root / 'not-published.db', KEY)
            else:
                result = OwnerStore.restore(target, self.root / 'published.db', KEY)
                with OwnerStore(result['store_path'], KEY) as restored:
                    self.assertTrue(restored.recovery_required())
        with OwnerStore(self.path, KEY) as source:
            self.assertFalse(source.recovery_required())

    def test_actual_restore_exit_never_publishes_unlocked_recovery_copy(self):
        snapshot = self.store.backup(self.root / 'restore-source.bin')
        original = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        for stage in ('restore-before', 'restore-after'):
            target = self.root / (stage+'.db')
            self.child(stage, snapshot, target)
            if stage == 'restore-before':
                self.assertEqual(target.read_bytes(), b'')
                with self.assertRaises(Exception):
                    OwnerStore(target, KEY)
                copies = [p for p in self.root.glob(target.name+'.pending-*') if not p.name.endswith('.lock')]
                self.assertEqual(len(copies), 1)
                with OwnerStore(copies[0], KEY) as staged:
                    self.assertTrue(staged.recovery_required())
            else:
                with OwnerStore(target, KEY) as restored:
                    self.assertTrue(restored.recovery_required())
            self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(), original)


def child(stage, source, destination=None):
    if stage == 'locked':
        try:
            OwnerStore(source, KEY)
        except ValueError:
            os._exit(73)
        os._exit(74)
    if stage == 'open':
        with OwnerStore(source, KEY):
            os._exit(73)
    if stage.startswith('before-') or stage.startswith('after-'):
        with OwnerStore(source, KEY) as store:
            if stage == 'before-commit':
                old = store._write_head
                def stop_before_commit(head):
                    old(head)
                    os._exit(73)
                store._write_head = stop_before_commit
            store.batch([('cursor', 99, False), ('public-proof', {'observed': True}, True)])
            os._exit(73)
    original = store_module._publish
    def publish(temporary, target):
        if stage.endswith('-after'):
            original(temporary, target)
        os._exit(73)
    store_module._publish = publish
    if stage.startswith('backup-'):
        with OwnerStore(source, KEY) as store:
            store.backup(destination)
    elif stage.startswith('restore-'):
        OwnerStore.restore(source, destination, KEY)
    os._exit(74)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child(*sys.argv[2:])
    else:
        unittest.main(verbosity=2)
