"""Full encrypted owner/session checkpoints against a real local AnchorStore.

Financial transport is explicitly mocked. Real storage, signatures, snapshots,
locks, fresh-read CAS, journal exposure and protective restoration are exercised.
"""
import copy
from contextlib import closing
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from swap_runtime.anchor import AnchorClient, AnchorConflict, AnchorError, AnchorStore, AnchorUncertain
from swap_runtime.anchored_owner import AnchoredOwner, _logical_fingerprint
from swap_runtime.common import new_private_file
from swap_runtime.journal import Admission, Journal
from swap_runtime.lifecycle import Owner, _session_key
from swap_runtime.lifecycle_store import OwnerStore
import test_owner_recovery as recovery_fixture


SIGNER = Ed25519PrivateKey.from_private_bytes(bytes([71]) * 32)  # Public synthetic key.
SERVICE, STREAM = '11' * 32, '22' * 32
ADMISSION = Admission(20, 2, 50, 2, 50, True, True, True)


class Transport:
    def __init__(self, store):
        self.store, self.fault, self.calls = store, None, []

    def __call__(self, value):
        self.calls.append(copy.deepcopy(value))
        fault = self.fault
        if fault == 'offline': raise ConnectionError('private-anchor-diagnostic')
        if value['operation'] == 'append' and fault == 'before-append':
            self.fault = None
            raise ConnectionError('private-anchor-diagnostic')
        result = self.store.handle(value)
        if value['operation'] == 'append' and fault == 'after-append':
            self.fault = None
            raise TimeoutError('private-anchor-diagnostic')
        return result


class AnchoredOwnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = recovery_fixture.OwnerRecoveryTests()
        self.fixture.setUp()
        self.root = self.fixture.root
        self.key = recovery_fixture.KEY
        public = SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.anchor = AnchorStore(self.root / 'independent-anchor.db', service_id=SERVICE,
            stream_id=STREAM, writer_public_key=public, create=True)
        self.transport = Transport(self.anchor)
        self.client = AnchorClient(self.transport, service_id=SERVICE, stream_id=STREAM, writer_key=SIGNER)
        self.opened = []
        self.directory = self.root / 'anchored-owner'

    def tearDown(self):
        for item in reversed(self.opened): item.close()
        self.anchor.close()
        self.fixture.tearDown()

    def open(self, directory=None, creating=True, client=None, role='foreign-owner', durable_funding=False):
        credentials = dict(xds_rho='31' * 32,
            foreign_key=self.fixture.keys[role].private_numbers().private_value.to_bytes(32, 'big').hex())
        if role == 'foreign-owner': credentials['secret'] = self.fixture.secret.hex()
        item = AnchoredOwner(directory or self.directory, self.key, self.fixture.rpc, self.fixture.rpc,
            wallet=self.fixture.rpc, exchange_dir=self.fixture.mailbox, backup_dir=self.root / 'backups',
            offer=self.fixture.offer if creating else None, role=role if creating else None,
            credentials=credentials if creating else None, anchor_client=client or self.client,
            durable_funding=durable_funding)
        self.opened.append(item)
        return item

    def pair(self, item):
        self.fixture.drafts(item.owner)
        item.owner._open_session()
        item._commit_current()
        return item

    def current_raw(self, item):
        return (item.snapshots / (self.client.read()['commitment'] + '.backup')).read_bytes()

    def inspect(self, item, assertion):
        owner_bytes, companion = OwnerStore._decode_backup(self.current_raw(item), AESGCM(self.key))
        owner_path = self.root / ('inspect-' + uuid.uuid4().hex + '.db')
        new_private_file(owner_path, owner_bytes)
        journal = None
        with OwnerStore(owner_path, self.key) as store:
            if companion is not None:
                companion_path = self.root / ('inspect-session-' + uuid.uuid4().hex + '.db')
                new_private_file(companion_path, companion)
                journal = Journal(companion_path, _session_key(self.key))
            try: assertion(store, journal)
            finally:
                if journal is not None: journal.close()

    def mutate_step(self, item, label='test.marker', value='retained'):
        def action():
            item.owner.store.put(label, value)
            return dict(action='fixture-state-advanced')
        return patch.object(item.owner, 'step', side_effect=action)

    def crash_accept(self, stage):
        item = self.open()
        previous = item.head
        item.close()
        self.anchor.close()
        result = subprocess.run([sys.executable, '-B', __file__, '--child', stage,
            str(self.directory), str(self.anchor.path)], capture_output=True, cwd=ROOT, timeout=30,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout, b'')
        self.anchor = AnchorStore(self.anchor.path,
            **{key: value for key, value in self.anchor.profile.items() if key != 'version'})
        self.transport.store = self.anchor
        return previous

    def fund_fixture(self, item):
        owner = item.owner
        owner.wallet = Mock(return_value=dict(genesis_hash=self.fixture.offer['xds']['genesis_hash'],
            commitment=self.fixture.offer['xds']['claim_commitment'], address=self.fixture.offer['xds']['claim_address']))
        adapter = Mock()
        adapter.plan.return_value = {'selection': 'immutable-test-plan'}
        adapter.prepare.return_value = (b'fixed-test-signed-funding', '71' * 32)
        adapter.receipt.return_value = dict(status='unknown', publicly_observed=False, final=False)
        owner.foreign_funding = adapter
        owner._clock_ready = Mock(return_value=True)
        owner._funded_terms = Mock(return_value=self.fixture.bitcoin.terms)
        return adapter

    def native_durable_fixture(self, item):
        owner = item.owner
        adapter = Mock()
        adapter.terms = owner.native_funding.terms
        adapter.plan.return_value = owner.native_funding.plan()
        owner.native_funding = adapter
        owner._identity = Mock()
        owner._clock_ready = Mock(return_value=True)
        owner._peer_funding = Mock(return_value=True)
        owner._foreign_adapter = Mock(return_value=Mock(observe=Mock(return_value={'status': 'unspent', 'final': True})))
        owner._funded_terms = Mock(return_value=self.fixture.native.terms)
        return adapter

    def test_native_scan_lag_waits_without_plan_operation_or_intent_then_reopens_ready(self):
        item = self.open(role='xds-owner', durable_funding=True)
        first_config = item.owner.store.get('config')
        adapter = self.native_durable_fixture(item)
        with patch('swap_runtime.xds_preparation.scan_ready', return_value=False) as ready, \
                patch('swap_runtime.xds_preparation.capabilities') as caps, \
                patch('swap_runtime.xds_preparation.prepare') as prepare, \
                patch.object(item.owner, 'step', side_effect=item.owner._fund):
            self.assertEqual(item.step()['action'], 'wait-native-wallet-scan')
            waited = item.head
            self.assertEqual(item.step()['action'], 'wait-native-wallet-scan')
            self.assertEqual(item.head, waited)
            self.assertEqual(ready.call_count, 2)
            caps.assert_not_called(); prepare.assert_not_called()
        adapter.plan.assert_not_called(); adapter.send.assert_not_called()
        for label in ('funding.plan', 'funding.operation', 'funding.prepare-started', 'funding.attempt', 'funding.send-started'):
            self.assertIsNone(item.owner.store.get(label))
        item.close()
        resumed = self.open(creating=False)
        self.assertEqual(resumed.owner.store.get('config'), first_config)
        adapter = self.native_durable_fixture(resumed)
        raw, txid = b'synthetic-state-machine-funding', '72' * 32
        with patch('swap_runtime.xds_preparation.scan_ready', return_value=True) as ready, \
                patch('swap_runtime.xds_preparation.capabilities') as caps, \
                patch('swap_runtime.xds_preparation.prepare', return_value=(raw, txid)) as prepare, \
                patch.object(resumed.owner, 'step', side_effect=resumed.owner._fund):
            self.assertEqual(resumed.step()['action'], 'funding-submitted')
            operation = resumed.owner.store.get('funding.operation')
            ready.assert_called_once_with(adapter); caps.assert_called_once_with(adapter)
            prepare.assert_called_once_with(adapter, resumed.owner.rho, operation['operation_id'], resume=False)
        adapter.plan.assert_called_once(); adapter.send.assert_called_once_with(raw, txid)

    def test_unknown_native_scan_observation_cannot_persist_preparation_markers(self):
        from swap_runtime.xds import _Unavailable
        item = self.open(role='xds-owner', durable_funding=True)
        adapter = self.native_durable_fixture(item)
        with patch('swap_runtime.xds_preparation.scan_ready', side_effect=_Unavailable('unknown')), \
                patch('swap_runtime.xds_preparation.prepare') as prepare, \
                patch.object(item.owner, 'step', side_effect=item.owner._fund):
            with self.assertRaises(_Unavailable): item.step()
            prepare.assert_not_called()
        adapter.plan.assert_not_called(); adapter.send.assert_not_called()
        for label in ('funding.plan', 'funding.operation', 'funding.prepare-started', 'funding.attempt'):
            self.assertIsNone(item.owner.store.get(label))

    def test_started_native_operation_resumes_exact_retained_identity_without_new_scan_gate(self):
        from swap_runtime.xds import _Unavailable
        item = self.open(role='xds-owner', durable_funding=True)
        self.native_durable_fixture(item)
        with patch('swap_runtime.xds_preparation.scan_ready', return_value=True), \
                patch('swap_runtime.xds_preparation.capabilities'), \
                patch('swap_runtime.xds_preparation.prepare', side_effect=_Unavailable('lost reply')), \
                patch.object(item.owner, 'step', side_effect=item.owner._fund):
            with self.assertRaises(_Unavailable): item.step()
        operation = item.owner.store.get('funding.operation')
        plan = item.owner.store.get('funding.plan')
        item.close()
        resumed = self.open(creating=False)
        adapter = self.native_durable_fixture(resumed)
        raw, txid = b'synthetic-state-machine-resumed-funding', '73' * 32
        with patch('swap_runtime.xds_preparation.scan_ready', side_effect=AssertionError('new-operation gate')), \
                patch('swap_runtime.xds_preparation.capabilities') as caps, \
                patch('swap_runtime.xds_preparation.prepare', return_value=(raw, txid)) as prepare, \
                patch.object(resumed.owner, 'step', side_effect=resumed.owner._fund):
            self.assertEqual(resumed.step()['action'], 'funding-submitted')
            prepare.assert_called_once_with(adapter, resumed.owner.rho, operation['operation_id'], resume=True)
            caps.assert_not_called()
        adapter.plan.assert_not_called()
        self.assertEqual(resumed.owner.store.get('funding.operation'), operation)
        self.assertEqual(resumed.owner.store.get('funding.plan'), plan)

    def test_initial_checkpoint_is_complete_encrypted_and_normal_restart_stays_normal(self):
        item = self.pair(self.open())
        raw, txid = self.fixture.native.wire()
        item.owner.session.journal.prepare(self.fixture.offer['swap_id'], 'xds-claim', raw, txid)
        item._commit_current()
        head = item.head
        self.assertFalse(item.owner.store.recovery_required())
        self.assertNotIn(self.fixture.secret, self.current_raw(item))
        self.assertFalse((self.directory / 'owner.db').exists())
        item.close()
        resumed = self.open(creating=False)
        self.assertEqual(resumed.head, head)
        self.assertFalse(resumed.owner.store.recovery_required())
        self.assertFalse(resumed.owner.session.journal.recovery_required())
        self.assertEqual(resumed.owner.session.journal.intent(self.fixture.offer['swap_id'], 'xds-claim')['payload'], raw)
        self.fixture.rpc.assert_not_called()

    def test_unchanged_polling_and_internal_checkpoints_do_not_consume_backup_history(self):
        item = self.pair(self.open())
        head = item.head
        retained = set(item.snapshots.iterdir())
        backups = set(item.owner.backup_dir.iterdir())
        calls = len(self.transport.calls)
        with patch.object(item.owner, 'step', return_value={'action': 'waiting'}):
            for _ in range(12):
                self.assertEqual(item.step(), {'action': 'waiting'})
                item.owner._checkpoint()
        self.assertEqual(item.head, head)
        self.assertEqual(set(item.snapshots.iterdir()), retained)
        self.assertEqual(set(item.owner.backup_dir.iterdir()), backups)
        self.assertGreaterEqual(len(self.transport.calls) - calls, 36)

    def test_restart_can_reuse_only_freshly_authenticated_current_pair(self):
        item = self.pair(self.open())
        head = item.head
        item.close()
        resumed = self.open(creating=False)
        with patch.object(resumed.owner, 'backup', side_effect=AssertionError('duplicate backup')):
            resumed.owner._checkpoint()
        self.assertEqual(resumed.head, head)

    def test_constructor_changes_are_not_mistaken_for_already_anchored_state(self):
        item = self.pair(self.open())
        head = item.head
        item.close()
        original = Owner._open_session
        def constructor_change(owner, *args, **kwargs):
            result = original(owner, *args, **kwargs)
            owner.store.once('test.constructor-binding', 'durable')
            return result
        with patch.object(Owner, '_open_session', constructor_change):
            resumed = self.open(creating=False)
        self.assertEqual(resumed.head, head)
        resumed.owner._checkpoint()
        self.assertEqual(resumed.head['sequence'], head['sequence'] + 1)
        self.inspect(resumed, lambda store, journal: self.assertEqual(store.get('test.constructor-binding'), 'durable'))

    def test_companion_intent_status_and_exposure_each_advance_complete_checkpoint(self):
        item = self.pair(self.open())
        journal = item.owner.session.journal
        raw, txid = self.fixture.native.wire()
        owner_before = list(item.owner.store.db.iterdump())
        sequence = item.head['sequence']
        journal.prepare(self.fixture.offer['swap_id'], 'xds-claim', raw, txid)
        item.owner._checkpoint()
        self.assertEqual(item.head['sequence'], sequence + 1)
        journal.db.execute("UPDATE attempts SET status='confirmed' WHERE kind='xds-claim'")
        item.owner._checkpoint()
        self.assertEqual(item.head['sequence'], sequence + 2)
        journal.db.execute('UPDATE swaps SET exposed=1')
        item.owner._checkpoint()
        self.assertEqual(item.head['sequence'], sequence + 3)
        self.assertEqual(list(item.owner.store.db.iterdump()), owner_before)
        self.inspect(item, lambda store, saved: self.assertTrue(saved.exposed(self.fixture.offer['swap_id'])))

    def test_identical_sql_updates_do_not_create_checkpoint_but_changed_history_does(self):
        item = self.pair(self.open())
        head = item.head
        item.owner.session.journal.db.execute('UPDATE swaps SET exposed=exposed')
        item.owner._checkpoint()
        self.assertEqual(item.head, head)
        item.owner.store.put('test.marker', 'same')
        item.owner._checkpoint()
        changed = item.head
        self.assertEqual(changed['sequence'], head['sequence'] + 1)
        item.owner.store.put('test.marker', 'same')
        item.owner._checkpoint()
        self.assertEqual(item.head, changed)
        item.owner.store.put('test.marker', 'new')
        item.owner.store.put('test.marker', 'same')
        item.owner._checkpoint()
        self.assertEqual(item.head['sequence'], changed['sequence'] + 1)

    def test_unchanged_state_cannot_skip_missing_snapshot(self):
        item = self.open()
        (item.snapshots / (item.head['commitment'] + '.backup')).unlink()
        with patch.object(item.owner, 'backup', side_effect=AssertionError('fallback')):
            with self.assertRaises((OSError, ValueError, AnchorError)): item.owner._checkpoint()
        self.assertTrue(item.failed)

    def test_unchanged_state_cannot_skip_offline_anchor(self):
        item = self.open()
        self.transport.fault = 'offline'
        with patch.object(item.owner, 'backup', side_effect=AssertionError('fallback')):
            with self.assertRaises(AnchorUncertain): item.owner._checkpoint()
        self.assertTrue(item.failed)

    def test_unchanged_state_cannot_skip_accepted_head_tamper(self):
        item = self.open()
        raw = item.accepted_path.read_bytes()
        item.accepted_path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(InvalidTag): item.owner._checkpoint()
        self.assertTrue(item.failed)

    def test_logical_fingerprint_includes_entire_schema_rows_companion_and_format(self):
        with closing(sqlite3.connect(':memory:', isolation_level=None)) as owner, closing(sqlite3.connect(':memory:', isolation_level=None)) as session:
            owner.execute('CREATE TABLE records(id INTEGER PRIMARY KEY, value BLOB)')
            owner.execute('INSERT INTO records VALUES(1,?)', (b'ciphertext',))
            first = _logical_fingerprint(owner)
            self.assertNotEqual(first, _logical_fingerprint(owner, session))
            owner.execute('UPDATE records SET value=value')
            self.assertEqual(first, _logical_fingerprint(owner))
            owner.execute('CREATE INDEX retained_history ON records(value)')
            second = _logical_fingerprint(owner)
            self.assertNotEqual(first, second)
            owner.execute('PRAGMA user_version=3')
            third = _logical_fingerprint(owner)
            self.assertNotEqual(second, third)
            owner.execute('PRAGMA application_id=17')
            self.assertNotEqual(third, _logical_fingerprint(owner))
            owner.execute('BEGIN IMMEDIATE')
            with self.assertRaises(AnchorError): _logical_fingerprint(owner)
            owner.execute('ROLLBACK')

    def test_uncommitted_working_changes_and_leftover_companion_never_become_authoritative(self):
        item = self.pair(self.open())
        item.owner.store.put('uncommitted', True)
        stale = self.directory / 'work-stale-copy'
        stale.mkdir()
        (stale / 'settlement.db').write_bytes(b'not-an-authoritative-journal')
        item.close()
        resumed = self.open(creating=False)
        self.assertIsNone(resumed.owner.store.get('uncommitted'))
        self.assertIsNotNone(resumed.owner.session)
        self.assertFalse(resumed.owner.session.journal.recovery_required())
        self.assertTrue((stale / 'settlement.db').exists())

    def test_full_old_directory_cannot_satisfy_current_external_head(self):
        item = self.open()
        item.close()
        stale = self.root / 'old-owner-directory'
        shutil.copytree(self.directory, stale)
        item = self.open(creating=False)
        with self.mutate_step(item): item.step()
        item.close()
        with self.assertRaises((ValueError, OSError)): self.open(stale, creating=False)
        current = self.open(creating=False)
        self.assertEqual(current.owner.store.get('test.marker'), 'retained')

    def test_older_paired_snapshot_cannot_replace_current_companion(self):
        item = self.pair(self.open())
        before = self.current_raw(item)
        raw, txid = self.fixture.native.wire()
        item.owner.session.journal.prepare(self.fixture.offer['swap_id'], 'xds-claim', raw, txid)
        item._commit_current()
        target = item.snapshots / (item.head['commitment'] + '.backup')
        item.close()
        target.write_bytes(before)  # Isolated whole-backup restoration fault.
        with self.assertRaises(AnchorError): self.open(creating=False)

    def test_missing_current_snapshot_refuses_normal_progress(self):
        item = self.open()
        current = item.snapshots / (item.head['commitment'] + '.backup')
        item.close()
        current.unlink()
        with self.assertRaises((ValueError, OSError)): self.open(creating=False)
        self.fixture.rpc.assert_not_called()

    def test_lost_anchor_ack_reconciles_exact_pending_without_second_append(self):
        item = self.open()
        previous = item.head['sequence']
        self.transport.fault = 'after-append'
        with self.mutate_step(item), self.assertRaises(AnchorUncertain): item.step()
        self.assertTrue(item.pending_path.exists())
        committed = self.client.read()
        self.assertEqual(committed['sequence'], previous + 1)
        appends = sum(value['operation'] == 'append' for value in self.transport.calls)
        with self.assertRaises(AnchorError): item.status()
        item.close()
        resumed = self.open(creating=False)
        self.assertFalse(resumed.pending_path.exists())
        self.assertEqual(resumed.head, committed)
        self.assertEqual(resumed.owner.store.get('test.marker'), 'retained')
        self.assertEqual(sum(value['operation'] == 'append' for value in self.transport.calls), appends)

    def test_before_anchor_commit_restart_submits_only_same_durable_pending(self):
        item = self.open()
        previous = item.head['sequence']
        self.transport.fault = 'before-append'
        with self.mutate_step(item), self.assertRaises(AnchorUncertain): item.step()
        failed_request = next(value for value in reversed(self.transport.calls) if value['operation'] == 'append')
        self.assertEqual(self.client.read()['sequence'], previous)
        item.close()
        resumed = self.open(creating=False)
        last_request = next(value for value in reversed(self.transport.calls) if value['operation'] == 'append')
        self.assertEqual(last_request['pending'], failed_request['pending'])
        self.assertNotEqual(last_request['nonce'], failed_request['nonce'])
        self.assertEqual(resumed.head['sequence'], previous + 1)
        self.assertEqual(resumed.owner.store.get('test.marker'), 'retained')

    def test_external_conflict_refuses_pending_publication(self):
        item = self.open()
        old_head = item.head
        self.transport.fault = 'before-append'
        with self.mutate_step(item), self.assertRaises(AnchorUncertain): item.step()
        self.client.submit(self.client.prepare(old_head, 'aa' * 32, True))
        item.close()
        with self.assertRaises(AnchorConflict): self.open(creating=False)
        self.assertTrue((self.directory / 'pending.json').exists())

    def test_each_step_checks_fresh_head_before_any_base_owner_action(self):
        item = self.open()
        current = self.client.read()
        self.client.submit(self.client.prepare(current, current['commitment'], True))
        with patch.object(item.owner, 'step') as action:
            with self.assertRaises(AnchorConflict): item.step()
            action.assert_not_called()
        self.fixture.rpc.assert_not_called()

    def test_provider_only_rollback_cannot_reopen_old_available_owner_snapshot(self):
        item = self.open()
        earlier = self.root / 'earlier-independent-anchor.db'
        with closing(sqlite3.connect(earlier)) as destination:
            self.anchor.db.backup(destination)
        with self.mutate_step(item): item.step()
        retained = item.head
        item.close()
        with AnchorStore(earlier, **{key: value for key, value in self.anchor.profile.items() if key != 'version'}) as old:
            client = AnchorClient(old.handle, service_id=SERVICE, stream_id=STREAM, writer_key=SIGNER)
            self.assertLess(client.read()['sequence'], retained['sequence'])
            with self.assertRaises(AnchorError): self.open(creating=False, client=client)
        current = self.open(creating=False)
        self.assertEqual(current.head, retained)
        self.assertEqual(current.owner.store.get('test.marker'), 'retained')

    def test_unstaged_external_advance_refused_even_when_committed_snapshot_exists(self):
        item = self.open()
        before = item.head
        item.close()
        # A second writer uses the same valid snapshot but has no local staged
        # handoff. Presence of snapshot bytes is insufficient publication proof.
        self.client.submit(self.client.prepare(before, before['commitment'], False))
        with self.assertRaises(AnchorError): self.open(creating=False)
        self.fixture.rpc.assert_not_called()

    def test_real_exit_before_local_acceptance_reconciles_committed_exact_pending(self):
        previous = self.crash_accept('before-accept')
        current = self.client.read()
        self.assertEqual(current['sequence'], previous['sequence'] + 1)
        self.assertTrue((self.directory / 'pending.json').exists())
        self.transport.calls.clear()
        resumed = self.open(creating=False)
        self.assertEqual(resumed.head, current)
        self.assertEqual(resumed.owner.store.get('child.marker'), 'before-accept')
        self.assertFalse(resumed.pending_path.exists())
        self.assertFalse(any(value['operation'] == 'append' for value in self.transport.calls))

    def test_real_exit_after_local_acceptance_before_pending_removal_is_idempotent(self):
        previous = self.crash_accept('after-accept')
        current = self.client.read()
        self.assertEqual(current['sequence'], previous['sequence'] + 1)
        self.assertTrue((self.directory / 'pending.json').exists())
        self.transport.calls.clear()
        resumed = self.open(creating=False)
        self.assertEqual(resumed.head, current)
        self.assertEqual(resumed.owner.store.get('child.marker'), 'after-accept')
        self.assertFalse(resumed.pending_path.exists())
        self.assertFalse(any(value['operation'] == 'append' for value in self.transport.calls))

    def test_accepted_head_tamper_is_rejected_before_remote_or_financial_calls(self):
        item = self.open()
        accepted = item.accepted_path
        item.close()
        raw = accepted.read_bytes()
        accepted.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        count = len(self.transport.calls)
        with self.assertRaises((AnchorError, InvalidTag)): self.open(creating=False)
        self.assertEqual(len(self.transport.calls), count)
        self.fixture.rpc.assert_not_called()

    def test_missing_accepted_head_never_adopts_available_remote_snapshot(self):
        item = self.open()
        accepted = item.accepted_path
        item.close()
        accepted.unlink()
        count = len(self.transport.calls)
        with self.assertRaises((ValueError, OSError)): self.open(creating=False)
        self.assertEqual(len(self.transport.calls), count)

    def test_provider_rollback_after_local_acceptance_does_not_resubmit_old_pending(self):
        item = self.open()
        earlier = self.root / 'anchor-before-accept.db'
        with closing(sqlite3.connect(earlier)) as destination: self.anchor.db.backup(destination)
        original = item._accept
        def fail_after_accept(head):
            original(head)
            raise OSError('fixture interruption before pending removal')
        with self.mutate_step(item), patch.object(item, '_accept', side_effect=fail_after_accept):
            with self.assertRaises(OSError): item.step()
        self.assertTrue(item.pending_path.exists())
        item.close()
        with AnchorStore(earlier, **{key: value for key, value in self.anchor.profile.items() if key != 'version'}) as old:
            transport = Transport(old)
            client = AnchorClient(transport, service_id=SERVICE, stream_id=STREAM, writer_key=SIGNER)
            with self.assertRaises(AnchorError): self.open(creating=False, client=client)
            self.assertFalse(any(value['operation'] == 'append' for value in transport.calls))
        resumed = self.open(creating=False)
        self.assertEqual(resumed.owner.store.get('test.marker'), 'retained')

    def test_offline_anchor_does_not_fallback_to_local_status_or_step(self):
        item = self.open()
        self.transport.fault = 'offline'
        with patch.object(item.owner, 'step') as action:
            with self.assertRaises(AnchorUncertain): item.step()
            with self.assertRaises(AnchorUncertain): item.status()
            action.assert_not_called()
        item.close()
        with self.assertRaises(AnchorUncertain): self.open(creating=False)
        self.fixture.rpc.assert_not_called()

    def test_outer_lock_excludes_second_writer_before_external_calls(self):
        item = self.open()
        count = len(self.transport.calls)
        with self.assertRaisesRegex(ValueError, 'already open'): self.open(creating=False)
        self.assertEqual(len(self.transport.calls), count)
        self.assertFalse(item.failed)

    def test_changed_profile_binding_refused_before_external_calls(self):
        item = self.open()
        item.close()
        different = AnchorClient(self.transport, service_id='33' * 32, stream_id=STREAM, writer_key=SIGNER)
        count = len(self.transport.calls)
        with self.assertRaises(ValueError): self.open(creating=False, client=different)
        self.assertEqual(len(self.transport.calls), count)

    def test_legacy_owner_cannot_open_extracted_anchored_working_store(self):
        item = self.open()
        owner_bytes, _ = OwnerStore._decode_backup(self.current_raw(item), AESGCM(self.key))
        copied = self.root / 'copied-owner'
        copied.mkdir()
        new_private_file(copied / 'owner.db', owner_bytes)
        with self.assertRaisesRegex(ValueError, 'coordinator'):
            Owner(copied, self.key, self.fixture.rpc, self.fixture.rpc)
        self.fixture.rpc.assert_not_called()

    def test_backup_exports_exact_current_snapshot_and_never_overwrites(self):
        item = self.open()
        expected = self.current_raw(item)
        item.owner.store.put('uncommitted', 'must-not-export')
        destination = self.root / 'export.backup'
        item.backup(destination)
        self.assertEqual(destination.read_bytes(), expected)
        with self.assertRaises(FileExistsError): item.backup(destination)
        self.assertEqual(destination.read_bytes(), expected)

    def test_historical_restore_creates_new_protective_head_and_fences_live_normal_copy(self):
        item = self.pair(self.open())
        raw, txid = self.fixture.native.wire()
        item.owner.session.journal.prepare(self.fixture.offer['swap_id'], 'xds-claim', raw, txid)
        item._commit_current()
        snapshot = self.root / 'historical.backup'
        item.backup(snapshot)
        original = snapshot.read_bytes()
        previous = item.head
        target = self.root / 'recovered-anchored'
        result = AnchoredOwner.restore(snapshot, target, self.key, anchor_client=self.client)
        self.assertTrue(result['recovery_required'])
        self.assertGreater(result['checkpoint_sequence'], previous['sequence'])
        with patch.object(item.owner, 'step') as action:
            with self.assertRaises(AnchorConflict): item.step()
            action.assert_not_called()
        restored = self.open(target, creating=False)
        self.assertTrue(restored.owner.store.recovery_required())
        self.assertTrue(restored.owner.session.journal.recovery_required())
        self.assertEqual(restored.owner.session.journal.intent(self.fixture.offer['swap_id'], 'xds-claim')['payload'], raw)
        self.assertEqual(restored.owner._fund()['action'], 'protective-no-funding')
        self.assertFalse(restored.owner._first_claim_ready({}))
        self.assertEqual(snapshot.read_bytes(), original)
        self.fixture.rpc.assert_not_called()

    def test_explicit_offline_restore_is_protective_in_both_journals_without_anchor_io(self):
        item = self.pair(self.open())
        raw, txid = self.fixture.native.wire()
        item.owner.session.journal.prepare(self.fixture.offer['swap_id'], 'xds-claim', raw, txid)
        item._commit_current()
        snapshot = self.root / 'offline-source.backup'
        item.backup(snapshot)
        previous = self.client.read()
        count = len(self.transport.calls)
        self.transport.fault = 'offline'
        target = self.root / 'offline-recovered'
        result = AnchoredOwner.restore_offline(snapshot, target, self.key)
        self.assertTrue(result['offline_protective'])
        self.assertFalse(result['externally_anchored'])
        self.assertEqual(len(self.transport.calls), count)
        with Owner(target, self.key, self.fixture.rpc, self.fixture.rpc) as owner:
            self.assertTrue(owner.store.recovery_required())
            self.assertTrue(owner.session.journal.recovery_required())
            self.assertTrue(owner.store.get('freshness.offline-recovery'))
            self.assertEqual(owner._fund()['action'], 'protective-no-funding')
            self.assertFalse(owner._first_claim_ready({}))
        self.transport.fault = None
        self.assertEqual(self.client.read(), previous)
        self.fixture.rpc.assert_not_called()

    def test_funding_wire_and_send_started_are_anchored_before_financial_send(self):
        item = self.open()
        adapter = self.fund_fixture(item)
        def send(plan, raw, txid):
            def check(store, journal):
                packet = store.get('funding.attempt')
                self.assertEqual((packet['plan'], bytes.fromhex(packet['raw']), packet['txid']), (plan, raw, txid))
                self.assertTrue(store.get('funding.send-started'))
                self.assertIsNone(journal)
            self.inspect(item, check)
            self.assertFalse(item.pending_path.exists())
        adapter.send.side_effect = send
        self.assertEqual(item.owner._fund()['action'], 'funding-submitted')
        adapter.send.assert_called_once()

    def test_failed_anchor_commit_prevents_funding_and_retains_signed_artifact(self):
        item = self.open()
        adapter = self.fund_fixture(item)
        def prepared(plan):
            self.transport.fault = 'before-append'
            return adapter.prepare.return_value
        adapter.prepare.side_effect = prepared
        with self.assertRaises(AnchorUncertain): item.owner._fund()
        adapter.send.assert_not_called()
        retained = item.owner.store.get('funding.attempt')
        self.assertIsNotNone(retained)
        item.close()
        resumed = self.open(creating=False)
        self.assertEqual(resumed.owner.store.get('funding.attempt'), retained)
        self.assertTrue(resumed.owner.store.get('funding.send-started'))

    def test_plan_is_anchored_before_wallet_reservation_and_lost_prepare_reply(self):
        item = self.open()
        adapter = self.fund_fixture(item)
        retained_plan = copy.deepcopy(adapter.plan.return_value)
        def reserve_then_lose_reply(plan):
            def check(store, journal):
                self.assertEqual(store.get('funding.plan'), retained_plan)
                self.assertTrue(store.get('funding.prepare-started'))
                self.assertIsNone(store.get('funding.attempt'))
            self.inspect(item, check)
            raise TimeoutError('fixture wallet reserved inputs; signing acknowledgment lost')
        adapter.prepare.side_effect = reserve_then_lose_reply
        with self.assertRaises(TimeoutError): item.owner._fund()
        adapter.plan.assert_called_once()
        adapter.prepare.assert_called_once_with(retained_plan)
        adapter.send.assert_not_called()
        item.close()
        resumed = self.open(creating=False)
        self.assertEqual(resumed.owner.store.get('funding.plan'), retained_plan)
        self.assertTrue(resumed.owner.store.get('funding.prepare-started'))
        retried = self.fund_fixture(resumed)
        self.assertEqual(resumed.owner._fund()['action'], 'funding-submitted')
        retried.plan.assert_not_called()
        retried.prepare.assert_called_once_with(retained_plan)
        retried.send.assert_called_once()

    def test_failed_preparation_checkpoint_prevents_wallet_reservation_or_signing(self):
        item = self.open()
        adapter = self.fund_fixture(item)
        self.transport.fault = 'before-append'
        with self.assertRaises(AnchorUncertain): item.owner._fund()
        adapter.prepare.assert_not_called()
        adapter.send.assert_not_called()
        self.assertTrue(item.pending_path.exists())

    def test_post_journal_exposure_and_exact_bytes_are_anchored_before_claim_send(self):
        item = self.pair(self.open())
        session = item.owner.session
        raw, txid = self.fixture.native.wire()
        session.journal.prepare(session.id, 'xds-claim', raw, txid)
        underlying = Mock()
        session.adapters['xds'] = underlying
        def send(kind, wire, identity):
            self.assertEqual((kind, wire, identity), ('xds-claim', raw, txid))
            def check(store, journal):
                self.assertIsNotNone(journal)
                self.assertTrue(journal.exposed(session.id))
                intent = journal.intent(session.id, 'xds-claim')
                self.assertEqual((intent['payload'], intent['txid'], intent['stage']), (raw, txid, 'attempt-started'))
            self.inspect(item, check)
            return txid
        underlying.send.side_effect = send
        wrapped = session._adapter('xds-claim')
        with patch.object(session, 'observe', return_value=(ADMISSION, {})):
            result = session.journal._broadcast(session.id, 'xds-claim',
                lambda payload, identity: wrapped.send('xds-claim', payload, identity),
                lambda: ADMISSION, require_fresh=True)
        self.assertEqual(result, txid)
        underlying.send.assert_called_once()

    def test_post_journal_anchor_failure_preserves_exposure_without_sending(self):
        item = self.pair(self.open())
        session = item.owner.session
        raw, txid = self.fixture.native.wire()
        session.journal.prepare(session.id, 'xds-claim', raw, txid)
        underlying = Mock()
        session.adapters['xds'] = underlying
        self.transport.fault = 'after-append'
        wrapped = session._adapter('xds-claim')
        with self.assertRaises(AnchorUncertain):
            session.journal._broadcast(session.id, 'xds-claim',
                lambda payload, identity: wrapped.send('xds-claim', payload, identity), lambda: ADMISSION)
        underlying.send.assert_not_called()
        item.close()
        resumed = self.open(creating=False)
        self.assertTrue(resumed.owner.session.journal.exposed(session.id))
        self.assertEqual(resumed.owner.session.journal.intent(session.id, 'xds-claim')['stage'], 'attempt-started')
        self.assertFalse(resumed.owner.session._public_proof())

    def test_first_disclosure_rechecks_admission_after_external_checkpoint(self):
        item = self.pair(self.open())
        session = item.owner.session
        raw, txid = self.fixture.native.wire()
        session.journal.prepare(session.id, 'xds-claim', raw, txid)
        underlying = Mock()
        session.adapters['xds'] = underlying
        expired = Admission(20, 2, 1, 2, 50, True, True, True)
        wrapped = session._adapter('xds-claim')
        with patch.object(session, 'observe', return_value=(expired, {})):
            with self.assertRaisesRegex(ValueError, 'admission changed'):
                session.journal._broadcast(session.id, 'xds-claim',
                    lambda payload, identity: wrapped.send('xds-claim', payload, identity), lambda: ADMISSION)
        underlying.send.assert_not_called()
        self.assertTrue(session.journal.exposed(session.id))


def child_main(stage, directory, anchor_path):
    public = SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    with AnchorStore(anchor_path, service_id=SERVICE, stream_id=STREAM, writer_public_key=public) as store:
        client = AnchorClient(store.handle, service_id=SERVICE, stream_id=STREAM, writer_key=SIGNER)
        with AnchoredOwner(directory, recovery_fixture.KEY, recovery_fixture.no_rpc, recovery_fixture.no_rpc,
                           anchor_client=client) as item:
            original = item._accept
            def stop(head):
                if stage == 'before-accept': os._exit(73)
                if stage == 'after-accept':
                    original(head)
                    os._exit(73)
                os._exit(74)
            item._accept = stop
            def action():
                item.owner.store.put('child.marker', stage)
                return dict(action='fixture-child-state')
            item.owner.step = action
            item.step()
    os._exit(74)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child': child_main(*sys.argv[2:])
    unittest.main()
