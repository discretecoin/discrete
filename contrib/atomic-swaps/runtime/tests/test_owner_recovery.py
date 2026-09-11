"""Owner session publication and recovery faults, without nodes or transmission.

SQLite, AEAD, signed offers, owner/session locks and abrupt child exits are real.
Funding receipt observations are mocked only in the final pairing guard tests.
Process interruption is not a claim of power-loss or whole-storage rollback safety.
"""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag
from swap_runtime.common import canonical
from swap_runtime.bitcoin import BitcoinAdapter
from swap_runtime.journal import Journal
from swap_runtime.lifecycle import Owner, _session_key
from swap_runtime.lifecycle_settlement import OwnerSession
from swap_runtime.lifecycle_store import OwnerStore
from swap_runtime.owner_protocol import PublicExchange, offer_hash
from test_bitcoin import FakeCore
from test_owner_protocol import configuration
from test_xds import Fixture as NativeFixture
from test_xds_discovery import DiscoveryFixture


KEY = bytes([53]) * 32  # Public laboratory encryption key, never an operator key.


def no_rpc(*_):
    raise AssertionError('Recovery/publication tests must not access chain or wallet RPC')


def child(stage, directory):
    owner = Owner(directory, KEY, no_rpc, no_rpc, wallet=no_rpc)
    if stage == 'during-stage':
        original = Journal.prepare
        def stop(self, swap, kind, *args, **kwargs):
            if kind == 'session':
                os._exit(73)
            return original(self, swap, kind, *args, **kwargs)
        Journal.prepare = stop
    elif stage in ('before-link', 'after-link'):
        original = os.link
        def stop(source, destination, *args, **kwargs):
            if Path(destination).name == 'settlement.db':
                if stage == 'after-link':
                    original(source, destination, *args, **kwargs)
                os._exit(73)
            return original(source, destination, *args, **kwargs)
        os.link = stop
    elif stage == 'after-pointer':
        original = owner.store.once
        def stop(name, value):
            result = original(name, value)
            if name == 'settlement.config':
                os._exit(73)
            return result
        owner.store.once = stop
    else:
        raise ValueError('Unknown owned crash fixture')
    owner._open_session()
    raise AssertionError('Requested crash boundary was not reached')


class OwnerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='owner-recovery-')
        self.root = Path(self.tmp.name)
        self.mailbox = self.root / 'mailbox'
        self.mailbox.mkdir()
        self.offer, _ = configuration()
        self.native, self.bitcoin = NativeFixture(), FakeCore()
        self.offer['xds'] = {k: v for k, v in self.native.terms.items()
                             if k not in ('funding_txid', 'funding_vout', 'funding_wire')}
        self.offer['xds']['net_amount_atoms'] = 1000
        self.offer['foreign']['contract'] = {k: v for k, v in self.bitcoin.terms.items()
                                           if k not in ('funding_txid', 'funding_vout')}
        self.secret = self.native.secret
        self.keys = {role: ec.derive_private_key(number, ec.SECP256K1())
                     for role, number in (('xds-owner', 12345), ('foreign-owner', 67890))}
        self.opened = []
        self.rpc = Mock(side_effect=no_rpc)

    def tearDown(self):
        for owner in reversed(self.opened):
            owner.close()
        self.tmp.cleanup()

    def open(self, directory=None, new=True, role='foreign-owner'):
        directory = directory or self.root / 'owner'
        credentials = dict(xds_rho='31' * 32,
            foreign_key=self.keys[role].private_numbers().private_value.to_bytes(32, 'big').hex())
        if role == 'foreign-owner':
            credentials['secret'] = self.secret.hex()
        owner = Owner(directory, KEY, self.rpc, self.rpc, wallet=self.rpc,
            exchange_dir=self.mailbox, backup_dir=self.root / 'backups',
            offer=self.offer if new else None, role=role if new else None,
            credentials=credentials if new else None)
        self.opened.append(owner)
        return owner

    def drafts(self, owner):
        owner.store.batch([('terms.xds', self.native.terms, True),
                           ('terms.foreign', self.bitcoin.terms, True)])

    def paired(self, role='foreign-owner', directory=None):
        owner = self.open(directory=directory, role=role)
        self.drafts(owner)
        owner._open_session()
        self.assertEqual(owner.session.config, owner.store.get('settlement.config'))
        return owner

    def crash(self, stage):
        owner = self.open()
        self.drafts(owner)
        directory = owner.directory
        owner.close()
        result = subprocess.run([sys.executable, '-B', __file__, '--child', stage, str(directory)],
            cwd=ROOT, timeout=20, capture_output=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors='replace'))
        with OwnerStore(directory / 'owner.db', KEY) as store:
            self.assertEqual(store.get('terms.xds'), self.native.terms)
            self.assertEqual(store.get('terms.foreign'), self.bitcoin.terms)
            self.assertIsNone(store.get('funding.attempt'))
            self.assertFalse(store.recovery_required())
            self.assertEqual(store.get('settlement.config') is not None, stage == 'after-pointer')
        published = (directory / 'settlement.db').exists()
        self.assertEqual(published, stage in ('after-link', 'after-pointer'))
        resumed = self.open(directory, new=False)
        self.assertEqual(resumed.session is not None, published)
        if not published:
            resumed._open_session()
        self.assertEqual(resumed.session.config, resumed.store.get('settlement.config'))
        self.assertIsNotNone(resumed.session.journal.intent(self.offer['swap_id'], 'session'))
        self.assertFalse(resumed.session.journal.recovery_required())
        self.assertIsNone(resumed.session.journal.intent(self.offer['swap_id'], 'xds-claim'))
        self.assertFalse(resumed.session.journal.exposed(self.offer['swap_id']))
        self.rpc.assert_not_called()

    def test_crash_during_stage_never_publishes_partial_session(self):
        self.crash('during-stage')

    def test_crash_before_link_leaves_drafts_retryable(self):
        self.crash('before-link')

    def test_crash_after_link_recovers_pointer_without_new_session(self):
        self.crash('after-link')

    def test_crash_after_pointer_commit_reopens_bound_session(self):
        self.crash('after-pointer')

    def test_live_owner_and_companion_locks_exclude_second_writer(self):
        owner = self.paired()
        with self.assertRaisesRegex(ValueError, 'already open'):
            Owner(owner.directory, KEY, self.rpc, self.rpc, wallet=self.rpc)
        with self.assertRaisesRegex(ValueError, 'already open'):
            OwnerSession(owner.directory / 'settlement.db', _session_key(KEY), self.offer['swap_id'],
                         self.rpc, self.rpc, self.rpc)
        owner.close()
        reopened = self.open(new=False)
        self.assertTrue(reopened.status()['paired'])
        self.rpc.assert_not_called()

    def test_session_publication_does_not_replace_an_existing_destination(self):
        owner = self.open()
        self.drafts(owner)
        original = os.link
        destination = owner.directory / 'settlement.db'
        sentinel = b'existing session path must remain untouched'
        def occupied(source, target):
            self.assertEqual(Path(target), destination)
            destination.write_bytes(sentinel)
            return original(source, target)
        with patch('swap_runtime.lifecycle.os.link', side_effect=occupied):
            with self.assertRaises(FileExistsError):
                owner._open_session()
        self.assertEqual(destination.read_bytes(), sentinel)
        self.assertIsNone(owner.store.get('settlement.config'))
        self.assertIsNone(owner.session)
        self.rpc.assert_not_called()

    def test_snapshot_preserves_exact_intent_and_both_recovery_markers(self):
        owner = self.paired()
        raw, txid = self.native.wire()
        owner.session.journal.prepare(self.offer['swap_id'], 'xds-claim', raw, txid)
        original = owner.session.journal.intent(self.offer['swap_id'], 'xds-claim')
        snapshot = owner.backup(self.root / 'paired.backup')
        before = snapshot.read_bytes()
        owner.close()
        destination = self.root / 'recovered'
        opened_journals = []
        original_restore = Journal.restore
        def tracked_restore(*args):
            journal = original_restore(*args)
            opened_journals.append(journal)
            return journal
        with patch('swap_runtime.lifecycle.Journal.restore', side_effect=tracked_restore):
            result = Owner.restore(snapshot, destination, KEY)
        self.assertTrue(result['recovery_required'])
        self.assertEqual(len(opened_journals), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened_journals[0].db.execute('SELECT 1')
        restored = self.open(destination, new=False)
        self.assertTrue(restored.store.recovery_required())
        self.assertTrue(restored.session.journal.recovery_required())
        self.assertEqual(restored.session.journal.intent(self.offer['swap_id'], 'xds-claim'), original)
        self.assertFalse(restored._first_claim_ready({}))
        self.assertEqual(restored._fund()['action'], 'protective-no-funding')
        self.assertEqual(snapshot.read_bytes(), before)
        self.rpc.assert_not_called()

    def test_restore_terms_without_companion_creates_only_protective_session(self):
        owner = self.open()
        self.drafts(owner)
        snapshot = owner.backup(self.root / 'known-terms.backup')
        owner.close()
        destination = self.root / 'terms-recovered'
        Owner.restore(snapshot, destination, KEY)
        restored = self.open(destination, new=False)
        self.assertIsNone(restored.session)
        restored._open_session()
        self.assertTrue(restored.session.journal.recovery_required())
        self.assertTrue(restored.store.recovery_required())
        self.assertIsNone(restored.session.journal.intent(self.offer['swap_id'], 'xds-claim'))
        self.assertEqual(restored._fund()['action'], 'protective-no-funding')
        restored.close()
        reopened = self.open(destination, new=False)
        self.assertTrue(reopened.session.journal.recovery_required())
        self.rpc.assert_not_called()

    def test_missing_committed_companion_is_never_silently_regenerated(self):
        owner = self.paired()
        directory = owner.directory
        pointer = owner.store.get('settlement.config')
        owner.close()
        # Isolated fixture deletion represents a missing file, not a node attack.
        (directory / 'settlement.db').unlink()
        resumed = self.open(directory, new=False)
        self.assertIsNone(resumed.session)
        with self.assertRaisesRegex(ValueError, 'journal missing'):
            resumed._open_session()
        self.assertEqual(resumed.store.get('settlement.config'), pointer)
        self.assertFalse((directory / 'settlement.db').exists())
        self.rpc.assert_not_called()

    def foreign_companion(self, owner, key=None, changes=None):
        config = copy.deepcopy(owner.session.config)
        config.update(changes or {'swap_id': 'different-authenticated-swap'})
        path = self.root / 'foreign-session.db'
        with OwnerSession(path, key or _session_key(KEY), config['swap_id'], self.rpc, self.rpc,
                          self.rpc, config=config) as other:
            snapshot = other.snapshot(self.root / 'foreign-session.snapshot')
        return snapshot.read_bytes()

    def test_restore_rejects_authenticated_wrong_swap_companion_before_success(self):
        owner = self.paired()
        companion = self.foreign_companion(owner)
        snapshot = self.root / 'mismatched.backup'
        owner.store.backup(snapshot, companion=companion)
        before = snapshot.read_bytes()
        destination = self.root / 'mismatch-recovery'
        with self.assertRaises((ValueError, KeyError)):
            Owner.restore(snapshot, destination, KEY)
        self.assertEqual(snapshot.read_bytes(), before)
        with OwnerStore(destination / 'owner.db', KEY) as restored:
            self.assertTrue(restored.recovery_required())
        self.rpc.assert_not_called()

    def test_restore_rejects_same_swap_with_opposite_owner_role(self):
        owner = self.paired()
        companion = self.foreign_companion(owner, changes={'role': 'xds-owner'})
        snapshot = self.root / 'wrong-role.backup'
        owner.store.backup(snapshot, companion=companion)
        destination = self.root / 'wrong-role-recovery'
        with self.assertRaisesRegex(ValueError, 'companion differs'):
            Owner.restore(snapshot, destination, KEY)
        with OwnerStore(destination / 'owner.db', KEY) as restored:
            self.assertTrue(restored.recovery_required())
        self.rpc.assert_not_called()

    def test_wrong_companion_encryption_key_cannot_report_success(self):
        owner = self.paired()
        companion = self.foreign_companion(owner, b'z' * 32)
        snapshot = self.root / 'wrong-key.backup'
        owner.store.backup(snapshot, companion=companion)
        destination = self.root / 'wrong-key-recovery'
        with self.assertRaises(InvalidTag):
            Owner.restore(snapshot, destination, KEY)
        with OwnerStore(destination / 'owner.db', KEY) as restored:
            self.assertTrue(restored.recovery_required())
        self.assertFalse((destination / 'companion.snapshot').exists())
        self.rpc.assert_not_called()

    def test_restore_refuses_normal_companion_substitution_in_recovery_owner(self):
        owner = self.paired()
        ordinary = owner.session.snapshot(self.root / 'ordinary.snapshot').read_bytes()
        snapshot = owner.backup(self.root / 'normal-pair.backup')
        destination = self.root / 'substitution-recovery'
        Owner.restore(snapshot, destination, KEY)
        # Fault-injected backup operator mix-up; no crafted signed transaction.
        (destination / 'settlement.db').write_bytes(ordinary)
        with self.assertRaisesRegex(ValueError, 'recovery provenance'):
            self.open(destination, new=False)
        with OwnerStore(destination / 'owner.db', KEY) as restored:
            self.assertTrue(restored.recovery_required())
        self.rpc.assert_not_called()

    def test_failed_finalized_solana_funding_never_pairs_or_publishes(self):
        offer, keys = configuration('solana')
        secret = b'q' * 32
        offer['xds']['hashlock'] = offer['foreign']['hashlock'] = hashlib.sha256(secret).hexdigest()
        with Owner(self.root / 'solana-owner', KEY, self.rpc, self.rpc, wallet=self.rpc,
                   exchange_dir=self.mailbox, backup_dir=self.root / 'backups', offer=offer,
                   role='foreign-owner', credentials=dict(xds_rho='31' * 32,
                   foreign_key=bytes(keys['foreign-owner']).hex(), secret=secret.hex())) as owner:
            PublicExchange(self.mailbox, offer).publish('xds-owner', 'accept',
                {'offer_hash': offer_hash(offer)}, keys['xds-owner'])
            packet = dict(plan={'retained': True}, raw=b'owned signed fixture'.hex(), txid='signedFixture')
            owner.store.batch([('funding.attempt', packet, True), ('peer.funding', packet, True)])
            owner._own_refund = Mock(return_value=None)
            owner._identity = Mock()
            owner._peer_funding = Mock(return_value=True)
            owner._open_session = Mock(side_effect=AssertionError('Failed funding cannot pair'))
            owner._solana_expired = Mock(return_value=False)
            adapter = owner.foreign_funding = Mock()
            adapter.receipt.return_value = dict(status='failed', final=True, publicly_observed=False)
            result = owner.step()
            self.assertEqual(result['action'], 'funding-failed-await-expiry')
            owner._open_session.assert_not_called()
            adapter.prepare.assert_not_called()
            adapter.send.assert_not_called()
            self.assertIsNone(owner.exchange.read('foreign-owner', 'funding'))
            self.assertIsNone(owner.store.get('settlement.config'))
            self.assertFalse((owner.directory / 'settlement.db').exists())
            self.assertNotIn(secret.hex(), canonical(result).decode())
        self.rpc.assert_not_called()

    def claim_after_refund(self, status, witness):
        owner = self.paired(role='xds-owner', directory=self.root / ('owner-' + status))
        discovery = DiscoveryFixture()
        discovery.f = self.native
        owner.daemon = discovery.rpc
        core = FakeCore()
        owner.session.adapters['foreign'] = BitcoinAdapter(core.rpc, self.bitcoin.terms)
        raw, txid = self.native.wire('xds-refund')
        refund = dict(kind='xds-refund', raw=raw.hex(), txid=txid)
        owner.store.once('refund.intent', refund)
        owner._own_refund = Mock(return_value=dict(action='refund-observed', status=status, final=False))
        public = discovery.add() if witness else None
        return owner, discovery, core, refund, public

    def test_conflicting_or_failed_refund_allows_claim_only_after_actual_public_scan(self):
        for status in ('conflict', 'failed'):
            with self.subTest(status=status):
                owner, discovery, core, refund, public = self.claim_after_refund(status, True)
                result = owner.step()
                self.assertEqual(result['action'], 'claim-submitted')
                proof = owner.store.get('scanner.claim')
                self.assertEqual(proof['txid'], public[1])
                self.assertEqual(proof['raw'], public[0].hex())
                self.assertTrue(proof['acquisition']['full_wire_fetched'])
                self.assertTrue(owner.session._public_proof())
                intent = owner.session.journal.intent(self.offer['swap_id'], 'foreign-claim')
                self.assertEqual(core.spend, intent['payload'])
                self.assertEqual(owner.store.get('refund.intent'), refund)
                self.assertNotIn(self.secret.hex(), canonical(result).decode())
                self.assertTrue(any(method == 'getrawtransactionspool' for method, _ in discovery.calls))
                owner.close()
        self.rpc.assert_not_called()

    def test_refund_conflict_without_public_witness_never_prepares_foreign_claim(self):
        owner, discovery, core, refund, _ = self.claim_after_refund('conflict', False)
        result = owner.step()
        self.assertEqual((result['action'], result['status']), ('refund-observed', 'conflict'))
        self.assertIsNone(owner.store.get('scanner.claim'))
        self.assertIsNone(owner.session.journal.intent(self.offer['swap_id'], 'foreign-claim'))
        self.assertIsNone(core.spend)
        self.assertEqual(owner.store.get('refund.intent'), refund)
        self.assertTrue(discovery.calls)
        self.rpc.assert_not_called()

    def test_confirmed_refund_does_not_dispatch_a_claim_or_scan(self):
        owner, discovery, core, _, _ = self.claim_after_refund('confirmed', True)
        result = owner.step()
        self.assertEqual((result['action'], result['status']), ('refund-observed', 'confirmed'))
        self.assertFalse(discovery.calls)
        self.assertIsNone(owner.session.journal.intent(self.offer['swap_id'], 'foreign-claim'))
        self.assertIsNone(core.spend)
        self.rpc.assert_not_called()


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        child(sys.argv[2], sys.argv[3])
    else:
        unittest.main(verbosity=2)
