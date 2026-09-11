"""Owner durability/routing faults, with explicit mocked chain observations.

Actual signing/finality are exercised in adapter and opt-in paired node tests.
These tests use real encrypted stores, mailboxes, backups and reopen/restore.
"""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from swap_runtime.lifecycle import Owner
from swap_runtime.owner_protocol import PublicExchange, offer_hash
from test_owner_protocol import configuration


class OwnerGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mailbox = self.root / 'mailbox'
        self.mailbox.mkdir()
        self.offer, self.keys = configuration()
        self.secret = b's' * 32
        self.offer['xds']['hashlock'] = hashlib.sha256(self.secret).hexdigest()
        self.offer['foreign']['contract']['hashlock'] = self.offer['xds']['hashlock']
        self.key = b'k' * 32
        self.rpc = Mock(side_effect=AssertionError('No unexpected chain operation'))

    def open(self, role='foreign-owner', directory=None, new=True):
        directory = directory or self.root / role
        side = 'claim' if role == 'foreign-owner' else 'refund'
        wallet = Mock(return_value=dict(genesis_hash=self.offer['xds']['genesis_hash'],
            commitment=self.offer['xds'][side + '_commitment'], address=self.offer['xds'][side + '_address']))
        credentials = dict(xds_rho='31' * 32,
            foreign_key=self.keys[role].private_numbers().private_value.to_bytes(32, 'big').hex())
        if role == 'foreign-owner':
            credentials['secret'] = self.secret.hex()
        owner = Owner(directory, self.key, self.rpc, self.rpc, wallet=wallet,
                      exchange_dir=self.mailbox, backup_dir=self.root / 'backups',
                      offer=self.offer if new else None, role=role if new else None,
                      credentials=credentials if new else None)
        self.addCleanup(owner.close)
        return owner

    def accept(self, role):
        PublicExchange(self.mailbox, self.offer).publish(role, 'accept',
            {'offer_hash': offer_hash(self.offer)}, self.keys[role])

    def fund_fixture(self, owner):
        # Wire semantics belong to adapter tests; coordinator must preserve this
        # identity even across a possibly accepted send and process restart.
        adapter = Mock()
        adapter.plan.return_value = {'selection': 'fixed'}
        adapter.prepare.return_value = (b'exact-retained-signed-artifact', '71' * 32)
        adapter.receipt.return_value = dict(status='unknown', final=False, publicly_observed=False)
        owner.foreign_funding = adapter
        owner._clock_ready = Mock(return_value=True)
        terms = dict(self.offer['foreign']['contract'], funding_txid='71' * 32, funding_vout=0)
        owner._funded_terms = Mock(return_value=terms)
        return adapter

    def test_status_and_backup_are_offline_and_create_no_funding(self):
        with self.open() as owner:
            self.assertFalse(owner.status()['own_funding_retained'])
            path = self.root / 'initial.backup'
            owner.backup(path)
            self.assertTrue(path.is_file())
            self.rpc.assert_not_called()
            self.assertIsNone(owner.store.get('funding.plan'))

    def test_no_peer_acceptance_no_plan_or_send(self):
        with self.open() as owner:
            result = owner.step()
            self.assertEqual(result['action'], 'wait-peer-acceptance')
            self.rpc.assert_not_called()
            self.assertIsNone(owner.store.get('funding.plan'))
            self.assertIsNotNone(owner.exchange.read('foreign-owner', 'accept'))

    def test_wrong_wallet_never_publishes_acceptance(self):
        with self.open() as owner:
            owner.wallet.return_value['address'] = 'other-wallet'
            with self.assertRaisesRegex(ValueError, 'identity'):
                owner.step()
            self.assertIsNone(owner.exchange.read(owner.role, 'accept'))

    def test_durable_exact_bytes_and_backup_precede_send(self):
        with self.open() as owner:
            adapter = self.fund_fixture(owner)
            def send(plan, raw, txid):
                stored = owner.store.get('funding.attempt')
                self.assertEqual((plan, raw.hex(), txid), (stored['plan'], stored['raw'], stored['txid']))
                self.assertTrue(list((self.root / 'backups').glob('*.backup')))
                self.assertTrue(owner.store.get('funding.send-started'))
            adapter.send.side_effect = send
            self.assertEqual(owner._fund()['action'], 'funding-submitted')
            self.assertIsNone(owner.exchange.read(owner.role, 'funding'))

    def test_backup_failure_prevents_any_transmission(self):
        with self.open() as owner:
            adapter = self.fund_fixture(owner)
            with patch.object(owner, '_checkpoint', side_effect=OSError('fixture disk full')):
                with self.assertRaises(OSError):
                    owner._fund()
            adapter.send.assert_not_called()
            self.assertIsNotNone(owner.store.get('funding.attempt'))

    def test_lost_ack_reopen_reconciles_without_reselection_or_resend(self):
        owner = self.open()
        adapter = self.fund_fixture(owner)
        adapter.send.side_effect = TimeoutError('fixture acknowledged nowhere')
        with self.assertRaises(TimeoutError):
            owner._fund()
        retained = owner.store.get('funding.attempt')
        owner.close()
        with self.open(new=False) as resumed:
            resumed.foreign_funding = adapter
            adapter.receipt.return_value = dict(status='pending', final=False, publicly_observed=True)
            self.assertEqual(resumed._fund()['action'], 'funding-observed')
            self.assertEqual(resumed.store.get('funding.attempt'), retained)
            self.assertEqual(adapter.prepare.call_count, 1)
            self.assertEqual(adapter.plan.call_count, 1)
            self.assertEqual(adapter.send.call_count, 1)
            self.assertEqual(resumed.exchange.read(resumed.role, 'funding'), retained)

    def test_changed_clock_after_backup_prevents_send(self):
        with self.open() as owner:
            adapter = self.fund_fixture(owner)
            owner._clock_ready.side_effect = [True, False]
            self.assertEqual(owner._fund()['action'], 'wait-funding-window')
            adapter.send.assert_not_called()

    def test_reopen_with_two_drafts_does_not_skip_unbroadcast_funding(self):
        owner = self.open()
        adapter = self.fund_fixture(owner)
        with patch.object(owner, '_checkpoint', side_effect=OSError('crash before send')):
            with self.assertRaises(OSError):
                owner._fund()
        owner.store.once('terms.xds', dict(self.offer['xds'], funding_txid='81' * 32, funding_vout=0))
        retained = owner.store.get('funding.attempt')
        owner.close()
        with self.open(new=False) as resumed:
            self.assertIsNone(resumed.session)
            self.assertFalse((resumed.directory / 'settlement.db').exists())
            self.assertIsNone(resumed.store.get('settlement.config'))
            resumed.foreign_funding = adapter
            resumed._clock_ready = Mock(return_value=True)
            self.assertEqual(resumed._fund()['action'], 'funding-submitted')
            self.assertEqual(resumed.store.get('funding.attempt'), retained)
            self.assertEqual(adapter.prepare.call_count, 1)
            adapter.send.assert_called_once_with(retained['plan'], bytes.fromhex(retained['raw']), retained['txid'])

    def test_restored_old_backup_never_creates_funding(self):
        with self.open() as owner:
            owner.backup(self.root / 'old.backup')
        destination = self.root / 'restored'
        Owner.restore(self.root / 'old.backup', destination, self.key)
        with self.open(directory=destination, new=False) as restored:
            adapter = self.fund_fixture(restored)
            self.assertTrue(restored.status()['recovery_required'])
            self.assertEqual(restored._fund()['action'], 'protective-no-funding')
            adapter.prepare.assert_not_called()
            adapter.plan.assert_not_called()
            adapter.send.assert_not_called()

    def test_restore_never_overwrites_original_or_existing_destination(self):
        with self.open() as owner:
            owner.backup(self.root / 'safe.backup')
            before = hashlib.sha256((self.root / 'safe.backup').read_bytes()).hexdigest()
            with self.assertRaises(FileExistsError):
                Owner.restore(self.root / 'safe.backup', owner.directory, self.key)
            self.assertEqual(hashlib.sha256((self.root / 'safe.backup').read_bytes()).hexdigest(), before)

    def test_restored_foreign_deposit_waits_without_native_wallet_or_peer(self):
        with self.open() as owner:
            self.fund_fixture(owner)
            owner._fund()
            owner.backup(self.root / 'waiting.backup')
        destination = self.root / 'waiting-restored'
        Owner.restore(self.root / 'waiting.backup', destination, self.key)
        with self.open(directory=destination, new=False) as restored:
            restored.wallet = None
            observation = Mock(return_value=dict(status='unspent', final=True, refund_eligible=False))
            restored._foreign_adapter = Mock(return_value=Mock(observe=observation))
            self.assertEqual(restored.step()['action'], 'protective-await-refund')
            observation.assert_called_once_with()
            self.rpc.assert_not_called()
            self.assertIsNone(restored.exchange.read(restored.role, 'accept'))

    def test_restore_without_deposit_never_requires_signing_wallet(self):
        with self.open() as owner:
            owner.backup(self.root / 'unfunded.backup')
        destination = self.root / 'unfunded-restored'
        Owner.restore(self.root / 'unfunded.backup', destination, self.key)
        with self.open(directory=destination, new=False) as restored:
            restored.wallet = None
            self.assertEqual(restored.step()['action'], 'protective-no-funding')
            self.rpc.assert_not_called()

    def test_native_uncertain_prepare_is_not_repeated(self):
        with self.open(role='xds-owner') as owner:
            owner._clock_ready = Mock(return_value=True)
            owner._peer_funding = Mock(return_value=True)
            owner._foreign_adapter = Mock(return_value=Mock(observe=Mock(return_value=dict(status='unspent', final=True))))
            owner.native_funding = Mock()
            owner.native_funding.plan.return_value = self.offer['xds']
            owner.native_funding.prepare.side_effect = TimeoutError('lost prepare response')
            with self.assertRaises(TimeoutError):
                owner._fund()
            self.assertEqual(owner._fund()['action'], 'native-prepare-response-uncertain')
            self.assertEqual(owner.native_funding.prepare.call_count, 1)
            owner.native_funding.send.assert_not_called()

    def test_cancellation_is_sticky_and_blocks_new_deposit(self):
        with self.open() as owner:
            adapter = self.fund_fixture(owner)
            self.assertEqual(owner.cancel()['action'], 'cancelled-await-refund')
            self.assertEqual(owner._fund()['action'], 'protective-no-funding')
            with self.assertRaises(ValueError):
                owner.store.put('cancelled', False)
            adapter.prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
