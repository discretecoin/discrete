"""Owner engine with real Solana ELF/System/SPL/ATA VM and native wire crypto.

Native ledger membership, mining and RPC discovery are controlled fixtures;
Solana RPC contexts/finality are also fixtures around actual LiteSVM execution.
These tests qualify coordinator wiring, durability and token ownership, not a
distributed network, real RPC finality or independent owner process custody.
The subsequent ordinary SPL spend is signed in a separate process with only
the corresponding owner's key. No private material appears in public results.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from solders.account import Account
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata

from swap_runtime.lifecycle import Owner
from swap_runtime.owner_protocol import PublicExchange, offer_hash
from swap_runtime.solana_funding import SolanaFundingAdapter
from swap_runtime.xds import _parse, TX_SWAP_FUND
from test_owner_protocol import configuration
import test_solana_funding as sf
from test_xds_funding import FundingFixture as NativeFixture


class NativeLedger:
    """Real ML-DSA native wire validation, explicit synthetic membership."""
    def __init__(self):
        self.f = NativeFixture()
        self.s = self.f.s
        self.s.funding = self.f.raw
        self.s.terms.update(funding_wire=self.f.raw.hex(), funding_txid=self.f.txid)
        self.funding_sent = False
        self.fail_lookup = False

    def wallet(self, method, params):
        return self.f.wallet(method, params) if method == 'swap_prepare_funding' else self.s.wallet(method, params)

    def rpc(self, method, params):
        if self.fail_lookup:
            raise ValueError('Fixture native history unavailable')
        self.s.height = self.f.height
        if method == 'getinfo': return self.s.rpc(method, params)
        if method == 'get_swap_outpoint':
            if params['txid'] in self.f.sources: return self.f.rpc(method, params)
            if params['txid'] == self.f.txid and not self.funding_sent: return self.f.state()
            return self.s.rpc(method, params)
        if method == 'sendrawtransaction':
            if _parse(bytes.fromhex(params['tx_as_hex']))['family'] == TX_SWAP_FUND:
                result = self.f.rpc(method, params)
                self.f.entries[self.f.txid] = (self.f.raw, 10)
                self.funding_sent = True
                return result
            return self.s.rpc(method, params)
        if method == 'getrawtransactionspool':
            entries = []
            for txid, (raw, height) in self.s.entries.items():
                if height is None:
                    branch = _parse(raw)['inputs'][0]['branch']
                    entries.append(dict(hash=txid, coinbase=False, transaction=dict(tx_type=5,
                        vin=[dict(type='20', value=dict(prev_txid=self.f.txid, prev_out_index=0, branch=branch))])))
            return dict(status='OK', transactions=entries)
        # The scanner retains the independently checked mempool candidate even
        # if its subsequent block-page pass is unavailable in this fixture.
        raise ValueError('Native fixture RPC outside controlled scope')


class OwnerSolanaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-solana-vm-')
        self.root = Path(self.temp.name)
        self.mail = self.root / 'mail'; self.mail.mkdir()
        self.native, self.sol = NativeLedger(), sf.Fixture()
        self.sol.secret = self.native.s.secret
        self.sol.terms['hashlock'] = hashlib.sha256(self.sol.secret).hexdigest()
        self.sol.adapter = SolanaFundingAdapter(self.sol.rpc, self.sol.terms)
        self.offer, _ = configuration('solana')
        self.offer.update(xds=copy.deepcopy(self.native.f.terms), foreign=copy.deepcopy(self.sol.terms))
        self.owners = []
        self.encryption = {'xds-owner': bytes([41]) * 32, 'foreign-owner': bytes([42]) * 32}
        self.keys = {'xds-owner': self.sol.claimant, 'foreign-owner': self.sol.owner}

    def tearDown(self):
        for owner in reversed(self.owners): owner.close()
        self.temp.cleanup()

    def open(self, role, existing=False, directory=None):
        path = directory or self.root / role
        kwargs = dict(wallet=self.native.wallet)
        if not existing:
            credentials = dict(xds_rho=self.native.s.rhos[1 if role == 'xds-owner' else 0].hex(),
                               foreign_key=bytes(self.keys[role]).hex())
            if role == 'foreign-owner': credentials['secret'] = self.native.s.secret.hex()
            kwargs.update(offer=self.offer, role=role, credentials=credentials,
                          exchange_dir=self.mail, backup_dir=self.root / (role + '-backups'))
        owner = Owner(path, self.encryption[role], self.native.rpc, self.sol.rpc, **kwargs)
        self.owners.append(owner)
        return owner

    def accept_peer(self, role='foreign-owner'):
        peer = 'xds-owner' if role == 'foreign-owner' else 'foreign-owner'
        exchange = PublicExchange(self.mail, self.offer)
        exchange.publish(peer, 'accept', {'offer_hash': offer_hash(self.offer)}, self.keys[peer])

    def fund_foreign(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        self.assertEqual(bob.step()['action'], 'funding-submitted')
        self.assertEqual(len(self.sol.sent), 1)
        self.assertNotIsInstance(self.sol.sent[-1][1], FailedTransactionMetadata)
        return bob

    def pair(self):
        alice, bob = self.open('xds-owner'), self.open('foreign-owner')
        self.assertEqual(alice.step()['action'], 'wait-peer-acceptance')
        self.assertEqual(bob.step()['action'], 'funding-submitted')
        self.assertEqual(bob.step()['action'], 'funding-observed')
        self.assertEqual(alice.step()['action'], 'funding-submitted')
        self.assertEqual(alice.step()['action'], 'paired-contracts-observed')
        self.assertEqual(bob.step()['action'], 'paired-contracts-observed')
        self.assertIsNotNone(alice.session); self.assertIsNotNone(bob.session)
        return alice, bob

    def assert_public_results(self, value):
        text = json.dumps(value)
        for material in (self.native.s.secret.hex(), bytes(self.sol.owner).hex(), bytes(self.sol.claimant).hex()):
            self.assertNotIn(material, text)

    def test_foreign_owner_requires_acceptance_then_persists_before_actual_funding(self):
        bob = self.open('foreign-owner')
        self.assertEqual(bob.step()['action'], 'wait-peer-acceptance')
        self.assertFalse(self.sol.sent)
        self.accept_peer()
        original = self.sol.rpc
        observed = []
        def inspect_send(method, params):
            if method == 'sendTransaction':
                packet = bob.store.get('funding.attempt')
                observed.append(packet)
                self.assertIsNotNone(packet)
                self.assertIsNotNone(bob.store.get('funding.acquisition'))
                self.assertTrue(list(bob.backup_dir.glob('*.backup')))
            return original(method, params)
        bob.foreign_funding._rpc = inspect_send
        result = bob.step()
        self.assertEqual(result['action'], 'funding-submitted'); self.assert_public_results(result)
        self.assertEqual(len(observed), 1)
        packet = observed[0]; plan = packet['plan']
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), self.sol.terms['amount'])
        self.assertEqual(self.sol.balance(self.sol.source), 10_000_000 - self.sol.terms['amount'])
        self.assertIsNone(bob.exchange.read('foreign-owner', 'funding'))
        self.assertEqual(bob.step()['action'], 'funding-observed')
        self.assertEqual(bob.exchange.read('foreign-owner', 'funding'), packet)

    def test_restart_after_lost_funding_ack_uses_exact_receipt_without_second_deposit(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        original = bob.foreign_funding._rpc
        def lost_ack(method, params):
            result = original(method, params)
            if method == 'sendTransaction': raise TimeoutError('private fixture transport detail')
            return result
        bob.foreign_funding._rpc = lost_ack
        with patch.object(bob.foreign_funding, 'prepare', wraps=bob.foreign_funding.prepare) as prepare, \
                patch.object(bob, '_renew', wraps=bob._renew) as renew:
            result = bob.step()
            self.assertEqual(result['action'], 'funding-unknown')
            self.assert_public_results(result)
            self.assertNotIn('private fixture', json.dumps(result))
            self.assertEqual(prepare.call_count, 1); renew.assert_not_called()
        self.assertIsNone(bob.store.get('funding.attempt.1'))
        self.assertIsNotNone(bob.store.get('funding.acquisition'))
        packet = bob.store.get('funding.attempt'); bob.close()
        reopened = self.open('foreign-owner', existing=True)
        with patch.object(reopened.foreign_funding, 'prepare', wraps=reopened.foreign_funding.prepare) as prepare:
            self.assertEqual(reopened.step()['action'], 'funding-observed')
            prepare.assert_not_called()
        self.assertEqual(reopened.store.get('funding.attempt'), packet)
        self.assertEqual(len(self.sol.sent), 1)
        self.assertEqual(self.sol.balance(packet['plan']['accounts']['vault']), self.sol.terms['amount'])

    def test_funding_finalizes_during_exact_resend_guard_without_replacement_or_second_send(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        original = bob.foreign_funding._rpc
        requests = []
        def pending_ack(method, params):
            if method == 'sendTransaction':
                requests.append(copy.deepcopy(params))
                txid = str(Transaction.from_bytes(base64.b64decode(params[0])).signatures[0])
                return txid
            return original(method, params)
        bob.foreign_funding._rpc = pending_ack
        self.assertEqual(bob.step()['action'], 'funding-submitted')
        packet = bob.store.get('funding.attempt')
        acquisition = bob.store.get('funding.acquisition')
        self.assertEqual(len(requests), 1); self.assertFalse(self.sol.sent)
        self.assertEqual(bob.foreign_funding.receipt(
            packet['plan'], bytes.fromhex(packet['raw']), packet['txid'])['status'], 'unknown')
        # The prior accepted request finishes between the resend's first and
        # second account snapshots. This is execution of that queued request,
        # not another coordinator send.
        finalized = []
        def finalize_during_guard(method, params):
            if method == 'getFeeForMessage' and not finalized:
                finalized.append(original('sendTransaction', requests[0]))
            return pending_ack(method, params)
        bob.foreign_funding._rpc = finalize_during_guard
        with patch.object(bob.foreign_funding, 'prepare', wraps=bob.foreign_funding.prepare) as prepare, \
                patch.object(bob, '_renew', wraps=bob._renew) as renew:
            result = bob.step()
            self.assertEqual(result['action'], 'funding-unknown'); self.assert_public_results(result)
            prepare.assert_not_called(); renew.assert_not_called()
            self.assertEqual(bob.step()['action'], 'funding-observed')
            prepare.assert_not_called(); renew.assert_not_called()
        self.assertEqual(finalized, [packet['txid']])
        self.assertEqual(len(requests), 1); self.assertEqual(len(self.sol.sent), 1)
        self.assertNotIsInstance(self.sol.sent[0][1], FailedTransactionMetadata)
        self.assertEqual(self.sol.sent[0][0].hex(), packet['raw'])
        self.assertEqual(bob.store.get('funding.attempt'), packet)
        self.assertEqual(bob.store.get('funding.acquisition'), acquisition)
        self.assertIsNone(bob.store.get('funding.attempt.1'))
        self.assertEqual(bob.exchange.read('foreign-owner', 'funding'), packet)
        self.assertEqual(self.sol.balance(packet['plan']['accounts']['vault']), self.sol.terms['amount'])

    def test_live_blockhash_send_failure_retains_exact_funding_for_retry(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        original = bob.foreign_funding._rpc
        requests = []
        def unavailable_once(method, params):
            if method == 'sendTransaction':
                requests.append(copy.deepcopy(params))
                if len(requests) == 1:
                    raise TimeoutError('private fixture transport detail')
            return original(method, params)
        bob.foreign_funding._rpc = unavailable_once
        with patch.object(bob.foreign_funding, 'prepare', wraps=bob.foreign_funding.prepare) as prepare, \
                patch.object(bob, '_renew', wraps=bob._renew) as renew:
            result = bob.step()
            self.assertEqual(result['action'], 'funding-unknown'); self.assert_public_results(result)
            self.assertNotIn('private fixture', json.dumps(result))
            packet = bob.store.get('funding.attempt')
            acquisition = bob.store.get('funding.acquisition')
            self.assertFalse(self.sol.sent)
            self.assertEqual(str(self.sol.vm.latest_blockhash()), acquisition['recent_blockhash'])
            self.assertEqual(bob.step()['action'], 'funding-submitted')
            self.assertEqual(bob.step()['action'], 'funding-observed')
            self.assertEqual(prepare.call_count, 1); renew.assert_not_called()
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0][0], requests[1][0])
        self.assertEqual(base64.b64decode(requests[1][0]).hex(), packet['raw'])
        self.assertEqual(len(self.sol.sent), 1)
        self.assertEqual(bob.store.get('funding.attempt'), packet)
        self.assertEqual(bob.store.get('funding.acquisition'), acquisition)
        self.assertIsNone(bob.store.get('funding.attempt.1'))
        self.assertEqual(self.sol.balance(packet['plan']['accounts']['vault']), self.sol.terms['amount'])

    def test_lost_refund_ack_retains_exact_intent_and_recovers_receipt_without_renewal(self):
        bob = self.fund_foreign()
        plan = bob.store.get('funding.attempt')['plan']
        self.sol.vm.warp_to_slot(self.sol.terms['deadline_slot']); self.sol.expire()
        adapter = bob._foreign_adapter()
        original = adapter._rpc
        def lost_ack(method, params):
            result = original(method, params)
            if method == 'sendTransaction': raise TimeoutError('private fixture transport detail')
            return result
        adapter._rpc = lost_ack
        with patch.object(bob, '_foreign_adapter', return_value=adapter), \
                patch.object(adapter, 'prepare', wraps=adapter.prepare) as prepare, \
                patch.object(bob, '_renew', wraps=bob._renew) as renew:
            result = bob.step()
            self.assertEqual(result['action'], 'refund-unknown'); self.assert_public_results(result)
            self.assertNotIn('private fixture', json.dumps(result))
            intent = bob.store.get('refund.intent')
            self.assertIsNotNone(bob.store.get('refund.acquisition'))
            self.assertEqual(bob.step()['action'], 'refund-observed')
            self.assertEqual(prepare.call_count, 1); renew.assert_not_called()
        self.assertEqual(bob.store.get('refund.intent'), intent)
        self.assertIsNone(bob.store.get('refund.intent.1'))
        self.assertEqual(len(self.sol.sent), 2)
        self.assertNotIsInstance(self.sol.sent[-1][1], FailedTransactionMetadata)
        self.assertEqual(self.sol.sent[-1][0].hex(), intent['raw'])
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), 0)
        self.assertEqual(self.sol.balance(plan['accounts']['refund']), self.sol.terms['amount'])

    def test_unpaired_cancel_refunds_and_independent_owner_spends_spl_after_restart(self):
        bob = self.fund_foreign(); packet = bob.store.get('funding.attempt')
        self.assertEqual(bob.cancel()['action'], 'cancelled-await-refund')
        self.assertEqual(bob.step()['action'], 'cancelled-await-refund')
        bob.close(); bob = self.open('foreign-owner', existing=True)
        self.sol.vm.warp_to_slot(self.sol.terms['deadline_slot']); self.sol.expire()
        self.assertEqual(bob.step()['action'], 'refund-submitted')
        self.assertEqual(bob.step()['action'], 'refund-observed')
        plan = packet['plan']
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), 0)
        self.assertEqual(self.sol.balance(plan['accounts']['refund']), self.sol.terms['amount'])
        helper = sf.SolanaFundingTests('runTest')
        helper._ordinary_spend(self.sol, plan['accounts']['refund'], str(self.sol.source), self.sol.claimant, success=False)
        helper._ordinary_spend(self.sol, plan['accounts']['refund'], str(self.sol.source), self.sol.owner)
        self.assertEqual(self.sol.balance(self.sol.source), 10_000_000)
        self.assertEqual(len(self.native.s.sent), 0)

    def test_two_owner_pair_discovers_public_native_witness_and_claimant_spends_spl(self):
        alice, bob = self.pair()
        self.assertEqual(alice.session.config['foreign']['payer'], str(self.sol.claimant.pubkey()))
        self.assertEqual(bob.session.config['foreign']['payer'], str(self.sol.owner.pubkey()))
        self.assertEqual(bob.step()['action'], 'claim-submitted')
        self.assertEqual(len(self.native.s.sent), 1)
        result = alice.step(); self.assertEqual(result['action'], 'claim-submitted'); self.assert_public_results(result)
        proof = alice.store.get('scanner.claim')
        self.assertEqual(proof['secret'], self.native.s.secret.hex())
        self.assertEqual(alice.step()['action'], 'claim-observed')
        plan = bob.store.get('funding.attempt')['plan']
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), 0)
        self.assertEqual(self.sol.balance(plan['accounts']['claim']), self.sol.terms['amount'])
        alice.close(); alice = self.open('xds-owner', existing=True)
        sent = len(self.sol.sent)
        self.assertEqual(alice.step()['action'], 'claim-observed'); self.assertEqual(len(self.sol.sent), sent)
        helper = sf.SolanaFundingTests('runTest')
        helper._ordinary_spend(self.sol, plan['accounts']['claim'], plan['accounts']['refund'], self.sol.owner, success=False)
        helper._ordinary_spend(self.sol, plan['accounts']['claim'], plan['accounts']['refund'], self.sol.claimant)
        self.assertEqual(self.sol.balance(plan['accounts']['claim']), 0)
        self.assertEqual(self.sol.balance(plan['accounts']['refund']), self.sol.terms['amount'])

    def test_claimant_fee_unreadiness_blocks_first_native_secret_and_preserves_deposits(self):
        alice, bob = self.pair()
        key = self.sol.claimant.pubkey(); account = self.sol.vm.get_account(key)
        self.sol.vm.set_account(key, Account(1, account.data, account.owner))
        result = bob.step()
        self.assertEqual(result['action'], 'wait-first-claim-admission')
        self.assertFalse(self.native.s.sent)
        self.assertIsNone(bob.session.journal.intent(bob.offer['swap_id'], 'xds-claim'))
        self.assertFalse(bob.session.journal.exposed(bob.offer['swap_id']))

    def test_restored_prefunding_backup_cannot_create_a_deposit(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        snapshot = bob.backup(self.root / 'before-funding.backup'); bob.close()
        restored_path = self.root / 'restored-owner'
        self.assertTrue(Owner.restore(snapshot, restored_path, self.encryption['foreign-owner'])['recovery_required'])
        restored = self.open('foreign-owner', existing=True, directory=restored_path)
        self.assertEqual(restored.step()['action'], 'protective-no-funding')
        self.assertFalse(self.sol.sent)

    def test_restore_existing_funded_owner_preserves_identity_and_can_only_refund(self):
        bob = self.fund_foreign(); packet = bob.store.get('funding.attempt')
        snapshot = bob.backup(self.root / 'funded.backup'); bob.close()
        restored_path = self.root / 'restored-funded-owner'
        Owner.restore(snapshot, restored_path, self.encryption['foreign-owner'])
        restored = self.open('foreign-owner', existing=True, directory=restored_path)
        restored.wallet = None
        self.assertEqual(restored.step()['action'], 'protective-await-refund')
        self.assertEqual(restored.store.get('funding.attempt'), packet); self.assertEqual(len(self.sol.sent), 1)
        self.sol.vm.warp_to_slot(self.sol.terms['deadline_slot']); self.sol.expire()
        self.assertEqual(restored.step()['action'], 'refund-submitted')
        self.assertEqual(restored.step()['action'], 'refund-observed')
        self.assertEqual(self.sol.balance(packet['plan']['accounts']['refund']), self.sol.terms['amount'])
        self.assertFalse(self.native.s.sent)

    def test_expired_unsent_funding_after_restart_renews_same_escrow_then_deposits_once(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        with patch.object(bob, '_checkpoint', side_effect=RuntimeError('fixture stopped before send')):
            with self.assertRaises(RuntimeError): bob.step()
        original = bob.store.get('funding.attempt')
        acquisition = bob.store.get('funding.acquisition')
        self.assertIsNotNone(acquisition); self.assertFalse(self.sol.sent)
        bob.close(); self.sol.expire()
        self.assertIsInstance(self.sol.vm.send_transaction(Transaction.from_bytes(bytes.fromhex(original['raw']))), FailedTransactionMetadata)
        resumed = self.open('foreign-owner', existing=True)
        self.assertEqual(resumed.step()['action'], 'funding-renewed')
        latest = resumed._attempt('funding')
        self.assertEqual(resumed.store.get('funding.attempt'), original)
        self.assertEqual(latest['plan'], original['plan']); self.assertNotEqual(latest['txid'], original['txid'])
        renewal = resumed.store.get('funding.renewal.1')
        self.assertGreater(renewal['expiry_context_slot'], acquisition['context_slot'])
        self.assertEqual(resumed.step()['action'], 'funding-submitted')
        self.assertEqual(resumed.step()['action'], 'funding-observed')
        self.assertEqual(resumed.exchange.read('foreign-owner', 'funding'), latest)
        self.assertEqual(len(self.sol.sent), 1)
        self.assertEqual(self.sol.balance(original['plan']['accounts']['vault']), self.sol.terms['amount'])

    def test_expired_unsent_refund_after_restart_preserves_original_attempt_and_principal(self):
        bob = self.fund_foreign()
        plan = bob.store.get('funding.attempt')['plan']
        self.sol.vm.warp_to_slot(self.sol.terms['deadline_slot']); self.sol.expire()
        with patch.object(bob, '_checkpoint', side_effect=RuntimeError('fixture stopped before refund send')):
            with self.assertRaises(RuntimeError): bob.step()
        original = bob.store.get('refund.intent'); acquisition = bob.store.get('refund.acquisition')
        self.assertIsNotNone(acquisition); self.assertEqual(len(self.sol.sent), 1)
        bob.close(); self.sol.expire()
        resumed = self.open('foreign-owner', existing=True)
        self.assertEqual(resumed.step()['action'], 'refund-renewed')
        latest = resumed._attempt('refund')
        self.assertEqual(resumed.store.get('refund.intent'), original)
        self.assertNotEqual(latest['txid'], original['txid'])
        self.assertGreater(resumed.store.get('refund.renewal.1')['expiry_context_slot'], acquisition['context_slot'])
        self.assertEqual(resumed.step()['action'], 'refund-submitted')
        self.assertEqual(resumed.step()['action'], 'refund-observed')
        self.assertEqual(len(self.sol.sent), 2)
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), 0)
        self.assertEqual(self.sol.balance(plan['accounts']['refund']), self.sol.terms['amount'])

    def test_saved_public_witness_backup_protects_claim_with_native_history_unavailable(self):
        alice, bob = self.pair()
        self.assertEqual(bob.step()['action'], 'claim-submitted')
        # Crash after scanner proof persistence, before protective signing.
        with patch.object(alice.session, 'prepare_observed_claim', side_effect=RuntimeError('fixture signing interruption')):
            with self.assertRaises(RuntimeError): alice.step()
        self.assertIsNotNone(alice.store.get('scanner.claim'))
        self.assertIsNone(alice.session.journal.intent(alice.session.id, 'foreign-claim'))
        snapshot = alice.backup(self.root / 'public-proof.backup'); alice.close()
        restored_path = self.root / 'restored-claimant'
        Owner.restore(snapshot, restored_path, self.encryption['xds-owner'])
        self.native.fail_lookup = True
        restored = self.open('xds-owner', existing=True, directory=restored_path)
        self.assertTrue(restored.store.recovery_required())
        self.assertEqual(restored.step()['action'], 'claim-submitted')
        self.assertEqual(restored.step()['action'], 'claim-observed')
        plan = bob.store.get('funding.attempt')['plan']
        self.assertEqual(self.sol.balance(plan['accounts']['claim']), self.sol.terms['amount'])
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), 0)

    def test_expired_unsent_public_claim_after_restart_renews_before_transmission(self):
        alice, bob = self.pair()
        self.assertEqual(bob.step()['action'], 'claim-submitted')
        with patch.object(alice, '_checkpoint', side_effect=RuntimeError('fixture stopped before claim send')):
            with self.assertRaises(RuntimeError): alice.step()
        original = alice.session.journal.intent(alice.session.id, 'foreign-claim')
        self.assertTrue(alice.session._public_proof())
        self.assertEqual(original['attempt'], 0); self.assertEqual(len(self.sol.sent), 1)
        alice.close(); self.sol.expire()
        resumed = self.open('xds-owner', existing=True)
        self.assertEqual(resumed.step()['action'], 'claim-renewed')
        current = resumed.session.journal.intent(resumed.session.id, 'foreign-claim')
        self.assertEqual(current['attempt'], 1); self.assertNotEqual(current['txid'], original['txid'])
        prior = resumed.session.journal.intent(resumed.session.id, 'foreign-claim', attempt=0)
        self.assertEqual(prior['payload'], original['payload']); self.assertEqual(len(self.sol.sent), 1)
        self.assertEqual(resumed.step()['action'], 'claim-submitted')
        self.assertEqual(resumed.step()['action'], 'claim-observed')
        plan = bob.store.get('funding.attempt')['plan']
        self.assertEqual(self.sol.balance(plan['accounts']['claim']), self.sol.terms['amount'])
        self.assertEqual(self.sol.balance(plan['accounts']['vault']), 0)
        self.assertEqual(len(self.sol.sent), 2)

    def test_ambiguous_previous_funding_history_cannot_authorize_a_new_attempt(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        with patch.object(bob, '_checkpoint', side_effect=RuntimeError('fixture stopped before send')):
            with self.assertRaises(RuntimeError): bob.step()
        old = bob.store.get('funding.attempt'); bob.close(); self.sol.expire()
        self.sol.history[old['txid']] = {'slot': self.sol.slot - 1, 'err': None, 'confirmationStatus': 'processed', 'confirmations': 0}
        resumed = self.open('foreign-owner', existing=True)
        with self.assertRaises(ValueError): resumed.step()
        self.assertEqual(resumed.store.get('funding.attempt'), old)
        self.assertIsNone(resumed.store.get('funding.attempt.1')); self.assertFalse(self.sol.sent)
        self.assertIsNone(self.sol.vm.get_account(Pubkey.from_string(old['plan']['accounts']['state'])))

    def test_restored_signed_unsent_funding_cannot_renew_or_deposit_after_expiry(self):
        bob = self.open('foreign-owner'); self.accept_peer()
        with patch.object(bob, '_checkpoint', side_effect=RuntimeError('fixture stopped before send')):
            with self.assertRaises(RuntimeError): bob.step()
        old = bob.store.get('funding.attempt')
        snapshot = bob.backup(self.root / 'signed-unsent.backup'); bob.close(); self.sol.expire()
        restored_path = self.root / 'restored-unsent'
        Owner.restore(snapshot, restored_path, self.encryption['foreign-owner'])
        restored = self.open('foreign-owner', existing=True, directory=restored_path)
        restored.wallet = None
        self.assertEqual(restored.step()['action'], 'protective-await-refund')
        self.assertEqual(restored.store.get('funding.attempt'), old)
        self.assertIsNone(restored.store.get('funding.attempt.1')); self.assertFalse(self.sol.sent)


if __name__ == '__main__':
    unittest.main(verbosity=2)
