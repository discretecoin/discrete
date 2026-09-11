"""Owner recovery: real wire cryptography, authenticated SQLite, mocked ledgers."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from solders.hash import Hash

from swap_runtime.common import canonical
from swap_runtime.journal import Journal
from swap_runtime.lifecycle_settlement import OwnerSession
from swap_runtime.session import Session
from swap_runtime.xds import _h
from swap_runtime.xds_discovery import XdsWitnessDiscovery
from test_xds import Fixture as NativeFixture
from test_bitcoin import FakeCore
from test_solana import Fixture as SolanaFixture


JOURNAL_KEY = bytes([45]) * 32


class OwnerSettlementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-settlement-')
        self.root = Path(self.temp.name)
        self.x, self.btc = NativeFixture(), FakeCore()
        self.claim_key = ec.derive_private_key(12345, ec.SECP256K1())
        self.refund_key = ec.derive_private_key(67890, ec.SECP256K1())
        self.sessions = []
        self.native_lookup_forbidden = False

    def tearDown(self):
        for session in reversed(self.sessions):
            session.close()
        self.temp.cleanup()

    def daemon(self, method, params):
        if self.native_lookup_forbidden:
            raise AssertionError('Saved public proof recovery must not require pruned native history')
        return self.x.rpc(method, params)

    def config(self, role='xds-owner', solana=None):
        return dict(version=1, swap_id='owner-pair', role=role, foreign_chain='solana' if solana else 'bitcoin',
            xds=copy.deepcopy(self.x.terms), foreign=copy.deepcopy(solana.terms if solana else self.btc.terms),
            policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2, foreign_claim_budget_units=2,
                        max_observation_seconds=15, solana_fee_attempt_reserve=2))

    def open(self, role='xds-owner', name='live.sqlite', solana=None, existing=False):
        session = OwnerSession(self.root / name, JOURNAL_KEY, 'owner-pair', self.daemon,
            solana.rpc if solana else self.btc.rpc, wallet=self.x.wallet,
            config=None if existing else self.config(role, solana))
        self.sessions.append(session)
        return session

    def restored(self, session, solana=None):
        snapshot = session.snapshot(self.root / 'snapshot.sqlite')
        Journal.restore(snapshot, self.root / 'restored.sqlite', JOURNAL_KEY).close()
        return self.open(name='restored.sqlite', solana=solana, existing=True)

    def proof(self):
        raw, txid = self.x.wire()
        self.x.entries[txid] = (raw, None)
        proof = XdsWitnessDiscovery(self.x.rpc, self.x.terms)._proof((txid, 'xds-claim'))['proof']
        self.assertTrue(proof['publicly_observed'])
        return proof

    def assert_private(self, result):
        encoded = json.dumps(result)
        self.assertNotIn(self.x.secret.hex(), encoded)
        self.assertNotIn('secret', encoded)
        self.assertNotIn('payload', encoded)

    def test_saved_public_claim_works_after_native_lookup_is_pruned_and_reuses_wire(self):
        session = self.open()
        proof = self.proof()
        self.native_lookup_forbidden = True
        result = session.prepare_observed_claim(self.claim_key, proof)
        first = session.journal.intent(session.id, 'foreign-claim')
        self.assert_private(result)
        self.assertTrue(session._public_proof())
        self.assertTrue(session.journal.exposed(session.id))
        with patch.object(session.adapters['foreign'], 'prepare', side_effect=AssertionError('must not resign')):
            repeated = session.prepare_observed_claim(None, proof)
        self.assertEqual(repeated['txid'], first['txid'])
        self.assertEqual(session.journal.intent(session.id, 'foreign-claim'), first)
        self.assertEqual(session.broadcast('foreign-claim')['action'], 'submitted')
        self.assertEqual(self.btc.spend, first['payload'])

    def test_restored_absent_protective_claim_uses_saved_public_witness_only(self):
        session = self.open()
        restored = self.restored(session)
        proof = self.proof()
        self.native_lookup_forbidden = True
        result = restored.prepare_observed_claim(self.claim_key, proof)
        self.assertTrue(restored.journal.recovery_required())
        self.assertTrue(restored._public_proof())
        self.assert_private(result)
        evidence = restored.journal.intent(restored.id, 'foreign-claim')['evidence']
        self.assertEqual(evidence['source'], 'owner-observed-claim-preparation-v1')
        self.assertEqual(evidence['_aad_version'], 1)
        self.assertEqual(evidence['public_txid'], proof['txid'])
        self.assertTrue(evidence['recovery_required'])
        with self.assertRaises(ValueError):
            restored.journal.prepare(restored.id, 'xds-fund', b'new', 'new')

    def test_crash_between_intent_and_public_record_recovers_without_second_signature(self):
        session = self.open()
        proof = self.proof()
        with patch.object(session, '_record_public', side_effect=TimeoutError('simulated process interruption')):
            with self.assertRaises(TimeoutError):
                session.prepare_observed_claim(self.claim_key, proof)
        first = session.journal.intent(session.id, 'foreign-claim')
        self.assertIsNotNone(first)
        self.assertFalse(session._public_proof())
        with self.assertRaises(ValueError):
            session.broadcast('foreign-claim')
        self.native_lookup_forbidden = True
        with patch.object(session.adapters['foreign'], 'prepare', side_effect=AssertionError('must not resign')):
            session.prepare_observed_claim(None, proof)
        self.assertEqual(session.journal.intent(session.id, 'foreign-claim'), first)
        self.assertTrue(session._public_proof())

    def test_wrong_role_private_preimage_false_receipt_or_mutated_wire_never_prepares(self):
        session = self.open()
        proof = self.proof()
        badwire = bytes.fromhex(proof['raw'])
        badwire = badwire[:-1] + bytes([badwire[-1] ^ 1])
        forged_acquisition = dict(proof['acquisition'], txid=_h(badwire).hex(), raw_sha256=hashlib.sha256(badwire).hexdigest())
        cases = [None, {'secret': self.x.secret.hex()}, dict(proof, kind='xds-refund'),
                 dict(proof, publicly_observed=False), dict(proof, publicly_observed=1),
                 dict(proof, status='private'), dict(proof, final=1),
                 dict(proof, secret='99' * 32), dict(proof, txid='99' * 32),
                 dict(proof, raw=badwire.hex(), txid=_h(badwire).hex(), acquisition=forged_acquisition)]
        for value in cases:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                session.prepare_observed_claim(self.claim_key, value)
            self.assertIsNone(session.journal.intent(session.id, 'foreign-claim'))
        wrong_role = self.open(role='foreign-owner', name='other.sqlite')
        with self.assertRaises(ValueError):
            wrong_role.prepare_observed_claim(self.claim_key, proof)

    def test_missing_or_mismatched_scanner_acquisition_cannot_authorize_claim(self):
        session = self.open()
        proof = self.proof()
        for metadata in (None, {}, dict(proof['acquisition'], full_wire_fetched=False),
                         dict(proof['acquisition'], full_wire_fetched=1),
                         dict(proof['acquisition'], source='peer-message'),
                         dict(proof['acquisition'], txid='99' * 32),
                         dict(proof['acquisition'], raw_sha256='99' * 32)):
            with self.assertRaises(ValueError):
                session.prepare_observed_claim(self.claim_key, dict(proof, acquisition=metadata))
            self.assertIsNone(session.journal.intent(session.id, 'foreign-claim'))

    def test_valid_saved_wire_with_unknown_current_receipt_preserves_public_exposure(self):
        session = self.open()
        proof = self.proof()
        proof.update(status='unknown', publicly_observed=False, final=False)
        self.native_lookup_forbidden = True
        session.prepare_observed_claim(self.claim_key, proof)
        self.assertTrue(session._public_proof())
        self.assertTrue(session.journal.exposed(session.id))

    def test_changed_native_contract_or_configuration_rejected_before_signing(self):
        proof = self.proof()
        changed = self.open()
        changed.config['xds']['nonce'] = '99' * 32
        with self.assertRaises(ValueError):
            changed.prepare_observed_claim(self.claim_key, proof)
        self.assertIsNone(changed.journal.intent(changed.id, 'foreign-claim'))
        other = NativeFixture()
        other.terms['nonce'] = self.x.terms['nonce']
        raw, txid = other.wire()
        second = self.open(name='second.sqlite')
        metadata = dict(proof['acquisition'], txid=txid, raw_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):
            second.prepare_observed_claim(self.claim_key, dict(proof, raw=raw.hex(), txid=txid, acquisition=metadata))
        self.assertIsNone(second.journal.intent(second.id, 'foreign-claim'))

    def test_recovery_refund_requires_recovery_lock_correct_role_and_deadline(self):
        live = self.open()
        self.x.height = 80
        with self.assertRaises(ValueError):
            live.prepare_recovery_refund('xds-refund', self.x.rhos[1])
        restored = self.restored(live)
        for kind in ('foreign-refund', 'foreign-claim', 'xds-claim', 'xds-fund', 'session'):
            with self.assertRaises(ValueError):
                restored.prepare_recovery_refund(kind, self.x.rhos[1])
        self.x.height = 79
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('xds-refund', self.x.rhos[1])
        self.assertEqual(self.x.wallet_calls, [])
        self.assertIsNone(restored.journal.intent(restored.id, 'xds-refund'))

    def test_absent_native_refund_has_authenticated_audit_and_preserves_old_intents(self):
        live = self.open()
        saved = live.journal.intent(live.id, 'session')
        restored = self.restored(live)
        self.x.height = 80
        result = restored.prepare_recovery_refund('xds-refund', self.x.rhos[1])
        intent = restored.journal.intent(restored.id, 'xds-refund')
        self.assert_private(result)
        self.assertEqual(intent['attempt'], 0)
        self.assertFalse(intent['exposes'])
        self.assertFalse(restored.journal.exposed(restored.id))
        self.assertEqual(intent['evidence']['source'], 'owner-recovery-refund-preparation-v1')
        self.assertEqual(intent['evidence']['_aad_version'], 1)
        self.assertEqual(restored.journal.intent(restored.id, 'session'), saved)
        encoded = restored.journal.db.execute("SELECT evidence FROM recovery_actions WHERE kind='xds-refund'").fetchone()[0]
        audit = json.loads(encoded)
        sealed = bytes.fromhex(audit['sealed'])
        plaintext = restored.journal.aead.decrypt(sealed[:12], sealed[12:],
            canonical([restored.id, 'xds-refund', 0, 'owner-protective-preparation-v1']))
        self.assertEqual(json.loads(plaintext)['source'], 'owner-recovery-refund-preparation-v1')
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('xds-refund', self.x.rhos[1])
        self.assertEqual(restored.journal.intent(restored.id, 'xds-refund'), intent)
        restored.broadcast('xds-refund')
        self.assertEqual(self.x.sent, [intent['payload']])
        self.assertTrue(restored.journal.recovery_required())

    def test_wrong_native_role_or_lost_chain_evidence_creates_no_refund(self):
        restored = self.restored(self.open())
        self.x.height = 80
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('xds-refund', self.x.rhos[0])
        self.assertIsNone(restored.journal.intent(restored.id, 'xds-refund'))
        for patch_value in ({'spent': True}, {'spent_known': False}, {'genesis_hash': '99' * 32}, {'confirmations': 1}):
            self.x.funding_patch = patch_value
            with self.assertRaises(ValueError):
                restored.prepare_recovery_refund('xds-refund', self.x.rhos[1])
            self.assertIsNone(restored.journal.intent(restored.id, 'xds-refund'))

    def test_state_change_during_refund_signing_rolls_back_absent_intent(self):
        restored = self.restored(self.open())
        self.x.height = 80
        adapter = restored.adapters['xds']
        original = adapter.prepare
        def changed(*args, **kwargs):
            value = original(*args, **kwargs)
            self.x.funding_patch['spent'] = True
            return value
        with patch.object(adapter, 'prepare', changed), self.assertRaises(ValueError):
            restored.prepare_recovery_refund('xds-refund', self.x.rhos[1])
        self.assertIsNone(restored.journal.intent(restored.id, 'xds-refund'))
        self.assertEqual(restored.journal.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)

    def test_absent_bitcoin_refund_uses_actual_role_signature_and_height(self):
        restored = self.restored(self.open(role='foreign-owner'))
        self.btc.height = 299
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('foreign-refund', self.refund_key)
        self.btc.height = 300
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('foreign-refund', self.claim_key)
        result = restored.prepare_recovery_refund('foreign-refund', self.refund_key)
        intent = restored.journal.intent(restored.id, 'foreign-refund')
        restored.adapters['foreign'].validate('foreign-refund', intent['payload'], intent['txid'])
        self.assert_private(result)
        self.assertFalse(restored.journal.exposed(restored.id))

    def test_unchanged_session_and_journal_still_reject_absent_recovery_preparation(self):
        restored = self.restored(self.open(role='foreign-owner'))
        with self.assertRaises(ValueError):
            Session.prepare(restored, 'xds-claim', self.x.rhos[0], self.x.secret)
        with self.assertRaises(ValueError):
            restored.journal.prepare(restored.id, 'foreign-refund', b'signed', 'id')
        self.assertIsNone(restored.journal.intent(restored.id, 'xds-claim'))
        self.assertIsNone(restored.journal.intent(restored.id, 'foreign-refund'))

    def solana(self):
        sol = SolanaFixture()
        old_hash = bytes.fromhex(self.x.terms['hashlock'])
        new_hash = hashlib.sha256(sol.secret).digest()
        self.x.secret = sol.secret
        self.x.output = self.x.output.replace(old_hash, new_hash)
        self.x.funding = self.x.funding.replace(old_hash, new_hash)
        self.x.terms.update(hashlock=new_hash.hex(), funding_wire=self.x.funding.hex(), funding_txid=_h(self.x.funding).hex())
        return sol

    def test_solana_recovery_refund_uses_finalized_clock_and_keeps_acquisition_for_renewal(self):
        sol = self.solana()
        restored = self.restored(self.open(role='foreign-owner', solana=sol), solana=sol)
        sol.slot, sol.processed = 219, 230
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('foreign-refund', sol.payer)
        sol.slot, sol.processed = 220, 230
        restored.prepare_recovery_refund('foreign-refund', sol.payer)
        intent = restored.journal.intent(restored.id, 'foreign-refund')
        evidence = intent['evidence']
        self.assertEqual(evidence['_aad_version'], 1)
        self.assertEqual(evidence['preparation']['source'], 'solana-blockhash-acquisition-v1')
        self.assertEqual(evidence['preparation']['raw_sha256'], hashlib.sha256(intent['payload']).hexdigest())
        self.assertEqual(evidence['observation']['finalized_height'], 220)
        self.assertFalse(restored.journal.exposed(restored.id))

    def test_solana_fee_or_refund_destination_failure_prevents_recovery_intent(self):
        sol = self.solana()
        restored = self.restored(self.open(role='foreign-owner', solana=sol), solana=sol)
        sol.slot, sol.processed = 220, 230
        sol.balance = 1
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('foreign-refund', sol.payer)
        sol.balance = 1000000
        sol.change('refund', 108, b'\x02')
        with self.assertRaises(ValueError):
            restored.prepare_recovery_refund('foreign-refund', sol.payer)
        self.assertIsNone(restored.journal.intent(restored.id, 'foreign-refund'))

    def test_saved_public_solana_claim_keeps_signed_acquisition_for_qualified_renewal(self):
        sol = self.solana()
        restored = self.restored(self.open(solana=sol), solana=sol)
        proof = self.proof()
        self.native_lookup_forbidden = True
        restored.prepare_observed_claim(sol.payer, proof)
        old = restored.journal.intent(restored.id, 'foreign-claim')
        metadata = old['evidence']['preparation']
        self.assertEqual(metadata['source'], 'solana-blockhash-acquisition-v1')
        old_hash = str(sol.blockhash)
        sol.blockhash = Hash.new_unique()
        sol.valid[str(sol.blockhash)] = True
        sol.valid[old_hash] = False
        sol.slot += 1
        renewed = restored.renew_solana('foreign-claim', sol.payer)
        self.assertEqual(renewed['attempt'], 1)
        self.assertEqual(restored.journal.intent(restored.id, 'foreign-claim', 0), old)
        self.assertEqual(restored.journal.intent(restored.id, 'foreign-claim')['evidence']['acquisition_context_slot'], metadata['context_slot'])
        self.assertTrue(restored._public_proof())
        self.assertEqual(sol.sent, [])

    def test_absent_recovery_solana_refund_remains_renewable_after_snapshot_restore(self):
        sol = self.solana()
        restored = self.restored(self.open(role='foreign-owner', solana=sol), solana=sol)
        sol.slot, sol.processed = 220, 230
        restored.prepare_recovery_refund('foreign-refund', sol.payer)
        old = restored.journal.intent(restored.id, 'foreign-refund')
        snapshot = restored.snapshot(self.root / 'refund-snapshot.sqlite')
        Journal.restore(snapshot, self.root / 'refund-restored.sqlite', JOURNAL_KEY).close()
        reopened = self.open(name='refund-restored.sqlite', solana=sol, existing=True)
        old_hash = str(sol.blockhash)
        sol.blockhash = Hash.new_unique()
        sol.valid[str(sol.blockhash)] = True
        sol.valid[old_hash] = False
        sol.slot += 1
        result = reopened.renew_solana('foreign-refund', sol.payer)
        self.assertEqual(result['attempt'], 1)
        self.assertEqual(reopened.journal.intent(reopened.id, 'foreign-refund', 0), old)
        self.assertFalse(reopened.journal.exposed(reopened.id))
        self.assertTrue(reopened.journal.recovery_required())
        self.assertEqual(sol.sent, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
