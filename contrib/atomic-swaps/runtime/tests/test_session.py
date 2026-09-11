"""Paired-session state machine faults with a patched concrete adapter factory.

These tests establish coordinator routing/durability, not cryptographic or RPC
truth. Each concrete adapter has separate wire and owned-node qualification.
"""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from swap_runtime.common import canonical
from swap_runtime.journal import Journal
from swap_runtime.session import Session, validate_config


KEY = bytes([73]) * 32
ROLE_KEY = bytes([29]) * 32
SECRET = bytes([41]) * 32
HASHLOCK = hashlib.sha256(SECRET).hexdigest()


def configuration(role='foreign-owner', chain='bitcoin'):
    return {'version': 1, 'swap_id': 'pair-1', 'role': role, 'foreign_chain': chain,
            'xds': {'hashlock': HASHLOCK, 'refund_height': 300, 'genesis_hash': '01' * 32},
            'foreign': {'hashlock': HASHLOCK, 'refund_height': 500, 'deadline_slot': 500,
                        'genesis_hash': '02' * 32},
            'policy': {'min_xds_confirmations': 11, 'xds_claim_budget_blocks': 30,
                       'foreign_claim_budget_units': 60, 'max_observation_seconds': 10,
                       'solana_fee_attempt_reserve': 3}}


class AdapterFixture:
    """Known immutable signed artifacts and mutable authoritative-node results."""
    def __init__(self, side):
        self.side = side
        self.observation = {'status': 'unspent', 'height': 100, 'confirmations': 20,
            'block_hash': ('03' if side == 'xds' else '04') * 32, 'tip_hash': '05' * 32,
            'genesis_hash': ('01' if side == 'xds' else '02') * 32,
            'final': True, 'fees_ready': True, 'refund_eligible': False,
            'claim_ready': True, 'payer_balance_lamports': 50000, 'fee_lamports': 5000}
        self.artifacts = {}
        self.receipts = {}
        self.public = {}
        self.prepare_calls = []
        self.validate_calls = []
        self.send_calls = []
        self.renew_calls = []
        self.generation = 0
        self.fail_before_send = False
        self.lose_ack = False
        self.renew_allowed = True
        self.prepared_evidence = None
        self.renew_provenance = []

    def observe(self):
        return copy.deepcopy(self.observation)

    def prepare(self, kind, key, secret=None):
        if key != ROLE_KEY:
            raise ValueError('wrong owner signing key')
        if kind.startswith('xds-') != (self.side == 'xds'):
            raise ValueError('wrong adapter family')
        if kind.endswith('-claim'):
            if not isinstance(secret, bytes) or hashlib.sha256(secret).hexdigest() != HASHLOCK:
                raise ValueError('wrong preimage')
        elif secret is not None:
            raise ValueError('refund must not carry a preimage')
        self.prepare_calls.append((kind, key, secret))
        raw = canonical({'kind': kind, 'generation': self.generation,
                         'secret': None if secret is None else secret.hex(), 'amount': 1000})
        txid = hashlib.sha256(raw).hexdigest()
        self.artifacts[(kind, txid)] = raw
        self.prepared_evidence = {'source': 'solana-blockhash-acquisition-v1', 'txid': txid,
            'raw_sha256': hashlib.sha256(raw).hexdigest(), 'recent_blockhash': str(self.generation),
            'context_slot': 100 + self.generation, 'last_valid_block_height': 200 + self.generation,
            'genesis_hash': '02' * 32}
        return raw, txid

    def preparation_evidence(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        if self.prepared_evidence is None or self.prepared_evidence['txid'] != txid:
            raise ValueError('no current preparation provenance')
        return copy.deepcopy(self.prepared_evidence)

    def validate(self, kind, raw, txid):
        self.validate_calls.append((kind, raw, txid))
        if self.artifacts.get((kind, txid)) != raw or hashlib.sha256(raw).hexdigest() != txid:
            raise ValueError('wire or identity differs from qualified artifact')
        values = json.loads(raw)
        result = {'txid': txid, 'kind': kind}
        if values['secret'] is not None:
            result['secret'] = values['secret']
        return result

    def receipt(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        return copy.deepcopy(self.receipts.get(txid, {'status': 'unknown', 'final': False, 'txid': txid}))

    def send(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        if self.fail_before_send:
            raise TimeoutError('interrupted before any network transmission')
        self.send_calls.append((kind, raw, txid))
        self.receipts[txid] = {'status': 'pending', 'txid': txid, 'final': False, 'publicly_observed': True}
        if self.lose_ack:
            raise TimeoutError('accepted remotely; acknowledgment lost')
        return txid

    def verify_public_spend(self, txid, kind):
        return copy.deepcopy(self.public.get(txid, {'status': 'unknown', 'kind': kind, 'txid': txid}))

    def publish_claim(self):
        raw, txid = self.prepare('xds-claim', ROLE_KEY, SECRET)
        self.public[txid] = {'status': 'pending', 'kind': 'xds-claim', 'txid': txid,
                            'raw': raw.hex(), 'secret': SECRET.hex(), 'publicly_observed': True}
        return txid

    def renew(self, kind, old_raw, old_txid, new_raw, new_txid, provenance):
        self.validate(kind, old_raw, old_txid)
        self.validate(kind, new_raw, new_txid)
        self.renew_calls.append((old_txid, new_txid))
        if provenance.get('txid') != old_txid or provenance.get('raw_sha256') != hashlib.sha256(old_raw).hexdigest():
            raise ValueError('wrong acquisition provenance')
        self.renew_provenance.append(copy.deepcopy(provenance))
        if not self.renew_allowed or old_txid == new_txid:
            raise ValueError('old transaction not proven expired or replacement unchanged')
        return {'status': 'renewable', 'old_txid': old_txid, 'new_txid': new_txid,
                'old_raw_sha256': hashlib.sha256(old_raw).hexdigest(),
                'new_raw_sha256': hashlib.sha256(new_raw).hexdigest(), 'basis': 'mock rooted expiry and funded state'}


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='paired-runtime-session-')
        self.root = Path(self.temp.name)
        self.xds, self.foreign = AdapterFixture('xds'), AdapterFixture('foreign')
        self.adapters = {'xds': self.xds, 'foreign': self.foreign}
        self.factory = patch('swap_runtime.session._adapters', return_value=self.adapters)
        self.factory.start()
        self.sessions = []

    def tearDown(self):
        for session in reversed(self.sessions):
            session.close()
        self.factory.stop()
        self.temp.cleanup()

    def open(self, name='live.db', role='foreign-owner', chain='bitcoin', existing=False, key=KEY):
        session = Session(self.root / name, key, 'pair-1', None, None,
                          config=None if existing else configuration(role, chain))
        self.sessions.append(session)
        return session

    def restore(self, source, name='recovered.db'):
        restored = Journal.restore(source, self.root / name, KEY)
        restored.close()
        return self.open(name, existing=True)

    def assert_private_output(self, value, raw=None):
        encoded = json.dumps(value, sort_keys=True)
        self.assertNotIn(SECRET.hex(), encoded)
        self.assertNotIn(ROLE_KEY.hex(), encoded)
        self.assertNotIn('"secret"', encoded)
        self.assertNotIn('"payload"', encoded)
        if raw is not None:
            self.assertNotIn(raw.hex(), encoded)

    def test_config_is_copied_and_cross_chain_hashlocks_must_match(self):
        original = configuration()
        normalized = validate_config(original)
        original['policy']['xds_claim_budget_blocks'] = 999
        self.assertEqual(normalized['policy']['xds_claim_budget_blocks'], 30)
        invalid = configuration()
        invalid['foreign']['hashlock'] = 'ff' * 32
        with self.assertRaises(ValueError):
            validate_config(invalid)
        for patch_value in ({'version': True}, {'role': 'both-owners'}, {'swap_id': '../key'}, {'extra': 'data'}):
            with self.subTest(patch=patch_value), self.assertRaises(ValueError):
                validate_config(dict(configuration(), **patch_value))

    def test_role_routes_only_owned_settlement_and_wrong_key_creates_no_intent(self):
        first = self.open()
        for kind in ('xds-refund', 'foreign-claim', 'xds-fund', 'session'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                first.prepare(kind, ROLE_KEY, SECRET)
        with self.assertRaises(ValueError):
            first.prepare('xds-claim', b'wrong-key', SECRET)
        self.assertFalse(first.describe('xds-claim')['prepared'])
        second = self.open('owner.db', role='xds-owner')
        for kind in ('xds-claim', 'foreign-refund'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                second.prepare(kind, ROLE_KEY, SECRET)

    def test_prepare_returns_no_secret_and_does_not_transmit(self):
        session = self.open()
        result = session.prepare('xds-claim', ROLE_KEY, SECRET)
        self.assert_private_output(result)
        self.assertEqual(self.xds.send_calls, [])
        self.assertFalse(session.journal.exposed(session.id))
        self.assertEqual(result['stage'], 'prepared')
        with self.assertRaises(ValueError):
            session.prepare('xds-claim', ROLE_KEY, SECRET)

    def test_exact_journal_bytes_are_validated_and_sent_then_status_reconciles_without_duplicate(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        expected = session.journal.intent(session.id, 'xds-claim')
        result = session.broadcast('xds-claim')
        self.assertEqual(result['action'], 'submitted')
        self.assertEqual(self.xds.send_calls, [('xds-claim', expected['payload'], expected['txid'])])
        self.assert_private_output(result, expected['payload'])
        second = session.broadcast('xds-claim')
        self.assertEqual(second['action'], 'reconciled')
        self.assertEqual(len(self.xds.send_calls), 1)
        self.assertTrue(session._public_proof())

    def test_crash_before_send_sticky_attempt_never_bypasses_new_expired_budget(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        self.xds.fail_before_send = True
        with self.assertRaises(TimeoutError):
            session.broadcast('xds-claim')
        self.assertTrue(session.journal.exposed(session.id))
        self.assertFalse(session._public_proof())
        self.assertEqual(self.xds.send_calls, [])
        session.close()
        self.xds.fail_before_send = False
        self.foreign.observation['height'] = 500
        resumed = self.open(existing=True)
        with self.assertRaises(ValueError):
            resumed.broadcast('xds-claim')
        self.assertEqual(self.xds.send_calls, [])
        self.assertTrue(resumed.journal.exposed(resumed.id))
        self.assertFalse(resumed._public_proof())

    def test_lost_ack_reconciles_exact_public_receipt_after_restart(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        expected = session.journal.intent(session.id, 'xds-claim')
        self.xds.lose_ack = True
        with self.assertRaises(TimeoutError):
            session.broadcast('xds-claim')
        self.assertEqual(len(self.xds.send_calls), 1)
        session.close()
        resumed = self.open(existing=True)
        result = resumed.broadcast('xds-claim')
        self.assertEqual(result['action'], 'reconciled')
        self.assertTrue(resumed._public_proof())
        self.assertEqual(len(self.xds.send_calls), 1)
        self.assertEqual(resumed.journal.intent(resumed.id, 'xds-claim')['payload'], expected['payload'])

    def test_authenticated_public_proof_allows_protective_retry_after_opposite_contract_spent(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        expected = session.journal.intent(session.id, 'xds-claim')
        session.broadcast('xds-claim')
        session.reconcile('xds-claim')
        session.close()
        self.xds.receipts.clear()  # Owned chain reorg: signed claim is no longer observed.
        self.foreign.observation.update(status='spent', final=False, height=501)
        resumed = self.open(existing=True)
        self.assertTrue(resumed._public_proof())
        result = resumed.broadcast('xds-claim')
        self.assertEqual(result['action'], 'submitted')
        self.assertEqual(self.xds.send_calls[0], self.xds.send_calls[1])
        self.assertEqual(self.xds.send_calls[-1][1], expected['payload'])

    def test_signature_status_only_pending_never_creates_public_witness_proof(self):
        session = self.open()
        prepared = session.prepare('xds-claim', ROLE_KEY, SECRET)
        self.xds.receipts[prepared['txid']] = {'status': 'pending', 'final': False,
                                             'publicly_observed': False, 'txid': prepared['txid']}
        session.reconcile('xds-claim')
        self.assertFalse(session._public_proof())
        self.assertFalse(session.journal.exposed(session.id))

    def test_foreign_claim_requires_valid_public_xds_witness_and_never_accepts_injected_secret(self):
        session = self.open(role='xds-owner')
        with self.assertRaises(ValueError):
            session.prepare('foreign-claim', ROLE_KEY, SECRET)
        with self.assertRaises(ValueError):
            session.prepare('foreign-claim', ROLE_KEY, public_xds_txid='00' * 32)
        self.assertEqual(self.foreign.prepare_calls, [])
        candidate = self.xds.publish_claim()
        result = session.prepare('foreign-claim', ROLE_KEY, public_xds_txid=candidate)
        self.assertTrue(session._public_proof())
        self.assertTrue(session.journal.exposed(session.id))
        self.assertEqual(self.foreign.prepare_calls[-1][2], SECRET)
        self.assert_private_output(result)
        self.xds.observation.update(status='spent', final=False)
        result = session.broadcast('foreign-claim')
        self.assertEqual(result['action'], 'submitted')
        self.assert_private_output(result)

    def test_foreign_prepare_crash_before_public_marker_requires_reobservation(self):
        session = self.open(role='xds-owner')
        candidate = self.xds.publish_claim()
        with patch.object(session, '_record_public', side_effect=OSError('crash before public evidence commit')):
            with self.assertRaises(OSError):
                session.prepare('foreign-claim', ROLE_KEY, public_xds_txid=candidate)
        self.assertTrue(session.describe('foreign-claim')['prepared'])
        self.assertFalse(session._public_proof())
        with self.assertRaises(ValueError):
            session.broadcast('foreign-claim')
        self.assertEqual(self.foreign.send_calls, [])
        observed = session.reobserve_public_xds('foreign-claim', candidate)
        self.assert_private_output(observed)
        self.assertTrue(session._public_proof())
        self.assertEqual(session.broadcast('foreign-claim')['action'], 'submitted')

    def test_public_reobservation_must_match_stored_claim_preimage(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        candidate = self.xds.publish_claim()
        self.xds.public[candidate]['secret'] = 'ff' * 32
        with self.assertRaises(ValueError):
            session.reobserve_public_xds('xds-claim', candidate)
        self.assertFalse(session._public_proof())

    def test_restore_before_intent_cannot_create_new_claim_funding_or_session(self):
        session = self.open()
        source = session.snapshot(self.root / 'old.db')
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        recovered = self.restore(source)
        self.assertFalse(recovered.describe('xds-claim')['prepared'])
        with self.assertRaises(ValueError):
            recovered.prepare('xds-claim', ROLE_KEY, SECRET)
        with self.assertRaises(ValueError):
            recovered.broadcast('xds-claim')
        for kind in ('xds-fund', 'foreign-fund', 'session'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                recovered.broadcast(kind)
        self.assertEqual(self.xds.send_calls, [])

    def test_restored_existing_intent_uses_current_validation_and_exact_bytes(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        expected = session.journal.intent(session.id, 'xds-claim')
        recovered = self.restore(session.snapshot(self.root / 'backup.db'))
        self.xds.observation['status'] = 'spent'
        with self.assertRaises(ValueError):
            recovered.broadcast('xds-claim')
        self.assertEqual(self.xds.send_calls, [])
        self.xds.observation['status'] = 'unspent'
        self.assertEqual(recovered.broadcast('xds-claim')['action'], 'submitted')
        self.assertEqual(self.xds.send_calls[-1], ('xds-claim', expected['payload'], expected['txid']))
        count = recovered.journal.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0]
        self.assertEqual(count, 1)

    def test_encrypted_config_tamper_and_wrong_key_fail_before_adapter_reuse(self):
        session = self.open()
        path = session.journal.path
        session.close()
        with self.assertRaises(Exception):
            self.open(existing=True, key=bytes([74]) * 32)
        db = sqlite3.connect(path)
        encrypted = db.execute("SELECT encrypted FROM attempts WHERE kind='session'").fetchone()[0]
        db.execute('DROP TRIGGER immutable_attempt')
        db.execute("UPDATE attempts SET encrypted=? WHERE kind='session'",
                   (encrypted[:-1] + bytes([encrypted[-1] ^ 1]),))
        db.commit()
        db.close()
        with self.assertRaises(Exception):
            self.open(existing=True)
        self.assertEqual(self.xds.send_calls, [])

    def test_public_proof_ciphertext_tamper_never_authorizes_retry(self):
        session = self.open()
        prepared = session.prepare('xds-claim', ROLE_KEY, SECRET)
        session.broadcast('xds-claim')
        session.reconcile('xds-claim')
        db = session.journal.db
        row_id, evidence = db.execute('SELECT id,evidence FROM recovery_actions').fetchone()
        evidence = json.loads(evidence)
        sealed = bytes.fromhex(evidence['sealed'])
        evidence['sealed'] = (sealed[:-1] + bytes([sealed[-1] ^ 1])).hex()
        db.execute('DROP TRIGGER immutable_recovery_action')
        db.execute('UPDATE recovery_actions SET evidence=? WHERE id=?', (canonical(evidence), row_id))
        self.xds.receipts.clear()
        self.foreign.observation['height'] = 501
        with self.assertRaises(Exception):
            session.broadcast('xds-claim')
        self.assertEqual(len(self.xds.send_calls), 1)

    def test_unknown_wrong_chain_fee_not_ready_and_confirmation_shortfall_block_first_claim(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        baseline_xds = copy.deepcopy(self.xds.observation)
        baseline_foreign = copy.deepcopy(self.foreign.observation)
        cases = [('xds', {'status': 'unknown', 'reason': 'genesis mismatch'}),
                 ('foreign', {'status': 'unknown', 'reason': 'wrong genesis'}),
                 ('xds', {'fees_ready': False}), ('xds', {'confirmations': 10}),
                 ('foreign', {'final': False}), ('xds', {'height': 280}),
                 ('foreign', {'height': 450})]
        for side, change in cases:
            self.xds.observation = copy.deepcopy(baseline_xds)
            self.foreign.observation = copy.deepcopy(baseline_foreign)
            self.adapters[side].observation.update(change)
            with self.subTest(side=side, change=change), self.assertRaises(ValueError):
                session.broadcast('xds-claim')
            self.assertFalse(session.journal.exposed(session.id))
            self.assertEqual(self.xds.send_calls, [])

    def test_solana_frozen_destination_or_insufficient_retry_fee_reserve_blocks_first_claim(self):
        session = self.open(chain='solana')
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        baseline = copy.deepcopy(self.foreign.observation)
        for change in ({'claim_ready': False}, {'fees_ready': False}, {'payer_balance_lamports': 14999},
                       {'fee_lamports': 0}, {'payer_balance_lamports': True}):
            self.foreign.observation = dict(baseline, **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                session.broadcast('xds-claim')
            self.assertFalse(session.journal.exposed(session.id))
            self.assertEqual(self.xds.send_calls, [])

    def test_slow_observation_and_same_height_changed_tip_block_first_disclosure(self):
        session = self.open()
        session.prepare('xds-claim', ROLE_KEY, SECRET)
        with patch('swap_runtime.session.time.monotonic', side_effect=[0, 11]):
            admission, _ = session.observe()
            self.assertFalse(admission.allow_first_exposure())
        first = self.xds.observe()
        second = dict(first, tip_hash='ff' * 32)
        with patch.object(self.xds, 'observe', side_effect=[first, second]):
            admission, _ = session.observe()
            self.assertFalse(admission.allow_first_exposure())
        self.assertEqual(self.xds.send_calls, [])

    def test_refund_waits_for_own_deadline_without_other_chain_admission(self):
        session = self.open(role='xds-owner')
        session.prepare('xds-refund', ROLE_KEY)
        with self.assertRaises(ValueError):
            session.broadcast('xds-refund')
        self.assertFalse(session.journal.exposed(session.id))
        self.xds.observation['refund_eligible'] = True
        self.foreign.observation.update(status='unknown', height=None)
        self.assertEqual(session.broadcast('xds-refund')['action'], 'submitted')
        self.assertFalse(session.journal.exposed(session.id))

    def test_renewal_is_solana_only_and_preserves_prior_artifact_and_evidence(self):
        session = self.open(chain='solana')
        session.prepare('foreign-refund', ROLE_KEY)
        old = session.journal.intent(session.id, 'foreign-refund')
        self.foreign.generation = 1
        renewed = session.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(renewed['attempt'], 1)
        self.assert_private_output(renewed)
        retained = session.journal.intent(session.id, 'foreign-refund', 0)
        self.assertEqual(retained['payload'], old['payload'])
        self.assertEqual(retained['txid'], old['txid'])
        latest = session.journal.intent(session.id, 'foreign-refund')
        self.assertEqual(latest['evidence']['old_txid'], old['txid'])
        self.assertEqual(latest['stage'], 'prepared')
        with self.assertRaises(ValueError):
            session.renew_solana('xds-claim', ROLE_KEY)
        btc = self.open('btc.db')
        with self.assertRaises(ValueError):
            btc.renew_solana('foreign-refund', ROLE_KEY)

    def test_failed_solana_renewal_does_not_append_or_replace_prior_history(self):
        session = self.open(chain='solana')
        session.prepare('foreign-refund', ROLE_KEY)
        old = session.journal.intent(session.id, 'foreign-refund')
        self.foreign.generation = 1
        self.foreign.renew_allowed = False
        with self.assertRaises(ValueError):
            session.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(session.journal.intent(session.id, 'foreign-refund'), old)
        self.assertEqual(session.journal.db.execute("SELECT COUNT(*) FROM attempts WHERE kind='foreign-refund'").fetchone()[0], 1)

    def test_solana_acquisition_survives_restart_and_chained_renewal(self):
        session = self.open(chain='solana')
        session.prepare('foreign-refund', ROLE_KEY)
        first = session.journal.intent(session.id, 'foreign-refund')
        self.assertEqual(first['evidence']['_aad_version'], 1)
        session.close()
        self.foreign.prepared_evidence = None
        resumed = self.open(existing=True)
        self.foreign.generation = 1
        resumed.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(self.foreign.renew_provenance[-1]['txid'], first['txid'])
        second = resumed.journal.intent(resumed.id, 'foreign-refund')
        self.assertEqual(second['evidence']['preparation']['txid'], second['txid'])
        self.foreign.generation = 2
        resumed.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(self.foreign.renew_provenance[-1], second['evidence']['preparation'])
        self.assertEqual(resumed.journal.intent(resumed.id, 'foreign-refund')['attempt'], 2)
        self.assertEqual(resumed.journal.intent(resumed.id, 'foreign-refund', 0), first)

    def test_restored_legacy_missing_acquisition_refuses_renewal_before_preparation(self):
        session = self.open(chain='solana')
        raw, txid = self.foreign.prepare('foreign-refund', ROLE_KEY)
        session.journal.prepare(session.id, 'foreign-refund', raw, txid)
        recovered = self.restore(session.snapshot(self.root / 'legacy-solana.db'))
        calls = len(self.foreign.prepare_calls)
        with self.assertRaisesRegex(ValueError, 'Authenticated blockhash acquisition'):
            recovered.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(len(self.foreign.prepare_calls), calls)
        self.assertEqual(self.foreign.send_calls, [])
        self.assertEqual(recovered.journal.intent(recovered.id, 'foreign-refund')['attempt'], 0)

    def test_unsealed_legacy_acquisition_cannot_authorize_renewal(self):
        session = self.open(chain='solana')
        raw, txid = self.foreign.prepare('foreign-refund', ROLE_KEY)
        evidence = self.foreign.preparation_evidence('foreign-refund', raw, txid)
        session.journal.prepare(session.id, 'foreign-refund', raw, txid)
        session.journal.db.execute('DROP TRIGGER immutable_attempt')
        session.journal.db.execute('UPDATE attempts SET evidence=? WHERE kind=?',
                                   (canonical(evidence), 'foreign-refund'))
        with self.assertRaisesRegex(ValueError, 'Authenticated blockhash acquisition'):
            session.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(self.foreign.renew_calls, [])

    def test_solana_acquisition_tamper_refuses_before_any_replacement(self):
        session = self.open(chain='solana')
        session.prepare('foreign-refund', ROLE_KEY)
        stored = session.journal.intent(session.id, 'foreign-refund')['evidence']
        stored['context_slot'] -= 1
        session.journal.db.execute('DROP TRIGGER immutable_attempt')
        session.journal.db.execute('UPDATE attempts SET evidence=? WHERE kind=?',
                                   (canonical(stored), 'foreign-refund'))
        calls = len(self.foreign.prepare_calls)
        with self.assertRaises(Exception):
            session.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(len(self.foreign.prepare_calls), calls)
        self.assertEqual(self.foreign.send_calls, [])

    def test_partial_confirmation_never_becomes_final_journal_settlement(self):
        session = self.open()
        prepared = session.prepare('xds-claim', ROLE_KEY, SECRET)
        self.xds.receipts[prepared['txid']] = {'status': 'confirmed', 'final': False,
                                             'publicly_observed': True, 'txid': prepared['txid']}
        session.reconcile('xds-claim')
        self.assertEqual(session.describe('xds-claim')['status'], 'unknown')
        self.xds.receipts[prepared['txid']]['final'] = True
        session.reconcile('xds-claim')
        self.assertEqual(session.describe('xds-claim')['status'], 'confirmed')
        self.xds.receipts.clear()
        session.reconcile('xds-claim')
        self.assertEqual(session.describe('xds-claim')['status'], 'unknown')
        self.assertTrue(session._public_proof())

    def test_restored_refund_needs_current_eligibility_and_never_discloses(self):
        session = self.open(role='xds-owner')
        session.prepare('xds-refund', ROLE_KEY)
        expected = session.journal.intent(session.id, 'xds-refund')
        recovered = self.restore(session.snapshot(self.root / 'refund-backup.db'))
        with self.assertRaises(ValueError):
            recovered.broadcast('xds-refund')
        self.xds.observation['refund_eligible'] = True
        self.foreign.observation.update(status='unknown', height=None)
        recovered.broadcast('xds-refund')
        self.assertEqual(self.xds.send_calls[-1], ('xds-refund', expected['payload'], expected['txid']))
        self.assertFalse(recovered.journal.exposed(recovered.id))
        self.assertTrue(recovered.journal.recovery_required())

    def test_restored_solana_renewal_only_appends_to_existing_semantic_intent(self):
        session = self.open(chain='solana')
        session.prepare('foreign-refund', ROLE_KEY)
        old = session.journal.intent(session.id, 'foreign-refund')
        recovered = self.restore(session.snapshot(self.root / 'solana-backup.db'))
        self.foreign.generation = 1
        renewed = recovered.renew_solana('foreign-refund', ROLE_KEY)
        self.assertEqual(renewed['attempt'], 1)
        self.assertEqual(recovered.journal.intent(recovered.id, 'foreign-refund', 0), old)
        self.assertTrue(recovered.journal.recovery_required())
        with self.assertRaises(ValueError):
            recovered.prepare('xds-claim', ROLE_KEY, SECRET)

    def test_plain_config_commitment_tamper_is_detected_against_authenticated_payload(self):
        session = self.open()
        path = session.journal.path
        session.close()
        db = sqlite3.connect(path)
        db.execute('DROP TRIGGER immutable_terms')
        db.execute('UPDATE swaps SET terms=?', (canonical({'version': 1, 'config_sha256': 'ff' * 32}),))
        db.commit()
        db.close()
        with self.assertRaisesRegex(ValueError, 'authenticated configuration'):
            self.open(existing=True)
        self.assertEqual(self.xds.send_calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
