"""Retained native prepare RPC qualification with independent ML-DSA wire checks.

The wallet boundary is a deterministic mock; existing funding fixtures provide
real signatures and source transaction parsing. No native node is started.
"""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from swap_runtime import xds_preparation as preparation
from swap_runtime.xds import _h, _Unavailable
from swap_runtime.xds_funding import XdsFundingAdapter
from test_xds_funding import FundingFixture


OPERATION = 'ab' * 32
CAPABILITIES = dict(version=1, durable_prepare=True, lookup=True,
                    max_operations=100000, max_wire_bytes=65536)


class DurableWallet:
    """Mock independently retained wallet selection and signed response, no send."""
    def __init__(self, fixture, saved=None):
        self.f = fixture
        self.saved = saved if saved is not None else {}
        self.calls, self.selections = [], 0
        self.reply_patch, self.lookup_patch, self.role_patch, self.capability_patch = {}, {}, {}, {}
        self.timeout = None
        self.return_draft = False
        self.lookup_absent = False
        self.scan_reply = {'height': fixture.height - 1}

    def response(self, operation, status):
        if status == 'absent':
            return dict(status='absent', operation_id=operation, request_hash='', draft_hash='',
                        tx_hash='', tx_as_hex='', fee_atoms=0, principal_atoms=0)
        return dict(status=status, operation_id=operation,
            request_hash=preparation.request_hash(self.f.adapter, self.f.s.rhos[1], operation),
            draft_hash='dd' * 32, tx_hash=self.f.txid if status == 'prepared' else '',
            tx_as_hex=self.f.raw.hex() if status == 'prepared' else '', fee_atoms=1, principal_atoms=1001)

    def __call__(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if self.timeout == method + '-before': raise TimeoutError('private-wallet-error-must-not-escape')
        if method == 'swap_funding_capabilities':
            result = CAPABILITIES | self.capability_patch
        elif method == 'swap_scan_height':
            result = copy.deepcopy(self.scan_reply)
        elif method == 'swap_role':
            result = dict(genesis_hash=self.f.terms['genesis_hash'], commitment=self.f.terms['refund_commitment'],
                          address=self.f.terms['refund_address']) | self.role_patch
        elif method == 'swap_get_funding_preparation':
            operation = params['operation_id']
            result = copy.deepcopy(self.saved.get(operation, self.response(operation, 'absent')))
            if self.lookup_absent: result = self.response(operation, 'absent')
            result.update(self.lookup_patch)
        elif method == 'swap_prepare_funding_once':
            operation = params['operation_id']
            if operation not in self.saved:
                self.selections += 1
                self.saved[operation] = self.response(operation, 'draft')
            if not self.return_draft:
                self.saved[operation] = self.response(operation, 'prepared')
            result = copy.deepcopy(self.saved[operation]) | self.reply_patch
        else:
            raise AssertionError('Unexpected legacy or broadcast RPC: ' + method)
        if self.timeout == method + '-after': raise TimeoutError('private-wallet-error-must-not-escape')
        return result

    def methods(self): return [method for method, _ in self.calls]


class XdsPreparationTests(unittest.TestCase):
    def setUp(self):
        self.f = FundingFixture()
        self.wallet = DurableWallet(self.f)
        self.adapter = XdsFundingAdapter(self.f.rpc, self.f.terms, self.wallet)
        self.rho = self.f.s.rhos[1]

    def prepare(self, resume=False):
        return preparation.prepare(self.adapter, self.rho, OPERATION, resume=resume)

    def test_canonical_request_hash_cross_language_vector(self):
        # Shared C++/Python vector, independent of randomly generated fixture keys.
        terms = SimpleNamespace(genesis_hash=bytes(range(0, 32)).hex(),
            funding_value_atoms=1001, refund_height=80, hashlock=bytes(range(64, 96)).hex(),
            nonce=bytes(range(96, 128)).hex(), claim_commitment=bytes(range(128, 160)).hex())
        adapter = SimpleNamespace(terms=terms)
        result = preparation.request_hash(adapter, bytes(range(160, 192)), bytes(range(32, 64)).hex())
        self.assertEqual(result, '7cee2f192755bd52e0398c04294253fbc8761d78a0f9f28b5018a746be44502a')

    def test_scan_readiness_uses_last_scanned_index_and_stable_daemon_count(self):
        for height, ready in [(0, False), (28, False), (29, True), (30, True), (2**32 - 1, True)]:
            self.wallet.scan_reply, self.wallet.calls = {'height': height}, []
            with self.subTest(height=height), patch.object(self.adapter, '_snapshot', wraps=self.adapter._snapshot) as snapshot:
                self.assertIs(preparation.scan_ready(self.adapter), ready)
                self.assertEqual(snapshot.call_count, 2)
            self.assertEqual(self.wallet.methods(), ['swap_scan_height'])
            self.assertEqual(self.wallet.calls[0][1], {})
        self.assertEqual((self.wallet.selections, self.wallet.saved, self.f.sent), (0, {}, []))

    def test_scan_readiness_changed_daemon_tip_is_wait_without_preparation(self):
        self.wallet.scan_reply = {'height': 100}
        with patch.object(self.adapter, '_snapshot', side_effect=[(30, '11' * 32), (30, '22' * 32)]):
            self.assertFalse(preparation.scan_ready(self.adapter))
        self.assertEqual(self.wallet.methods(), ['swap_scan_height'])
        self.assertEqual((self.wallet.selections, self.wallet.saved, self.f.sent), (0, {}, []))

    def test_scan_readiness_rejects_noncanonical_schema_and_height_types(self):
        for value in [None, [], {}, {'height': True}, {'height': False}, {'height': '29'},
                      {'height': 29.0}, {'height': -1}, {'height': 2**32}, {'height': 29, 'extra': 0}]:
            self.wallet.scan_reply, self.wallet.calls = value, []
            with self.subTest(value=value), self.assertRaises(ValueError): preparation.scan_ready(self.adapter)
            self.assertEqual(self.wallet.methods(), ['swap_scan_height'])
        self.assertEqual((self.wallet.selections, self.wallet.saved, self.f.sent), (0, {}, []))

    def test_scan_readiness_unknown_wallet_response_has_no_selection_side_effect(self):
        self.wallet.timeout = 'swap_scan_height-after'
        with self.assertRaises(_Unavailable) as error: preparation.scan_ready(self.adapter)
        self.assertNotIn('private-wallet-error', str(error.exception))
        self.assertEqual(self.wallet.methods(), ['swap_scan_height'])
        self.assertEqual((self.wallet.selections, self.wallet.saved, self.f.sent), (0, {}, []))

    def test_scan_readiness_invalid_daemon_stops_before_wallet_observation(self):
        for changes in [dict(finality_fork_warning=True), dict(min_fee=2), dict(height=True),
                        dict(last_known_block_index=100), dict(top_block_hash='invalid')]:
            self.f.info_patch, self.wallet.calls = changes, []
            with self.subTest(changes=changes), self.assertRaises((_Unavailable, ValueError)):
                preparation.scan_ready(self.adapter)
            self.assertEqual(self.wallet.calls, [])
        self.assertEqual((self.wallet.selections, self.wallet.saved, self.f.sent), (0, {}, []))

    def test_scan_readiness_unknown_final_daemon_read_is_not_success(self):
        with patch.object(self.adapter, '_snapshot', side_effect=[(30, '11' * 32), _Unavailable('unavailable')]):
            with self.assertRaises(_Unavailable): preparation.scan_ready(self.adapter)
        self.assertEqual(self.wallet.methods(), ['swap_scan_height'])
        self.assertEqual((self.wallet.selections, self.wallet.saved, self.f.sent), (0, {}, []))

    def test_initial_prepare_persists_one_selection_and_never_sends(self):
        self.assertEqual(self.prepare(), (self.f.raw, self.f.txid))
        self.assertEqual(self.wallet.methods(), ['swap_role', 'swap_prepare_funding_once'])
        self.assertEqual(self.wallet.selections, 1)
        self.assertEqual(self.wallet.saved[OPERATION]['status'], 'prepared')
        self.assertEqual(self.f.sent, [])
        self.assertEqual(self.wallet.calls[-1][1], preparation.request(self.adapter, self.rho, OPERATION))

    def test_lost_prepare_reply_then_restarted_lookup_returns_same_wire_without_selection(self):
        self.wallet.timeout = 'swap_prepare_funding_once-after'
        with self.assertRaises(_Unavailable) as error: self.prepare()
        self.assertNotIn('private-wallet-error', str(error.exception))
        self.assertEqual(self.wallet.selections, 1)
        restarted_wallet = DurableWallet(self.f, copy.deepcopy(self.wallet.saved))
        restarted = XdsFundingAdapter(self.f.rpc, self.f.terms, restarted_wallet)
        result = preparation.prepare(restarted, self.rho, OPERATION, resume=True)
        self.assertEqual(result, (self.f.raw, self.f.txid))
        self.assertEqual(restarted_wallet.methods(), ['swap_role', 'swap_get_funding_preparation'])
        self.assertEqual(restarted_wallet.selections, 0)
        self.assertEqual(self.f.sent, [])

    def test_stored_draft_resumes_same_operation_without_reselection(self):
        self.wallet.return_draft = True
        with self.assertRaises(_Unavailable): self.prepare()
        self.assertEqual(self.wallet.saved[OPERATION]['status'], 'draft')
        original_request = self.wallet.calls[-1][1]
        self.wallet.return_draft = False
        self.wallet.calls.clear()
        self.assertEqual(self.prepare(resume=True), (self.f.raw, self.f.txid))
        self.assertEqual(self.wallet.methods(), ['swap_role', 'swap_get_funding_preparation', 'swap_prepare_funding_once'])
        self.assertEqual(self.wallet.calls[-1][1], original_request)
        self.assertEqual(self.wallet.selections, 1)

    def test_resumed_draft_still_incomplete_stops_after_one_exact_attempt(self):
        self.wallet.saved[OPERATION] = self.wallet.response(OPERATION, 'draft')
        self.wallet.return_draft = True
        with self.assertRaises(_Unavailable): self.prepare(resume=True)
        self.assertEqual(self.wallet.methods().count('swap_prepare_funding_once'), 1)
        self.assertEqual(self.wallet.selections, 0)

    def test_absent_retained_operation_never_authorizes_prepare(self):
        with self.assertRaises(_Unavailable): self.prepare(resume=True)
        self.assertEqual(self.wallet.methods(), ['swap_role', 'swap_get_funding_preparation'])
        self.assertEqual(self.wallet.selections, 0)
        self.assertEqual(self.wallet.saved, {})

    def test_lost_lookup_response_never_authorizes_prepare(self):
        self.wallet.saved[OPERATION] = self.wallet.response(OPERATION, 'draft')
        self.wallet.timeout = 'swap_get_funding_preparation-after'
        with self.assertRaises(_Unavailable): self.prepare(resume=True)
        self.assertEqual(self.wallet.methods(), ['swap_role', 'swap_get_funding_preparation'])
        self.assertEqual(self.wallet.selections, 0)

    def test_lost_first_request_before_acceptance_remains_absent_after_restart(self):
        self.wallet.timeout = 'swap_prepare_funding_once-before'
        with self.assertRaises(_Unavailable): self.prepare()
        self.wallet.timeout = None
        self.wallet.calls.clear()
        with self.assertRaises(_Unavailable): self.prepare(resume=True)
        self.assertEqual(self.wallet.methods(), ['swap_role', 'swap_get_funding_preparation'])
        self.assertEqual(self.wallet.selections, 0)

    def test_draft_hash_change_during_exact_resume_refused(self):
        self.wallet.saved[OPERATION] = self.wallet.response(OPERATION, 'draft')
        self.wallet.reply_patch = dict(draft_hash='ee' * 32)
        with self.assertRaisesRegex(ValueError, 'draft'): self.prepare(resume=True)
        self.assertEqual(self.wallet.selections, 0)
        self.assertEqual(self.f.sent, [])

    def test_lookup_changed_request_hash_stops_before_resume_signing(self):
        self.wallet.saved[OPERATION] = self.wallet.response(OPERATION, 'draft')
        self.wallet.lookup_patch = dict(request_hash='ee' * 32)
        with self.assertRaises(ValueError): self.prepare(resume=True)
        self.assertNotIn('swap_prepare_funding_once', self.wallet.methods())

    def test_mutated_operation_or_role_request_rejected_before_preparation(self):
        for operation, rho in [('ab', self.rho), ('AB' * 32, self.rho), (OPERATION, bytearray(self.rho)),
                               (OPERATION, self.rho[:-1])]:
            with self.subTest(operation=operation, rho_type=type(rho).__name__):
                with self.assertRaises(ValueError): preparation.prepare(self.adapter, rho, operation)
        self.assertEqual(self.wallet.calls, [])

    def test_nonboolean_resume_rejected_without_rpc(self):
        for resume in [0, 1, None, 'true']:
            with self.subTest(resume=resume), self.assertRaises(ValueError): self.prepare(resume)
        self.assertEqual(self.wallet.calls, [])

    def test_claimed_wallet_identity_cannot_substitute_a_different_refund_rho(self):
        # The mock role RPC claims the expected identity; actual input authority
        # must independently bind the supplied refund rho to the agreed wallet.
        different = bytes([0x99]) * 32
        self.wallet.reply_patch = dict(request_hash=preparation.request_hash(self.adapter, different, OPERATION))
        with self.assertRaisesRegex(ValueError, 'agreed native wallet'):
            preparation.prepare(self.adapter, different, OPERATION)
        self.assertEqual(self.f.sent, [])

    def test_wrong_refund_wallet_address_network_commitment_stops_before_prepare(self):
        for changes in [dict(address='wrong'), dict(genesis_hash='ee' * 32), dict(commitment='ee' * 32)]:
            self.wallet.role_patch, self.wallet.calls = changes, []
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.prepare()
            self.assertEqual(self.wallet.methods(), ['swap_role'])

    def test_current_deadline_and_daemon_fee_fork_lag_stop_before_prepare(self):
        for changes in [dict(min_fee=2), dict(min_fee=True), dict(finality_fork_warning=True),
                        dict(last_known_block_index=100)]:
            self.f.info_patch, self.wallet.calls = changes, []
            with self.subTest(changes=changes), self.assertRaises((_Unavailable, ValueError)): self.prepare()
            self.assertEqual(self.wallet.methods(), ['swap_role'])
        self.f.info_patch, self.wallet.calls = {}, []
        self.f.height = self.f.terms['refund_height']
        with self.assertRaises(_Unavailable): self.prepare()
        self.assertEqual(self.wallet.methods(), ['swap_role'])

    def test_response_fee_principal_and_bool_ambiguity_refused(self):
        for changes in [dict(fee_atoms=0), dict(fee_atoms=2), dict(fee_atoms=True),
                        dict(principal_atoms=True), dict(principal_atoms=1002)]:
            self.wallet.reply_patch = changes
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.f.sent, [])

    def test_response_identity_hash_and_schema_binding(self):
        for changes in [dict(operation_id='ee' * 32), dict(request_hash='ee' * 32),
                        dict(draft_hash='EE' * 32), dict(draft_hash='ee'), dict(tx_hash='ee' * 32),
                        dict(status='signed'), dict(extra=0)]:
            self.wallet.reply_patch = changes
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.f.sent, [])

    def test_absent_response_cannot_smuggle_prepared_data(self):
        for changes in [dict(fee_atoms=1), dict(principal_atoms=1), dict(tx_hash='ee' * 32),
                        dict(draft_hash='ee' * 32), dict(tx_as_hex='00')]:
            self.wallet.lookup_patch = changes
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.prepare(resume=True)
        self.assertNotIn('swap_prepare_funding_once', self.wallet.methods())

    def test_draft_response_cannot_expose_prepared_wire(self):
        self.wallet.saved[OPERATION] = self.wallet.response(OPERATION, 'draft')
        for changes in [dict(tx_hash=self.f.txid), dict(tx_as_hex=self.f.raw.hex())]:
            self.wallet.lookup_patch = changes
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.prepare(resume=True)
        self.assertNotIn('swap_prepare_funding_once', self.wallet.methods())

    def test_prepared_wire_truncation_noncanonical_size_and_signature_refused(self):
        bad_signature = self.f.raw[:-1] + bytes([self.f.raw[-1] ^ 1])
        cases = [dict(tx_as_hex=self.f.raw.hex().upper()), dict(tx_as_hex=self.f.raw.hex() + ' '),
                 dict(tx_as_hex=''), dict(tx_as_hex='00' * 65537), dict(tx_as_hex=self.f.raw[:-1].hex()),
                 dict(tx_as_hex=bad_signature.hex(), tx_hash=_h(bad_signature).hex())]
        for changes in cases:
            self.wallet.reply_patch = changes
            with self.subTest(length=len(changes['tx_as_hex'])), self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.f.sent, [])

    def test_validly_signed_wrong_funding_fee_fails_independent_wire_validation(self):
        for fee in [0, 2]:
            raw, txid = self.f.wire(fee=fee)
            self.wallet.reply_patch = dict(tx_as_hex=raw.hex(), tx_hash=txid)
            with self.subTest(fee=fee), self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.f.sent, [])

    def test_current_spent_unknown_input_or_chain_binding_refuses_retained_wire(self):
        self.wallet.saved[OPERATION] = self.wallet.response(OPERATION, 'prepared')
        for changes in [dict(spent=True), dict(spent_in_pool=True), dict(spent_known=False),
                        dict(genesis_hash='ee' * 32), dict(spend_tag='ee' * 32), dict(amount_atoms=4999)]:
            self.f.source_patch, self.wallet.calls = changes, []
            with self.subTest(changes=changes), self.assertRaises((_Unavailable, ValueError)): self.prepare(resume=True)
            self.assertNotIn('swap_prepare_funding_once', self.wallet.methods())
        self.assertEqual(self.f.sent, [])

    def test_current_chain_change_during_prepared_input_checks_refused(self):
        original, calls = self.f.rpc, 0
        def changing(method, params):
            nonlocal calls
            response = original(method, params)
            if method == 'getinfo':
                calls += 1
                if calls >= 3: response['top_block_hash'] = 'ee' * 32
            return response
        self.adapter = XdsFundingAdapter(changing, self.f.terms, self.wallet)
        with self.assertRaises(_Unavailable): self.prepare()
        self.assertEqual(self.f.sent, [])

    def test_capability_requires_exact_durable_bounded_v1_profile(self):
        self.assertEqual(preparation.capabilities(self.adapter), CAPABILITIES)
        for changes in [dict(version=True), dict(version=2), dict(durable_prepare=1), dict(lookup=False),
                        dict(max_operations=0), dict(max_operations=True), dict(max_operations=100001),
                        dict(max_wire_bytes=65535), dict(extra=0)]:
            self.wallet.capability_patch = changes
            with self.subTest(changes=changes), self.assertRaises(ValueError): preparation.capabilities(self.adapter)
        self.assertEqual(self.wallet.selections, 0)


if __name__ == '__main__':
    unittest.main()
