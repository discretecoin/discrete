import copy
import struct
import unittest

from swap_runtime.xds import _parse, _h, _commit, _Unavailable, SIGN_DOMAIN
from swap_runtime.xds_funding import XdsFundingAdapter, FundingTerms, _source, _nullifier, _wire_hex
from test_xds import Fixture as SettlementFixture, var


class FundingFixture:
    def __init__(self):
        self.s = SettlementFixture()
        self.terms = {k: v for k, v in self.s.terms.items() if k not in ('funding_txid', 'funding_vout', 'funding_wire')}
        self.terms['net_amount_atoms'] = 1000
        self.height, self.sources, self.entries = 30, {}, {}
        self.sent, self.wallet_calls, self.source_patch = [], [], {}
        self.wallet_patch, self.info_patch, self.lost_ack = {}, {}, False
        self.add_source(5000, 0)
        self.raw, self.txid = self.wire()
        self.adapter = XdsFundingAdapter(self.rpc, self.terms, self.wallet)

    def add_source(self, amount, number, family=0, lock=20):
        commitment = _commit(self.s.pubs[1], self.s.rhos[1])
        output = var(amount) + var(lock) + (b'\x11' if family == 0 else b'\x10' + b'k' * 1088 + b'e' * 56) + commitment
        if family == 0:
            raw = b'\x01\0' + var(lock) + b'\x01\xff' + var(number + 1) + b'\x01' + output + b'\0'
        else:
            raw = (b'\x01' + var(family) + b'\0\x01\x10' + bytes([number]) * 32 + b'\0' + self.s.pubs[1]
                   + self.s.rhos[1] + b'\x01' + output + b'\0' + b'\0' * 3309)
        txid = _h(raw).hex()
        self.sources[txid] = (raw, output)
        return txid

    def wire(self, fee=1, references=None, family=6):
        references = list(self.sources) if references is None else references
        amount = sum(_source(self.sources[txid][0])['outputs'][0]['amount'] for txid in references)
        change = amount - 1001 - fee
        inputs = b''.join(b'\x10' + bytes.fromhex(txid) + b'\0' + self.s.pubs[1] + self.s.rhos[1] for txid in references)
        outputs = self.s.output
        if change:
            outputs += var(change) + b'\0\x10' + b'k' * 1088 + b'e' * 56 + b'c' * 32
        prefix = b'\x01' + var(family) + b'\0' + var(len(references)) + inputs + var(1 + bool(change)) + outputs
        resolved = [self.sources[txid][1] for txid in references]
        tail = (struct.pack('<I', len(prefix)) + prefix + struct.pack('<I', len(resolved))
                + b''.join(struct.pack('<I', len(output)) + output for output in resolved) + struct.pack('<Q', fee))
        signatures = b''.join(self.s.keys[1].sign(_h(SIGN_DOMAIN + bytes.fromhex(self.terms['genesis_hash'])
            + struct.pack('<I', index) + tail)) for index in range(len(references)))
        raw = prefix + signatures
        return raw, _h(raw).hex()

    def state(self, raw=None, block=None):
        return dict(status='OK', height=self.height, tip_hash=_h(str(self.height).encode()).hex(),
            genesis_hash=self.terms['genesis_hash'], found=raw is not None, in_chain=block is not None,
            in_pool=raw is not None and block is None, spent_known=False, spent=False, spent_in_pool=False,
            block_height=block or 0, block_hash=_h(str(block).encode()).hex() if block is not None else '',
            confirmations=self.height - block if block is not None else 0,
            amount_atoms=_source(raw)['outputs'][0]['amount'] if raw else 0,
            tx_as_hex=raw.hex() if raw else '', spend_tag='')

    def rpc(self, method, params):
        if method == 'getinfo':
            return dict(dict(status='OK', height=self.height, top_block_hash=_h(str(self.height).encode()).hex(),
                finality_fork_warning=False, last_known_block_index=self.height - 1, min_fee=1), **self.info_patch)
        if method == 'get_swap_outpoint':
            txid = params['txid']
            if txid in self.sources:
                result = self.state(self.sources[txid][0], 2)
                result.update(spent_known=True, spend_tag=params['spend_tag'],
                    spent=any(block is not None for _, block in self.entries.values()),
                    spent_in_pool=any(block is None for _, block in self.entries.values()))
                result.update(self.source_patch)
                return result
            return self.state(*self.entries[txid]) if txid in self.entries else self.state()
        if method == 'sendrawtransaction':
            raw = bytes.fromhex(params['tx_as_hex'])
            txid = _parse(raw)['txid']
            self.sent.append(raw)
            self.entries[txid] = (raw, None)
            if self.lost_ack:
                self.lost_ack = False
                raise TimeoutError('private-password-must-not-escape')
            return {'status': 'OK'}
        raise AssertionError(method)

    def wallet(self, method, params):
        self.wallet_calls.append(method)
        if method == 'swap_role':
            result = dict(genesis_hash=self.terms['genesis_hash'], commitment=self.terms['refund_commitment'],
                          address=self.terms['refund_address'])
        elif method == 'swap_prepare_funding':
            result = dict(tx_as_hex=self.raw.hex(), tx_hash=self.txid, fee_atoms=1, principal_atoms=1001)
        else:
            raise AssertionError(method)
        result.update(self.wallet_patch)
        return result


class XdsFundingTests(unittest.TestCase):
    def setUp(self):
        self.f = FundingFixture()
        self.a = self.f.adapter

    def test_signed_funding_binds_gross_net_both_fees_and_change(self):
        checked = self.a.validate(self.f.raw, self.f.txid)
        self.assertEqual((checked['funding_fee_atoms'], checked['exit_fee_atoms'], checked['net_amount_atoms']), (1, 1, 1000))
        self.assertEqual(checked['change_atoms'], 3998)
        self.assertEqual(checked['terms']['funding_wire'], self.f.raw.hex())
        self.assertTrue(checked['inputs_unspent'])
        selected = checked['selected_inputs'][0]
        self.assertEqual(selected['reservation_key'], self.f.terms['genesis_hash'] + ':' + selected['txid'] + ':0')
        self.assertEqual(selected['spend_tag'], _nullifier(_parse(self.f.raw)['inputs'][0]))

    def test_signed_old_four_funding_cannot_alias_pq_v2(self):
        self.assertEqual(_parse(self.f.raw)['family'], 0x06)
        self.assertEqual(self.a.validate(self.f.raw, self.f.txid)['funding_fee_atoms'], 1)
        # The old family is signed as such, and its identity is recomputed.
        old, old_txid = self.f.wire(family=0x04)
        for check in (_parse, _source):
            with self.subTest(check=check.__name__), self.assertRaises(ValueError):
                check(old)
        with self.assertRaises(ValueError):
            self.a.validate(old, old_txid)
        self.assertEqual(self.f.sent, [])

    def test_pq_and_pq_v2_sources_share_output_wire_but_not_identity(self):
        parsed = []
        for family in (0x01, 0x04):
            txid = self.f.add_source(2000, 2, family=family)
            raw, output = self.f.sources[txid]
            item = _source(raw)
            self.assertEqual((raw[1], item['family'], item['txid']), (family, family, txid))
            self.assertEqual(item['outputs'][0]['wire'], output)
            self.assertEqual((item['outputs'][0]['amount'], item['outputs'][0]['lock']), (2000, 20))
            with self.assertRaises(ValueError):
                _parse(raw)
            parsed.append(item)
        self.assertEqual(parsed[0]['outputs'], parsed[1]['outputs'])
        self.assertNotEqual(parsed[0]['txid'], parsed[1]['txid'])

    def test_pq_v2_source_requires_pq_input_and_encrypted_output_tags(self):
        txid = self.f.add_source(2000, 2, family=0x04)
        raw, output = self.f.sources[txid]
        output_at = 4 + 1 + 32 + 1 + len(self.f.s.pubs[1]) + len(self.f.s.rhos[1]) + 1
        self.assertEqual(raw[output_at:output_at + len(output)], output)
        coinbase_input = b'\x01\x04\0\x01\xff\x03\x01' + output + b'\0'
        transparent_output = var(2000) + var(20) + b'\x11' + _commit(self.f.s.pubs[1], self.f.s.rhos[1])
        transparent = raw[:output_at] + transparent_output + b'\0' + b'\0' * 3309
        for malformed in (coinbase_input, transparent):
            with self.subTest(size=len(malformed)), self.assertRaises(ValueError):
                _source(malformed)

    def test_pq_v2_source_keeps_extra_and_complete_signature_length(self):
        txid = self.f.add_source(2000, 2, family=0x04)
        raw, output = self.f.sources[txid]
        extra_at = len(raw) - 3309 - 1
        with_extra = raw[:extra_at] + b'\x03abc' + raw[extra_at + 1:]
        self.assertEqual(_source(with_extra)['outputs'][0]['wire'], output)
        self.assertEqual(_source(with_extra)['txid'], _h(with_extra).hex())
        for malformed in (raw[:4], raw[:100], raw[:extra_at], raw[:-3309], raw[:-1],
                          raw + b'\0', raw + b'\0' * 3309, b'\x81\0' + raw[1:],
                          raw[:1] + b'\x84\0' + raw[2:]):
            with self.subTest(size=len(malformed)), self.assertRaises(ValueError):
                _source(malformed)

    def test_pq_v2_funding_source_still_requires_current_chain_admission(self):
        txid = self.f.add_source(2000, 2, family=0x04)
        raw, identity = self.f.wire(references=[txid])
        self.assertTrue(self.a.validate(raw, identity)['inputs_unspent'])
        for patch in ({'amount_atoms': 1999}, {'genesis_hash': '44' * 32}, {'spent_known': False},
                      {'in_pool': True}, {'spent': 1}, {'spend_tag': '44' * 32}):
            self.f.source_patch = patch
            with self.subTest(patch=patch), self.assertRaises((_Unavailable, ValueError)):
                self.a.validate(raw, identity)
        self.f.source_patch = {'spent': True}
        self.assertFalse(self.a.validate(raw, identity)['inputs_unspent'])
        self.assertEqual(self.f.sent, [])

    def test_terms_are_closed_and_no_fee_or_value_ambiguity(self):
        for patch in ({'fee_atoms': 2}, {'fee_atoms': True}, {'net_amount_atoms': 1001}, {'min_confirmations': 0},
                      {'unexpected': 0}, {'nonce': 'AA' * 32}, {'refund_address': self.f.terms['claim_address']}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                FundingTerms.parse(dict(self.f.terms, **patch))
        plan = self.a.plan()
        plan['nonce'] = '44' * 32
        self.assertNotEqual(plan, self.a.plan())

    def test_multiinput_coinbase_pq_and_pq_v2_source_signatures(self):
        self.f.add_source(2000, 2, family=1)
        self.f.add_source(3000, 3, family=4)
        raw, txid = self.f.wire()
        result = self.a.validate(raw, txid)
        self.assertEqual(len(result['selected_inputs']), 3)
        self.assertEqual(result['change_atoms'], 8998)
        parsed = _parse(raw)
        swapped = parsed['prefix'] + b''.join(reversed(parsed['signatures']))
        with self.assertRaises(ValueError):
            self.a.validate(swapped, _h(swapped).hex())

    def test_changed_plan_source_or_signature_cannot_authorize_funding(self):
        for field in ('nonce', 'hashlock', 'claim_commitment', 'refund_commitment'):
            adapter = XdsFundingAdapter(self.f.rpc, dict(self.f.terms, **{field: '44' * 32}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                adapter.validate(self.f.raw, self.f.txid)
        bad = self.f.raw[:-1] + bytes([self.f.raw[-1] ^ 1])
        with self.assertRaises(ValueError):
            self.a.validate(bad, _h(bad).hex())
        self.f.source_patch = {'amount_atoms': 4999}
        with self.assertRaises(_Unavailable):
            self.a.validate(self.f.raw, self.f.txid)

    def test_signed_wrong_fee_duplicate_and_overflow_inputs_are_rejected(self):
        for fee in (0, 2):
            raw, txid = self.f.wire(fee=fee)
            with self.assertRaises(ValueError):
                self.a.validate(raw, txid)
        raw, txid = self.f.wire(references=list(self.f.sources) * 2)
        with self.assertRaises(ValueError):
            self.a.validate(raw, txid)
        self.f.add_source(2**64 - 1, 2)
        raw, txid = self.f.wire()
        with self.assertRaises(ValueError):
            self.a.validate(raw, txid)

    def test_source_wire_is_complete_canonical_and_bounded(self):
        raw = next(iter(self.f.sources.values()))[0]
        self.assertEqual(_source(raw)['txid'], _h(raw).hex())
        for length in range(len(raw)):
            with self.assertRaises(ValueError):
                _source(raw[:length])
        for malformed in (b'\x81\0' + raw[1:], raw + b'\0', b'x' * (1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                _source(malformed)
        for badhex in (raw.hex().upper(), raw.hex() + ' ', 123):
            with self.assertRaises(ValueError):
                _wire_hex(badhex)

    def test_prepare_checks_refund_wallet_before_native_preparation(self):
        for patch in ({'address': 'another'}, {'commitment': '44' * 32}, {'genesis_hash': '44' * 32}):
            self.f.wallet_patch, self.f.wallet_calls = patch, []
            with self.assertRaises(ValueError):
                self.a.prepare(self.f.s.rhos[1])
            self.assertEqual(self.f.wallet_calls, ['swap_role'])

    def test_prepare_validates_wire_and_does_not_send(self):
        self.assertEqual(self.a.prepare(self.f.s.rhos[1]), (self.f.raw, self.f.txid))
        self.assertEqual(self.f.sent, [])
        for patch in ({'tx_hash': '44' * 32}, {'fee_atoms': True}, {'principal_atoms': 1002}):
            self.f.wallet_patch = patch
            with self.assertRaises(ValueError):
                self.a.prepare(self.f.s.rhos[1])

    def test_unknown_prepare_reply_never_repeats_rpc_or_exposes_auth(self):
        calls = []
        def lost(method, params):
            calls.append(method)
            if method == 'swap_prepare_funding':
                raise TimeoutError('private-password-must-not-escape')
            return self.f.wallet(method, params)
        with self.assertRaises(_Unavailable) as error:
            XdsFundingAdapter(self.f.rpc, self.f.terms, lost).prepare(self.f.s.rhos[1])
        self.assertEqual(calls.count('swap_prepare_funding'), 1)
        self.assertNotIn('private-password', str(error.exception))
        self.assertEqual(self.f.sent, [])

    def test_lost_send_ack_and_reopen_reconcile_exact_wire_without_second_send(self):
        self.f.lost_ack = True
        with self.assertRaises(_Unavailable):
            self.a.send(self.f.raw, self.f.txid)
        restarted = XdsFundingAdapter(self.f.rpc, self.a.plan())
        self.assertEqual(restarted.receipt(self.f.raw, self.f.txid)['status'], 'pending')
        self.assertEqual(restarted.send(self.f.raw, self.f.txid), self.f.txid)
        self.assertEqual(self.f.sent, [self.f.raw])
        self.assertEqual(self.f.wallet_calls, [])

    def test_current_receipt_loses_finality_after_reorg(self):
        self.f.entries[self.f.txid] = (self.f.raw, 10)
        receipt = self.a.resolve(self.f.raw, self.f.txid)['receipt']
        self.assertTrue(receipt['final'])
        self.assertTrue(receipt['publicly_observed'])
        self.f.entries[self.f.txid] = (self.f.raw, None)
        receipt = self.a.receipt(self.f.raw, self.f.txid)
        self.assertEqual(receipt['status'], 'pending')
        self.assertFalse(receipt['final'])
        self.f.entries.clear()
        self.assertEqual(self.a.receipt(self.f.raw, self.f.txid)['status'], 'unknown')

    def test_receipt_requires_source_spentness_and_before_deadline_inclusion(self):
        self.f.entries[self.f.txid] = (self.f.raw, 10)
        self.f.source_patch = {'spent': False}
        self.assertEqual(self.a.receipt(self.f.raw, self.f.txid)['status'], 'unknown')
        self.f.source_patch = {}
        self.f.height = 90
        self.f.entries[self.f.txid] = (self.f.raw, 80)
        self.assertEqual(self.a.receipt(self.f.raw, self.f.txid)['status'], 'unknown')

    def test_interference_unknown_spentness_and_immaturity_prevent_send(self):
        for patch in ({'spent': True}, {'spent_in_pool': True}, {'spent_known': False}, {'spend_tag': '44' * 32},
                      {'genesis_hash': '44' * 32}, {'in_pool': True}, {'spent': 1}):
            self.f.source_patch = patch
            with self.subTest(patch=patch), self.assertRaises((_Unavailable, ValueError)):
                self.a.send(self.f.raw, self.f.txid)
            self.assertEqual(self.f.sent, [])
        self.f.source_patch = {}
        self.f.height = 20
        with self.assertRaises(_Unavailable):
            self.a.send(self.f.raw, self.f.txid)
        self.assertEqual(self.f.sent, [])

    def test_fork_lag_fee_drift_deadline_and_rpc_loss_fail_closed(self):
        for patch in ({'finality_fork_warning': True}, {'last_known_block_index': 31}, {'min_fee': 2}):
            self.f.info_patch = patch
            self.assertEqual(self.a.receipt(self.f.raw, self.f.txid)['status'], 'unknown')
            with self.assertRaises(_Unavailable):
                self.a.send(self.f.raw, self.f.txid)
        self.f.info_patch = {}
        self.f.height = 80
        with self.assertRaises(_Unavailable):
            self.a.prepare(self.f.s.rhos[1])
        def unavailable(method, params):
            raise TimeoutError('private-password-must-not-escape')
        adapter = XdsFundingAdapter(unavailable, self.f.terms)
        self.assertEqual(adapter.receipt(self.f.raw, self.f.txid)['status'], 'unknown')
        self.assertEqual(self.f.sent, [])

    def test_same_height_tip_change_invalidates_entire_input_snapshot(self):
        original, calls = self.f.rpc, 0
        def replaced(method, params):
            nonlocal calls
            result = original(method, params)
            if method == 'getinfo':
                calls += 1
                if calls >= 2:
                    result['top_block_hash'] = '99' * 32
            return result
        adapter = XdsFundingAdapter(replaced, self.f.terms)
        with self.assertRaises(_Unavailable):
            adapter.validate(self.f.raw, self.f.txid)
        self.assertEqual(self.f.sent, [])


if __name__ == '__main__':
    unittest.main()
