"""Funding plan/witness/state-machine faults with a synthetic owned wallet RPC.

Real Bitcoin Core tests separately qualify wire signing and consensus admission.
"""
import copy
from decimal import Decimal
import hashlib
import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from swap_runtime.bitcoin import N, _compact, _parse, _u32, dsha, pubkey, sha
from swap_runtime.bitcoin_funding import BitcoinFundingAdapter
from test_bitcoin import terms as settlement_terms


def script(key):
    return '0014' + hashlib.new('ripemd160', sha(pubkey(key))).hexdigest()


def configuration():
    contract = settlement_terms()
    contract.pop('funding_txid')
    contract.pop('funding_vout')
    contract['refund_height'] = 400
    return {'contract': contract, 'funding_fee_sats': 1000,
            'change_address': 'bcrt1qfixturechangeaddress',
            'change_script': script(ec.derive_private_key(82, ec.SECP256K1())), 'min_input_confirmations': 2}


class FundingCore:
    def __init__(self):
        self.terms = configuration()
        self.height, self.funding_height = 300, 295
        self.tip, self.block = '05' * 32, '06' * 32
        self.key = ec.derive_private_key(81, ec.SECP256K1())
        self.input = {'txid': '11' * 32, 'vout': 1, 'value_sats': 200000, 'script_pubkey': script(self.key)}
        self.coins = [dict(txid=self.input['txid'], vout=1, amount=Decimal('0.002'),
                           scriptPubKey=self.input['script_pubkey'], spendable=True, solvable=True, safe=True)]
        self.locked = set()
        self.calls = []
        self.raw = None
        self.plan = None
        self.confirmed = False
        self.funding_spent = False
        self.other_spent = False
        self.unknown = False
        self.orphaned = False
        self.input_confirmations = 20
        self.is_mine = True
        self.change_override = None
        self.wallet_genesis = self.terms['contract']['genesis_hash']
        self.failures = {}
        self.lost_lock_ack = False
        self.lost_send_ack = False
        self.admissible = True
        self.sign_complete = True
        self.change_signature = False
        self.sign_mutation = None
        self.adapter = BitcoinFundingAdapter(self.node, self.wallet, self.terms)

    def unsigned_sign(self, unsigned, plan):
        parsed = _parse(unsigned)
        stacks = []
        for index in range(len(parsed['inputs'])):
            sig = self.key.sign(self.adapter._signature_digest(plan, index), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            r, s = utils.decode_dss_signature(sig)
            sig = utils.encode_dss_signature(r, min(s, N-s)) + b'\x01'
            if self.change_signature:
                sig = sig[:-1] + b'\x02'
            stacks.append(b'\x02' + _compact(len(sig)) + sig + b'\x21' + pubkey(self.key))
        return unsigned[:4] + b'\x00\x01' + unsigned[4:-4] + b''.join(stacks) + unsigned[-4:]

    def wallet(self, method, params):
        self.calls.append(('wallet', method, params))
        if method in self.failures:
            raise self.failures[method]
        if method == 'getblockhash':
            return self.wallet_genesis
        if method == 'getaddressinfo':
            return {'ismine': self.is_mine, 'scriptPubKey': self.change_override or self.terms['change_script']}
        if method == 'listunspent':
            return copy.deepcopy(self.coins)
        if method == 'listlockunspent':
            return [{'txid': txid, 'vout': vout} for txid, vout in sorted(self.locked)]
        if method == 'lockunspent':
            if params[0] is not False or params[2] is not True:
                raise AssertionError('Funding must only add persistent explicit locks')
            self.locked.update((i['txid'], i['vout']) for i in params[1])
            if self.lost_lock_ack:
                raise TimeoutError('persistent lock acknowledged late')
            return True
        if method == 'signrawtransactionwithwallet':
            if params[2] != 'ALL':
                raise AssertionError('non-ALL signing')
            raw = self.unsigned_sign(bytes.fromhex(params[0]), self.plan)
            if self.sign_mutation:
                raw = self.sign_mutation(raw)
            return {'complete': self.sign_complete, 'hex': raw.hex()}
        raise AssertionError(method)

    def node(self, method, params):
        self.calls.append(('node', method, params))
        if method in self.failures:
            raise self.failures[method]
        if method == 'getblockhash':
            if params[0] == 0:
                return self.terms['contract']['genesis_hash']
            return '07' * 32 if self.orphaned else self.block
        if method == 'getblockchaininfo':
            return {'blocks': self.height, 'headers': self.height, 'bestblockhash': self.tip, 'initialblockdownload': False}
        if method == 'getblockheader':
            return {'hash': self.block, 'height': self.funding_height,
                    'confirmations': -1 if self.orphaned else self.height-self.funding_height+1}
        if method == 'gettxout':
            funding = self.plan and params[0] == self.plan['expected_txid']
            if funding:
                if not self.raw or self.funding_spent:
                    return None
                return {'bestblock': self.tip, 'confirmations': self.height-self.funding_height+1 if self.confirmed else 0,
                        'value': Decimal('0.001'), 'scriptPubKey': {'hex': self.adapter.contract.output_script().hex()}}
            if self.other_spent or self.raw and (self.confirmed or params[2]):
                return None
            return {'bestblock': self.tip, 'confirmations': self.input_confirmations, 'coinbase': False,
                    'value': Decimal(self.input['value_sats']) / 100000000,
                    'scriptPubKey': {'hex': self.input['script_pubkey']}}
        if method == 'getrawtransaction':
            if self.raw is None or self.unknown:
                raise ValueError('transaction not observed')
            parsed = _parse(self.raw)
            result = {'hex': self.raw.hex(), 'txid': parsed['txid'], 'hash': parsed['wtxid']}
            if self.confirmed:
                result.update(blockhash=self.block, confirmations=self.height-self.funding_height+1)
            return result
        if method == 'getmempoolentry':
            if not self.raw or self.confirmed:
                raise ValueError('not in mempool')
            return {'wtxid': _parse(self.raw)['wtxid']}
        if method == 'testmempoolaccept':
            return [{'txid': _parse(bytes.fromhex(params[0][0]))['txid'], 'allowed': self.admissible}]
        if method == 'sendrawtransaction':
            self.raw = bytes.fromhex(params[0])
            if self.lost_send_ack:
                raise TimeoutError('accepted funding, acknowledgment lost')
            return _parse(self.raw)['txid']
        raise AssertionError(method)

    def prepared(self):
        self.plan = self.adapter.plan()
        return self.plan, *self.adapter.prepare(self.plan)


class BitcoinFundingTests(unittest.TestCase):
    def setUp(self):
        self.core = FundingCore()
        self.adapter = self.core.adapter

    def sends(self):
        return [call for call in self.core.calls if call[1] == 'sendrawtransaction']

    def test_plan_read_only_stable_txid_fixed_output_and_owned_change(self):
        plan = self.adapter.plan()
        self.assertEqual(plan['deadline_remaining'], 100)
        self.assertEqual(plan['change_value_sats'], 99000)
        self.assertEqual(plan['inputs'], [self.core.input])
        self.assertEqual(self.core.locked, set())
        self.assertEqual(self.sends(), [])
        self.assertNotIn('signrawtransactionwithwallet', [c[1] for c in self.core.calls])
        self.assertEqual(self.adapter.plan(), plan)
        self.core.plan = plan
        raw, txid = self.adapter.prepare(plan)
        checked = self.adapter.validate(plan, raw, txid)
        self.assertEqual(checked['fee_sats'], 1000)
        self.assertEqual(checked['funding_vout'], 0)
        self.assertEqual(txid, plan['expected_txid'])
        self.assertEqual(self.core.locked, {('11' * 32, 1)})
        self.assertEqual(self.sends(), [])

    def test_configuration_and_returned_terms_mutation_cannot_rebind(self):
        expected = self.adapter.terms
        self.core.terms['funding_fee_sats'] = 2000
        exported = self.adapter.terms
        exported['contract']['claim_script'] = '0014' + 'ff' * 20
        self.assertEqual(self.adapter.terms, expected)

    def test_configuration_rejects_non_native_change_wrong_types_and_extra_fields(self):
        for delta in ({'other': 1}, {'funding_fee_sats': True}, {'min_input_confirmations': 0},
                      {'change_script': '0014' + 'FF' * 20}, {'change_script': '5120' + '01' * 32},
                      {'change_address': 'http://bad address'}):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                BitcoinFundingAdapter(self.core.node, self.core.wallet, dict(configuration(), **delta))

    def test_change_wallet_ownership_script_and_genesis_must_match(self):
        for field, value in (('is_mine', False), ('change_override', '0014' + 'ff' * 20), ('wallet_genesis', '09' * 32)):
            with self.subTest(field=field):
                prior = getattr(self.core, field)
                setattr(self.core, field, value)
                with self.assertRaises(ValueError):
                    self.adapter.plan()
                setattr(self.core, field, prior)
        self.assertEqual(self.core.locked, set())

    def test_reserved_unsafe_unspendable_non_native_or_insufficient_coins_are_not_selected(self):
        original = copy.deepcopy(self.core.coins)
        for delta in ({'safe': False}, {'spendable': False}, {'solvable': False}, {'scriptPubKey': 'a914' + '01' * 20 + '87'}):
            self.core.coins = [dict(original[0], **delta)]
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                self.adapter.plan()
        self.core.coins = original
        self.core.locked.add(('11' * 32, 1))
        with self.assertRaises(ValueError):
            self.adapter.plan()

    def test_saved_plan_tamper_rejects_before_any_lock_or_signature(self):
        plan = self.adapter.plan()
        changes = ({'terms_hash': '00' * 32}, {'expected_txid': '00' * 32}, {'change_value_sats': 98999},
                   {'deadline_remaining': 99}, {'selected_height': True}, {'version': True}, {'extra': 1})
        for delta in changes:
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                self.adapter.prepare(dict(plan, **delta))
        duplicated = copy.deepcopy(plan)
        duplicated['inputs'] *= 2
        with self.assertRaises(ValueError):
            self.adapter.prepare(duplicated)
        self.assertEqual(self.core.locked, set())

    def test_persistent_lock_lost_ack_retry_uses_same_plan_without_reselection(self):
        self.core.plan = self.adapter.plan()
        retained = json.loads(json.dumps(self.core.plan))
        self.core.lost_lock_ack = True
        with self.assertRaises(Exception):
            self.adapter.prepare(retained)
        self.assertEqual(self.core.locked, {('11' * 32, 1)})
        self.core.lost_lock_ack = False
        self.core.coins = []
        resumed = BitcoinFundingAdapter(self.core.node, self.core.wallet, configuration())
        raw, txid = resumed.prepare(retained)
        self.assertEqual(txid, retained['expected_txid'])
        resumed.validate(retained, raw, txid)
        self.assertEqual(len([c for c in self.core.calls if c[1] == 'lockunspent']), 1)
        self.assertEqual(self.sends(), [])

    def test_wallet_locked_or_incomplete_keeps_saved_plan_reserved_without_sending(self):
        self.core.plan = self.adapter.plan()
        self.core.failures['signrawtransactionwithwallet'] = ValueError('wallet is locked')
        with self.assertRaises(Exception):
            self.adapter.prepare(self.core.plan)
        self.core.failures.clear()
        self.core.sign_complete = False
        with self.assertRaises(ValueError):
            self.adapter.prepare(self.core.plan)
        self.assertEqual(self.core.locked, {('11' * 32, 1)})
        self.assertEqual(self.sends(), [])

    def test_changed_input_state_or_deadline_blocks_saved_prepare_and_send(self):
        plan, raw, txid = self.core.prepared()
        for field, value in (('other_spent', True), ('input_confirmations', 1), ('height', 400)):
            with self.subTest(field=field):
                old = getattr(self.core, field)
                setattr(self.core, field, value)
                with self.assertRaises(ValueError):
                    self.adapter.prepare(plan)
                with self.assertRaises(ValueError):
                    self.adapter.send(plan, raw, txid)
                setattr(self.core, field, old)
        self.assertEqual(self.sends(), [])

    def test_wrong_wire_or_non_all_signature_is_rejected_before_send(self):
        plan, raw, txid = self.core.prepared()
        for changed in (raw + b'\0', b'\x01' + raw[1:], raw[:-1] + b'\x01'):
            with self.assertRaises(ValueError):
                self.adapter.send(plan, changed, txid)
        self.core.change_signature = True
        with self.assertRaises(ValueError):
            self.adapter.prepare(plan)
        self.assertEqual(self.sends(), [])

    def test_wrong_signature_under_same_pubkey_is_rejected(self):
        plan, raw, txid = self.core.prepared()
        parsed = _parse(raw)
        sig = parsed['witnesses'][0][0]
        r, s = utils.decode_dss_signature(sig[:-1])
        altered = utils.encode_dss_signature(r, s-1 if s > 1 else 2) + b'\x01'
        bad = raw.replace(_compact(len(sig)) + sig, _compact(len(altered)) + altered)
        with self.assertRaisesRegex(ValueError, 'BIP143'):
            self.adapter.validate(plan, bad, txid)

    def test_two_input_signatures_commit_to_each_input_and_all_outputs(self):
        self.core.input['value_sats'] = 60000
        self.core.coins = [dict(self.core.coins[0], amount=Decimal('0.0006'), txid=value * 32)
                           for value in ('22', '11')]
        plan, raw, txid = self.core.prepared()
        self.assertEqual(len(plan['inputs']), 2)
        self.assertEqual([i['txid'] for i in plan['inputs']], ['11' * 32, '22' * 32])
        self.assertEqual(self.adapter.validate(plan, raw, txid)['change_value_sats'], 19000)
        parsed = _parse(raw)
        second = parsed['witnesses'][1][0]
        first = parsed['witnesses'][0][0]
        prefix = raw[:raw.rfind(_compact(len(second)) + second)]
        suffix = raw[raw.rfind(_compact(len(second)) + second) + len(_compact(len(second)) + second):]
        with self.assertRaisesRegex(ValueError, 'BIP143'):
            self.adapter.validate(plan, prefix + _compact(len(first)) + first + suffix, txid)

    def test_exact_no_change_and_dust_change_boundary(self):
        self.core.input['value_sats'] = 101000
        self.core.coins[0]['amount'] = Decimal('0.00101')
        plan, raw, txid = self.core.prepared()
        self.assertEqual(plan['change_value_sats'], 0)
        self.assertEqual(len(_parse(raw)['outputs']), 1)
        self.adapter.validate(plan, raw, txid)
        self.core.locked.clear()
        self.core.input['value_sats'] = 101001
        self.core.coins[0]['amount'] = Decimal('0.00101001')
        with self.assertRaisesRegex(ValueError, 'non-dust'):
            self.adapter.plan()

    def test_high_s_signature_and_changed_payment_are_rejected(self):
        plan, raw, txid = self.core.prepared()
        signature = _parse(raw)['witnesses'][0][0]
        r, s = utils.decode_dss_signature(signature[:-1])
        altered = utils.encode_dss_signature(r, N-s) + b'\x01'
        high_s = raw.replace(_compact(len(signature)) + signature, _compact(len(altered)) + altered)
        with self.assertRaisesRegex(ValueError, 'Noncanonical'):
            self.adapter.validate(plan, high_s, txid)
        output = (100000).to_bytes(8, 'little') + b'\x22' + self.adapter.contract.output_script()
        diverted = raw.replace(output, (99999).to_bytes(8, 'little') + output[8:])
        self.assertNotEqual(diverted, raw)
        with self.assertRaises(ValueError):
            self.adapter.validate(plan, diverted, txid)

    def test_lost_funding_ack_reconciles_and_never_submits_second_artifact(self):
        plan, raw, txid = self.core.prepared()
        self.core.lost_send_ack = True
        with self.assertRaises(Exception):
            self.adapter.send(plan, raw, txid)
        self.assertEqual(self.adapter.receipt(plan, raw, txid)['status'], 'pending')
        self.assertEqual(self.adapter.send(plan, raw, txid), txid)
        self.assertEqual(len(self.sends()), 1)
        self.assertEqual(bytes.fromhex(self.sends()[0][2][0]), raw)

    def test_unknown_funding_and_spent_inputs_never_authorize_new_funding(self):
        plan, raw, txid = self.core.prepared()
        self.core.other_spent = True
        self.assertEqual(self.adapter.receipt(plan, raw, txid)['status'], 'unknown')
        with self.assertRaises(ValueError):
            self.adapter.send(plan, raw, txid)
        self.assertEqual(self.sends(), [])

    def test_fixed_fee_rejection_does_not_estimate_or_bump(self):
        plan, raw, txid = self.core.prepared()
        self.core.admissible = False
        with self.assertRaisesRegex(ValueError, 'fixed fee'):
            self.adapter.send(plan, raw, txid)
        self.assertEqual(self.sends(), [])
        self.assertFalse(any(c[1] in ('estimatesmartfee', 'bumpfee', 'fundrawtransaction', 'walletcreatefundedpsbt') for c in self.core.calls))

    def test_resolution_needs_final_unspent_exact_funding_and_keeps_stable_terms(self):
        plan, raw, txid = self.core.prepared()
        self.adapter.send(plan, raw, txid)
        with self.assertRaises(ValueError):
            self.adapter.resolve(plan, raw, txid)
        self.core.confirmed = True
        resolved = self.adapter.resolve(plan, raw, txid)
        self.assertEqual(resolved['terms'], dict(configuration()['contract'], funding_txid=txid, funding_vout=0))
        self.assertEqual(resolved['receipt']['deadline_remaining'], 100)
        self.assertNotIn('funding_blockhash', resolved['terms'])
        self.core.funding_spent = True
        receipt = self.adapter.receipt(plan, raw, txid)
        self.assertEqual(receipt['status'], 'confirmed')
        self.assertFalse(receipt['funding_unspent'])
        with self.assertRaises(ValueError):
            self.adapter.resolve(plan, raw, txid)

    def test_reorg_and_unavailable_history_withhold_resolution_without_rebinding(self):
        plan, raw, txid = self.core.prepared()
        self.adapter.send(plan, raw, txid)
        self.core.confirmed = True
        self.assertTrue(self.adapter.resolve(plan, raw, txid)['receipt']['final'])
        self.core.orphaned = True
        self.assertEqual(self.adapter.receipt(plan, raw, txid)['status'], 'unknown')
        with self.assertRaises(ValueError):
            self.adapter.resolve(plan, raw, txid)
        self.core.orphaned = False
        self.core.unknown = True
        self.assertEqual(self.adapter.receipt(plan, raw, txid)['status'], 'unknown')
        self.assertEqual(plan['expected_txid'], txid)

    def test_same_stripped_id_other_valid_witness_is_conflict(self):
        plan, raw, txid = self.core.prepared()
        another, same_txid = self.adapter.prepare(plan)
        self.assertEqual(same_txid, txid)
        self.assertNotEqual(another, raw)
        self.core.raw = another
        self.assertEqual(self.adapter.receipt(plan, raw, txid)['status'], 'conflict')
        with self.assertRaises(ValueError):
            self.adapter.send(plan, raw, txid)
        self.assertEqual(self.sends(), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
