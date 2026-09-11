"""Opt-in funding lifecycle on owned Bitcoin Core regtest only.

BITCOIND selects the existing local binary; BITCOIN_TEST_DATA retains evidence.
The helper binds loopback, disables peers/discovery and stops its node on exit.
"""
import json
import os
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from swap_runtime.bitcoin import BitcoinAdapter, pubkey, sha
from swap_runtime.bitcoin_funding import BitcoinFundingAdapter
from test_bitcoin_funding import script
from test_bitcoin_rpc_integration import RegtestNode


BITCOIND = os.environ.get('BITCOIND')


@unittest.skipUnless(BITCOIND and Path(BITCOIND).is_file(), 'set BITCOIND for owned funding regtest')
class BitcoinFundingRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = RegtestNode()
        try:
            cls.node.rpc('createwallet', ['swaps-runtime'])
            cls.node.mine(120)
            cls.claim_key = ec.derive_private_key(8821, ec.SECP256K1())
            cls.refund_key = ec.derive_private_key(8822, ec.SECP256K1())
        except BaseException:
            cls.node.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def terms(self, delay=30):
        n = self.node
        change_address = n.rpc('getrawchangeaddress', ['bech32'], wallet=True)
        contract = {'genesis_hash': n.rpc('getblockhash', [0]), 'hashlock': sha(b'f' * 32).hex(),
                    'claim_pubkey': pubkey(self.claim_key).hex(), 'refund_pubkey': pubkey(self.refund_key).hex(),
                    'refund_height': n.rpc('getblockcount', []) + delay, 'funding_value_sats': 100000,
                    # These payout keys are distinct from sender-wallet inputs,
                    # change, and both settlement authorization keys.
                    'claim_script': script(ec.derive_private_key(8831, ec.SECP256K1())),
                    'refund_script': script(ec.derive_private_key(8832, ec.SECP256K1())),
                    'fee_sats': 1000, 'min_confirmations': 2}
        return {'contract': contract, 'funding_fee_sats': 1000, 'change_address': change_address,
                'change_script': n.rpc('getaddressinfo', [change_address], wallet=True)['scriptPubKey'],
                'min_input_confirmations': 2}

    def adapter(self, terms, node_rpc=None, wallet_rpc=None):
        return BitcoinFundingAdapter(node_rpc or self.node.rpc,
            wallet_rpc or (lambda method, params: self.node.rpc(method, params, wallet=True)), terms)

    def test_saved_plan_lock_crash_restart_and_confirmed_claim(self):
        terms = self.terms()
        adapter = self.adapter(terms)
        plan = adapter.plan()
        saved = self.node.path / 'durable-plan-before-lock.json'
        saved.write_text(json.dumps(plan, sort_keys=True), encoding='utf-8')
        def crash_at_sign(method, params):
            if method == 'signrawtransactionwithwallet':
                raise TimeoutError('fixture interruption after persistent input locks')
            return self.node.rpc(method, params, wallet=True)
        with self.assertRaises(Exception):
            self.adapter(terms, wallet_rpc=crash_at_sign).prepare(plan)
        wanted = {(i['txid'], i['vout']) for i in plan['inputs']}
        self.node.stop()
        self.node.start()
        if 'swaps-runtime' not in self.node.rpc('listwallets', []):
            self.node.rpc('loadwallet', ['swaps-runtime'])
        actual = {(i['txid'], i['vout']) for i in self.node.rpc('listlockunspent', [], wallet=True)}
        self.assertTrue(wanted <= actual)
        retained = json.loads(saved.read_text(encoding='utf-8'))
        def no_selection(method, params):
            if method == 'listunspent':
                self.fail('Restart must not select another funding input set')
            return self.node.rpc(method, params, wallet=True)
        resumed = self.adapter(terms, wallet_rpc=no_selection)
        raw, txid = resumed.prepare(retained)
        artifact = self.node.path / 'durable-signed-before-send.bin'
        artifact.write_bytes(raw)
        self.assertEqual(txid, plan['expected_txid'])
        self.assertEqual(resumed.validate(plan, raw, txid)['fee_sats'], 1000)
        self.assertTrue(self.node.rpc('testmempoolaccept', [[raw.hex()]])[0]['allowed'])
        self.assertEqual(resumed.receipt(plan, raw, txid)['status'], 'unknown')
        resumed.send(plan, artifact.read_bytes(), txid)
        self.node.mine(2)
        resolved = resumed.resolve(plan, raw, txid)
        self.assertEqual(resolved['terms']['funding_txid'], txid)
        self.assertEqual(resolved['terms']['funding_vout'], 0)
        self.assertNotIn('funding_blockhash', resolved['terms'])
        settlement = BitcoinAdapter(self.node.rpc, resolved['terms'])
        claim, claim_id = settlement.prepare('foreign-claim', self.claim_key, b'f' * 32)
        self.assertTrue(self.node.rpc('testmempoolaccept', [[claim.hex()]])[0]['allowed'])
        settlement.send('foreign-claim', claim, claim_id)
        self.node.mine(2)
        self.assertTrue(settlement.receipt('foreign-claim', claim, claim_id)['final'])
        self.assertFalse(resumed.receipt(plan, raw, txid)['funding_unspent'])
        with self.assertRaises(ValueError):
            resumed.resolve(plan, raw, txid)

    def test_lost_ack_exact_retry_and_funding_reorg_preserve_outpoint(self):
        terms = self.terms()
        adapter = self.adapter(terms)
        plan = adapter.plan()
        raw, txid = adapter.prepare(plan)
        submitted = []
        def lose_ack(method, params):
            result = self.node.rpc(method, params)
            if method == 'sendrawtransaction':
                submitted.append(bytes.fromhex(params[0]))
                raise TimeoutError('fixture lost funding acknowledgment')
            return result
        with self.assertRaises(Exception):
            self.adapter(terms, node_rpc=lose_ack).send(plan, raw, txid)
        self.assertEqual(submitted, [raw])
        self.assertEqual(adapter.receipt(plan, raw, txid)['status'], 'pending')
        self.assertEqual(self.adapter(terms, node_rpc=lose_ack).send(plan, raw, txid), txid)
        self.assertEqual(submitted, [raw])
        blocks = self.node.mine(2)
        before = adapter.resolve(plan, raw, txid)['terms']
        self.node.rpc('invalidateblock', [blocks[0]])
        self.assertEqual(adapter.receipt(plan, raw, txid)['status'], 'pending')
        with self.assertRaises(ValueError):
            adapter.resolve(plan, raw, txid)
        self.node.mine(2)
        self.assertEqual(adapter.resolve(plan, raw, txid)['terms'], before)

    def test_native_funding_then_mature_refund_keeps_independent_payout(self):
        terms = self.terms(delay=5)
        adapter = self.adapter(terms)
        plan = adapter.plan()
        raw, txid = adapter.prepare(plan)
        adapter.send(plan, raw, txid)
        self.node.mine(2)
        resolved = adapter.resolve(plan, raw, txid)
        settlement = BitcoinAdapter(self.node.rpc, resolved['terms'])
        refund, refund_id = settlement.prepare('foreign-refund', self.refund_key)
        self.assertFalse(self.node.rpc('testmempoolaccept', [[refund.hex()]])[0]['allowed'])
        self.node.mine(terms['contract']['refund_height'] - self.node.rpc('getblockcount', []))
        self.assertTrue(self.node.rpc('testmempoolaccept', [[refund.hex()]])[0]['allowed'])
        settlement.send('foreign-refund', refund, refund_id)
        self.node.mine(2)
        output = self.node.rpc('gettxout', [refund_id, 0])
        self.assertEqual(output['scriptPubKey']['hex'], terms['contract']['refund_script'])
        self.assertTrue(settlement.receipt('foreign-refund', refund, refund_id)['final'])
        self.assertEqual(adapter.receipt(plan, raw, txid)['status'], 'confirmed')

    def test_saved_unsigned_plan_cannot_fund_after_its_refund_height(self):
        terms = self.terms(delay=2)
        adapter = self.adapter(terms)
        plan = adapter.plan()
        raw, txid = adapter.prepare(plan)
        self.node.mine(2)
        with self.assertRaisesRegex(ValueError, 'refund height'):
            adapter.prepare(plan)
        with self.assertRaisesRegex(ValueError, 'refund height'):
            adapter.send(plan, raw, txid)
        receipt = adapter.receipt(plan, raw, txid)
        self.assertEqual(receipt['status'], 'unknown')
        self.assertEqual(receipt['deadline_remaining'], 0)
        with self.assertRaises(Exception):
            self.node.rpc('getrawtransaction', [txid])

    def test_multiple_native_wallet_inputs_are_independently_valid_and_accepted(self):
        terms = self.terms()
        # Synthetic regtest coinbase outputs are 50 BTC; this requires more than
        # one input and exercises each independent BIP143 signature against Core.
        terms['contract']['funding_value_sats'] = 60 * 100000000
        adapter = self.adapter(terms)
        plan = adapter.plan()
        self.assertGreater(len(plan['inputs']), 1)
        raw, txid = adapter.prepare(plan)
        self.assertEqual(adapter.validate(plan, raw, txid)['fee_sats'], 1000)
        self.assertTrue(self.node.rpc('testmempoolaccept', [[raw.hex()]])[0]['allowed'])
        adapter.send(plan, raw, txid)
        self.node.mine(2)
        self.assertEqual(adapter.resolve(plan, raw, txid)['terms']['funding_value_sats'], 60 * 100000000)


if __name__ == '__main__':
    unittest.main(verbosity=2)
