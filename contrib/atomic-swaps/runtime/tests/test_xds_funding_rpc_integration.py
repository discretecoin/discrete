"""Opt-in real native funding/discovery, synthetic private four-node network.

XDS_FUNDING_RPC_INTEGRATION=1 and SWAP_BUILD_DIR are required. The process
fixture supplies treasury/roles/clocks only. New funding and discovery use the
actual runtime adapters; this does not qualify the separate lifecycle journal.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from swap_runtime.rpc import LocalRpc
from swap_runtime.xds import XdsAdapter, _Unavailable
from swap_runtime.xds_funding import XdsFundingAdapter
from swap_runtime.xds_discovery import XdsWitnessDiscovery
import test_xds_rpc_integration as native_fixture


def reopen_child():
    request = json.loads(sys.stdin.buffer.read())
    daemon = LocalRpc(request['endpoint']).daemon
    def readonly(method, params):
        if method == 'sendrawtransaction':
            raise AssertionError('Known pending funding must not transmit again')
        return daemon(method, params)
    adapter = XdsFundingAdapter(readonly, request['terms'])
    raw, txid = bytes.fromhex(request['raw']), request['txid']
    if adapter.send(raw, txid) != txid:
        raise AssertionError('Funding identity changed during recovery')
    result = adapter.resolve(raw, txid)
    if result['receipt']['status'] != 'pending' or not result['receipt']['publicly_observed']:
        raise AssertionError('Exact native funding was not observed')
    print(json.dumps(dict(txid=txid, payload_sha256=hashlib.sha256(raw).hexdigest(),
                         status=result['receipt']['status'], funding_vout=result['terms']['funding_vout'])))


@unittest.skipUnless(os.environ.get('XDS_FUNDING_RPC_INTEGRATION') == '1', 'owned native funding integration is opt-in')
class XdsFundingRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_fixture.XdsRpcIntegration.setUpClass()
        cls.native = native_fixture.XdsRpcIntegration('runTest')

    @classmethod
    def tearDownClass(cls):
        native_fixture.XdsRpcIntegration.tearDownClass()

    def transports(self):
        x = self.native.x
        daemon = LocalRpc('http://127.0.0.1:' + str(x.n.rpc)).daemon
        alice = LocalRpc('http://127.0.0.1:' + str(x.alice.rpc), x.alice.auth).wallet
        bob = LocalRpc('http://127.0.0.1:' + str(x.bob.rpc), x.bob.auth).wallet
        return daemon, alice, bob

    def funding(self, contract, rpc=None):
        daemon, alice, _ = self.transports()
        c, values = contract, contract['terms']
        terms = dict(genesis_hash=values['genesis_hash'], hashlock=values['hashlock'], nonce=values['nonce'],
            claim_commitment=c['b']['commitment'], refund_commitment=c['a']['commitment'],
            claim_address=c['b']['address'], refund_address=c['a']['address'], refund_height=values['refund_height'],
            funding_value_atoms=1001, net_amount_atoms=1000, fee_atoms=1, min_confirmations=11)
        return XdsFundingAdapter(rpc or daemon, terms, alice)

    def test_01_native_prepare_source_signatures_lost_ack_child_discovery_and_ordinary_payout(self):
        x = self.native.x
        daemon, _, bob = self.transports()
        x.alice.synced(); x.bob.synced()
        before = x.bob.balance()
        contract = x.contract(delay=80)
        sends = []
        def lost_ack(method, params):
            response = daemon(method, params)
            if method == 'sendrawtransaction':
                sends.append(params['tx_as_hex'])
                raise TimeoutError('Owned funding accepted; acknowledgment deliberately dropped')
            return response
        adapter = self.funding(contract, lost_ack)
        raw, txid = adapter.prepare(contract['rho_a'])
        checked = adapter.validate(raw, txid)
        self.assertTrue(checked['inputs_unspent'])
        self.assertEqual((checked['funding_fee_atoms'], checked['exit_fee_atoms'], checked['net_amount_atoms']), (1, 1, 1000))
        self.assertEqual(sends, [])
        with self.assertRaises(_Unavailable):
            adapter.send(raw, txid)
        self.assertEqual(sends, [raw.hex()])
        request = dict(endpoint='http://127.0.0.1:' + str(x.n.rpc), terms=adapter.plan(), raw=raw.hex(), txid=txid)
        child = subprocess.run([sys.executable, '-B', __file__, '--reopen-child'], input=json.dumps(request).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        restored = json.loads(child.stdout)
        self.assertEqual(restored['payload_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(restored['txid'], txid)
        self.assertEqual(restored['status'], 'pending')
        x.mine(11)
        resolved = adapter.resolve(raw, txid)
        self.assertTrue(resolved['receipt']['final'])
        self.assertEqual(resolved['terms']['funding_wire'], raw.hex())
        settlement = XdsAdapter(daemon, resolved['terms'], bob)
        discovery = XdsWitnessDiscovery(daemon, resolved['terms'])
        before_claim = discovery.scan(max_blocks=4)
        self.assertEqual(before_claim['status'], 'ok')
        self.assertEqual(before_claim['candidates'], [])
        claim_raw, claim_id = settlement.prepare('xds-claim', contract['rho_b'], contract['secret'])
        settlement.send('xds-claim', claim_raw, claim_id)
        public = discovery.scan(before_claim['cursor'])
        self.assertEqual(public['status'], 'ok')
        self.assertEqual(public['candidates'][0]['txid'], claim_id)
        self.assertEqual(public['candidates'][0]['proof']['raw'], claim_raw.hex())
        self.assertEqual(public['candidates'][0]['proof']['secret'], contract['secret'].hex())
        self.assertEqual(public['candidates'][0]['proof']['status'], 'pending')
        x.mine(11)
        included = discovery.scan(public['cursor'])
        self.assertTrue(included['caught_up'])
        self.assertEqual(included['candidates'][0]['txid'], claim_id)
        self.assertTrue(included['candidates'][0]['proof']['final'])
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'new funding claimed payout scanned', 60)
        ordinary = x.bob.call('transfer', dict(destinations=[dict(address=contract['a']['address'], amount=900)],
                             fee=1, unlock_height=0, payment_id='', extra=''))
        x.mine()
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 99, 'new funding ordinary change scanned', 60)
        self.assertTrue(x.n.outpoint(ordinary['tx_hash'])['in_chain'])

    def test_02_abandoned_new_funding_refund_and_competing_input_interference(self):
        x = self.native.x
        daemon, alice, _ = self.transports()
        x.alice.synced()
        before = x.alice.balance()
        contract, competing = x.contract(delay=24), x.contract(delay=24)
        adapter, rival = self.funding(contract), self.funding(competing)
        raw, txid = adapter.prepare(contract['rho_a'])
        other_raw, other_id = rival.prepare(competing['rho_a'])
        self.assertEqual(adapter.validate(raw, txid)['selected_inputs'][0]['reservation_key'],
                         rival.validate(other_raw, other_id)['selected_inputs'][0]['reservation_key'])
        adapter.send(raw, txid)
        transmissions = []
        def count_send(method, params):
            if method == 'sendrawtransaction':
                transmissions.append(params)
            return daemon(method, params)
        blocked = XdsFundingAdapter(count_send, rival.plan())
        with self.assertRaises(_Unavailable):
            blocked.send(other_raw, other_id)
        self.assertEqual(transmissions, [])
        x.mine(11)
        resolved = adapter.resolve(raw, txid)
        settlement = XdsAdapter(daemon, resolved['terms'], alice)
        with self.assertRaises(_Unavailable):
            settlement.prepare('xds-refund', contract['rho_a'])
        x.mine(contract['terms']['refund_height'] - x.n.info()['height'])
        refund_raw, refund_id = settlement.prepare('xds-refund', contract['rho_a'])
        settlement.send('xds-refund', refund_raw, refund_id)
        x.mine(11)
        found = XdsWitnessDiscovery(daemon, resolved['terms']).scan()
        self.assertEqual(found['status'], 'ok')
        self.assertEqual(found['candidates'][0]['txid'], refund_id)
        self.assertNotIn('secret', found['candidates'][0]['proof'])
        self.assertTrue(found['candidates'][0]['proof']['final'])
        self.native.lab.wait_for(lambda: x.alice.balance() == before - 2, 'new funding refund net fees scanned', 60)


if __name__ == '__main__':
    if '--reopen-child' in sys.argv:
        reopen_child()
    else:
        unittest.main(verbosity=2)
