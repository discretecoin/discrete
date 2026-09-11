import copy
import hashlib
import unittest

from swap_runtime.xds import _h
from swap_runtime.xds_discovery import XdsWitnessDiscovery
from test_xds import Fixture


class DiscoveryFixture:
    def __init__(self):
        self.f = Fixture()
        self.blocks = [dict(height=n, hash=_h(str(n).encode()).hex(), previous_hash=_h(str(n - 1).encode()).hex(),
                            timestamp=n, transactions=[]) for n in range(self.f.height)]
        self.pool, self.calls = [], []
        self.page_patch = None
        self.discovery = XdsWitnessDiscovery(self.rpc, self.f.terms)

    def entry(self, raw, txid, kind='xds-claim'):
        return dict(hash=txid, coinbase=False, transaction=dict(tx_type=5, vin=[dict(type='20', value=dict(
            prev_txid=self.f.terms['funding_txid'], prev_out_index=0, branch=1 if kind == 'xds-claim' else 2))]))

    def add(self, block=None, kind='xds-claim'):
        raw, txid = self.f.wire(kind)
        self.f.entries[txid] = (raw, block)
        (self.pool if block is None else self.blocks[block]['transactions']).append(self.entry(raw, txid, kind))
        return raw, txid

    def rpc(self, method, params):
        self.calls.append((method, dict(params)))
        if method == 'getrawtransactionspool':
            return dict(status='OK', transactions=copy.deepcopy(self.pool))
        if method == 'get_wallet_sync_data':
            start, count = params['start_height'], params['block_count']
            response = dict(status='OK', top_height=self.f.height - 1, blocks=copy.deepcopy(self.blocks[start:start + count]))
            if self.page_patch:
                self.page_patch(response)
            return response
        response = self.f.rpc(method, params)
        if method == 'getinfo':
            response['top_block_hash'] = self.blocks[-1]['hash']
        if method == 'get_swap_outpoint':
            response['tip_hash'] = self.blocks[-1]['hash']
        return response


class XdsDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = DiscoveryFixture()
        self.d = self.f.discovery

    def test_new_funding_and_pq_v2_prefixes_do_not_block_claim_discovery(self):
        for family in (1, 4, 6):
            self.f.pool.append(dict(hash=bytes([family] * 32).hex(), coinbase=False,
                                   transaction=dict(tx_type=family, vin=[])))
            self.f.blocks[11]['transactions'].append(copy.deepcopy(self.f.pool[-1]))
        raw, txid = self.f.add(15)
        result = self.d.scan(max_blocks=32)
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(result['caught_up'])
        self.assertEqual([item['txid'] for item in result['candidates']], [txid])
        self.assertEqual(result['candidates'][0]['proof']['raw'], raw.hex())

    def test_bounded_linked_pages_find_full_signed_claim_and_finish_at_tip(self):
        raw, txid = self.f.add(15)
        first = self.d.scan(max_blocks=4)
        self.assertEqual(first['status'], 'ok')
        self.assertEqual(first['cursor']['next_height'], 14)
        self.assertFalse(first['caught_up'])
        second = self.d.scan(first['cursor'], max_blocks=16)
        self.assertTrue(second['caught_up'])
        self.assertEqual(second['candidates'][0]['txid'], txid)
        self.assertEqual(second['candidates'][0]['proof']['raw'], raw.hex())
        self.assertEqual(second['candidates'][0]['proof']['secret'], self.f.f.secret.hex())
        self.assertEqual(second['candidates'][0]['proof']['acquisition'],
            dict(source='xds-witness-discovery-v1', full_wire_fetched=True, txid=txid,
                 raw_sha256=hashlib.sha256(raw).hexdigest()))
        third = self.d.scan(second['cursor'])
        self.assertTrue(third['caught_up'])
        self.assertEqual(third['candidates'], [])

    def test_mempool_secret_survives_current_chain_warning_without_cursor_advance(self):
        _, txid = self.f.add()
        self.f.f.info_patch = {'finality_fork_warning': True}
        result = self.d.scan()
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['cursor'])
        self.assertEqual(result['candidates'][0]['txid'], txid)
        self.assertEqual(result['candidates'][0]['proof']['secret'], self.f.f.secret.hex())
        self.assertEqual(result['candidates'][0]['proof']['status'], 'unknown')
        self.assertTrue(result['candidates'][0]['proof']['acquisition']['full_wire_fetched'])

    def test_prefix_secret_without_valid_signed_wire_never_becomes_proof(self):
        raw, txid = self.f.add()
        self.f.f.entries.clear()
        result = self.d.scan()
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['candidates'], [])
        bad = raw[:-1] + bytes([raw[-1] ^ 1])
        identity = _h(bad).hex()
        self.f.f.entries[identity] = (bad, None)
        self.f.pool = [self.f.entry(bad, identity)]
        self.assertEqual(self.d.scan()['candidates'], [])

    def test_unrelated_outpoint_is_filtered_before_full_wire_lookup(self):
        _, txid = self.f.add()
        self.f.pool[0]['transaction']['vin'][0]['value']['prev_txid'] = '44' * 32
        result = self.d.scan()
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['candidates'], [])
        self.assertFalse(any(method == 'get_swap_outpoint' and params['txid'] == txid for method, params in self.f.calls))

    def test_candidate_budget_persists_exact_partial_block_offset(self):
        first = self.f.add(15)
        second = self.f.add(15)
        self.assertNotEqual(first[1], second[1])
        result = self.d.scan(max_candidates=1)
        self.assertEqual(result['status'], 'limited')
        self.assertEqual(result['cursor']['next_height'], 15)
        self.assertEqual(result['cursor']['offset'], 1)
        self.assertEqual(result['cursor']['block_hash'], self.f.blocks[15]['hash'])
        resumed = self.d.scan(result['cursor'], max_candidates=1)
        self.assertEqual(resumed['status'], 'ok')
        self.assertEqual(resumed['candidates'][0]['txid'], second[1])
        self.assertTrue(resumed['caught_up'])

    def test_reorg_at_previous_anchor_or_partial_block_requires_full_rewind(self):
        first = self.d.scan(max_blocks=4)
        self.f.blocks[13]['hash'] = '99' * 32
        self.f.blocks[14]['previous_hash'] = '99' * 32
        result = self.d.scan(first['cursor'])
        self.assertEqual(result['status'], 'reorg')
        self.assertIsNone(result['cursor'])
        self.f = DiscoveryFixture()
        self.d = self.f.discovery
        self.f.add(15); self.f.add(15)
        first = self.d.scan(max_candidates=1)
        self.f.blocks[15]['hash'] = '99' * 32
        self.f.blocks[16]['previous_hash'] = '99' * 32
        result = self.d.scan(first['cursor'])
        self.assertEqual(result['status'], 'reorg')
        self.assertIsNone(result['cursor'])

    def test_gapped_unlinked_truncated_wrong_tip_pages_never_advance(self):
        first = self.d.scan(max_blocks=4)
        def gap(page):
            page['blocks'][2]['height'] += 1
        def unlinked(page):
            page['blocks'][2]['previous_hash'] = '44' * 32
        def truncated(page):
            page['blocks'].pop()
        def wrong_tip(page):
            page['blocks'][-1]['hash'] = '44' * 32
        for mutate in (gap, unlinked, truncated, wrong_tip):
            self.f.page_patch = mutate
            result = self.d.scan(first['cursor'])
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(result['cursor'], first['cursor'])

    def test_unknown_full_candidate_does_not_skip_block(self):
        _, txid = self.f.add(15)
        first = self.d.scan(max_blocks=4)
        self.f.f.entries.clear()
        result = self.d.scan(first['cursor'])
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['cursor'], first['cursor'])
        self.assertEqual(result['candidates'], [])

    def test_refund_candidate_has_valid_wire_and_no_secret(self):
        _, txid = self.f.add(15, kind='xds-refund')
        result = self.d.scan()
        self.assertEqual(result['candidates'][0]['txid'], txid)
        self.assertEqual(result['candidates'][0]['kind'], 'xds-refund')
        self.assertNotIn('secret', result['candidates'][0]['proof'])

    def test_invalid_cursor_or_unbounded_budget_rejected_before_rpc(self):
        for cursor in ({}, {'next_height': True, 'previous_hash': '00' * 32, 'offset': 0, 'block_hash': None},
                       {'next_height': 15, 'previous_hash': '00' * 32, 'offset': 1, 'block_hash': None}):
            with self.assertRaises(ValueError):
                self.d.scan(cursor)
        for values in ({'max_blocks': 0}, {'max_blocks': 129}, {'max_candidates': 129}, {'max_candidates': True}):
            with self.assertRaises(ValueError):
                self.d.scan(**values)
        self.assertEqual(self.f.calls, [])

    def test_oversized_pool_and_malformed_prefix_do_not_advance_or_leak(self):
        self.f.pool = [{}] * 16385
        self.assertEqual(self.d.scan()['status'], 'unknown')
        self.f.pool = [dict(hash='private-password', coinbase=False, transaction={})]
        result = self.d.scan()
        self.assertEqual(result['status'], 'unknown')
        self.assertNotIn('private-password', str(result))


if __name__ == '__main__':
    unittest.main()
