"""Bounded, linked native claim/refund discovery with durable caller cursors.

Prefix RPC data only locates candidates. A candidate is returned only after
the complete signed wire is fetched and independently checked by XdsAdapter.
The returned private proof contains public-on-chain raw/witness material and
must be atomically persisted with the cursor in the caller's encrypted store.
Public logs must use only candidate txid/kind, never the proof object.

A cursor cannot skip a partly examined block. Its previous/block hash anchors
are rechecked on every call. Reorganizations request a restart from the current
funding block; authenticated old proofs remain exposure evidence. The supplied
validating daemon is the chain-data trust boundary, as in XdsAdapter.
"""
from copy import deepcopy
import hashlib

from .xds import XdsAdapter, _hex, _integer, _Unavailable, TX_SWAP_FUND, TX_SWAP_SPEND


MAX_PAGE_BLOCKS = 128
MAX_CANDIDATES = 128
MAX_TRANSACTIONS = 16384


def _cursor(value):
    if value is None:
        return None
    if type(value) is not dict or set(value) != {'next_height', 'previous_hash', 'offset', 'block_hash'}:
        raise ValueError('Complete native discovery cursor required')
    result = dict(value)
    _integer(result['next_height'], 0, 2**32 - 1, 'cursor height')
    _integer(result['offset'], 0, MAX_TRANSACTIONS, 'cursor offset')
    _hex(result['previous_hash'], 32, 'cursor previous block')
    if result['offset']:
        _hex(result['block_hash'], 32, 'cursor partial block')
    elif result['block_hash'] is not None:
        raise ValueError('Complete-block cursor cannot carry a partial block hash')
    return result


class XdsWitnessDiscovery:
    def __init__(self, rpc, terms):
        self.adapter = XdsAdapter(rpc, terms)

    def _entry(self, entry):
        if type(entry) is not dict or entry.get('coinbase') is not False or type(entry.get('transaction')) is not dict:
            raise _Unavailable('Malformed native discovery transaction prefix')
        txid = _hex(entry.get('hash'), 32, 'candidate transaction').hex()
        prefix = entry['transaction']
        family = _integer(prefix.get('tx_type'), 0, TX_SWAP_FUND, 'candidate family')
        if family != TX_SWAP_SPEND:
            return None
        vin = prefix.get('vin')
        if (type(vin) is not list or len(vin) != 1 or type(vin[0]) is not dict
                or vin[0].get('type') != '20' or type(vin[0].get('value')) is not dict):
            raise _Unavailable('Malformed native swap candidate input')
        item = vin[0]['value']
        previous = _hex(item.get('prev_txid'), 32, 'candidate funding').hex()
        index = _integer(item.get('prev_out_index'), 0, 2**32 - 1, 'candidate output')
        branch = _integer(item.get('branch'), 1, 2, 'candidate branch')
        c = self.adapter.contract
        if previous != c.funding_txid or index != c.funding_vout:
            return None
        return txid, 'xds-claim' if branch == 1 else 'xds-refund'

    def _proof(self, candidate):
        txid, kind = candidate
        proof = self.adapter.verify_public_spend(txid, kind)
        if not isinstance(proof, dict) or 'raw' not in proof or (kind == 'xds-claim' and 'secret' not in proof):
            raise _Unavailable('Native candidate full signed wire is unavailable or invalid')
        # The verification function retains valid public witnesses even when
        # current receipt metadata is unknown after a reorg or fork warning.
        proof = dict(proof, acquisition=dict(source='xds-witness-discovery-v1', full_wire_fetched=True,
            txid=txid, raw_sha256=hashlib.sha256(bytes.fromhex(proof['raw'])).hexdigest()))
        return dict(txid=txid, kind=kind, proof=proof)

    def scan(self, cursor=None, max_blocks=32, max_candidates=32):
        original = _cursor(cursor)
        _integer(max_blocks, 1, MAX_PAGE_BLOCKS, 'native discovery block budget')
        _integer(max_candidates, 1, MAX_CANDIDATES, 'native discovery candidate budget')
        candidates, seen = [], set()
        base = dict(status='unknown', cursor=deepcopy(original), candidates=candidates,
                    caught_up=False, height=None, tip_hash=None)
        try:
            a = self.adapter
            # Mempool witnesses have priority. A chain outage must not erase a
            # valid public witness already fetched from the selected daemon.
            pool = a._call('getrawtransactionspool', {})
            if type(pool) is not dict or pool.get('status') != 'OK' or type(pool.get('transactions')) is not list:
                raise _Unavailable('Native discovery pool unavailable')
            if len(pool['transactions']) > MAX_TRANSACTIONS:
                raise _Unavailable('Native discovery pool exceeds bounded profile')
            for entry in pool['transactions']:
                candidate = self._entry(entry)
                if candidate is not None and candidate[0] not in seen:
                    if len(candidates) == max_candidates:
                        return dict(base, status='limited')
                    candidates.append(self._proof(candidate))
                    seen.add(candidate[0])

            snapshot = a._info()
            funding = a._funding(snapshot)
            floor = funding['block_height']
            current = deepcopy(original)
            if current is not None and not floor <= current['next_height'] <= snapshot[0]:
                return dict(base, status='reorg', cursor=None, height=snapshot[0], tip_hash=snapshot[1])
            next_height = current['next_height'] if current else floor
            start = next_height - 1 if next_height > floor else floor
            count = max_blocks + (start < next_height)
            page = a._call('get_wallet_sync_data', dict(start_height=start, block_count=count, include_miner_txs=False))
            expected = min(count, snapshot[0] - start)
            if (type(page) is not dict or page.get('status') != 'OK' or type(page.get('top_height')) is not int
                    or page['top_height'] != snapshot[0] - 1 or type(page.get('blocks')) is not list
                    or len(page['blocks']) != expected):
                raise _Unavailable('Incomplete native discovery page')
            blocks, previous = page['blocks'], None
            for index, block in enumerate(blocks):
                if type(block) is not dict or type(block.get('height')) is not int or block['height'] != start + index:
                    raise _Unavailable('Native discovery page skipped a height')
                block_hash = _hex(block.get('hash'), 32, 'discovery block').hex()
                parent_hash = _hex(block.get('previous_hash'), 32, 'discovery parent').hex()
                if previous is not None and parent_hash != previous:
                    raise _Unavailable('Native discovery page is not linked')
                previous = block_hash
                if type(block.get('transactions')) is not list or len(block['transactions']) > MAX_TRANSACTIONS:
                    raise _Unavailable('Native discovery block exceeds bounded profile')
            if not blocks:
                raise _Unavailable('Native funding block unavailable')
            if blocks[-1]['height'] == snapshot[0] - 1 and blocks[-1]['hash'] != snapshot[1]:
                raise _Unavailable('Native discovery page tip differs from its snapshot')
            if next_height == floor and blocks[0]['hash'] != funding['block_hash']:
                raise _Unavailable('Native discovery funding anchor differs')
            if current is None:
                current = dict(next_height=floor, previous_hash=blocks[0]['previous_hash'], offset=0, block_hash=None)
            elif start < next_height:
                if blocks[0]['hash'] != current['previous_hash']:
                    return dict(base, status='reorg', cursor=None, height=snapshot[0], tip_hash=snapshot[1])
                blocks = blocks[1:]
            elif blocks[0]['previous_hash'] != current['previous_hash']:
                return dict(base, status='reorg', cursor=None, height=snapshot[0], tip_hash=snapshot[1])
            if blocks and current['offset'] and blocks[0]['hash'] != current['block_hash']:
                return dict(base, status='reorg', cursor=None, height=snapshot[0], tip_hash=snapshot[1])
            a._stable(snapshot)

            limited = False
            for block in blocks:
                transactions = block['transactions']
                offset = current['offset']
                if offset > len(transactions):
                    raise _Unavailable('Native partial cursor exceeds its block')
                for index in range(offset, len(transactions)):
                    candidate = self._entry(transactions[index])
                    if candidate is not None and candidate[0] not in seen:
                        if len(candidates) == max_candidates:
                            # offset zero has no partial hash; previous_hash
                            # still anchors the preceding block on the retry.
                            current = dict(next_height=block['height'], previous_hash=block['previous_hash'],
                                           offset=index, block_hash=block['hash'] if index else None)
                            limited = True
                            break
                        candidates.append(self._proof(candidate))
                        seen.add(candidate[0])
                if limited:
                    break
                current = dict(next_height=block['height'] + 1, previous_hash=block['hash'], offset=0, block_hash=None)
            a._stable(snapshot)
            return dict(base, status='limited' if limited else 'ok', cursor=current,
                        caught_up=not limited and current['next_height'] == snapshot[0],
                        height=snapshot[0], tip_hash=snapshot[1])
        except (_Unavailable, ValueError, TypeError, AttributeError):
            # Preserve separately authenticated witnesses, never uncertain cursor
            # progress or transport text which could contain credentials.
            return base
