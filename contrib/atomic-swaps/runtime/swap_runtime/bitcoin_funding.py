"""Native wallet funding with a durable, explicit coin plan and fixed satoshi fee.

BitcoinFundingAdapter(node_rpc, wallet_rpc, terms) accepts separate authenticated
RPC callables. ``terms`` has exactly contract, funding_fee_sats, change_address,
change_script, min_input_confirmations. The contract is the settlement adapter's
immutable terms without funding_txid, funding_vout or funding_blockhash. Change
must be an explicit wallet-owned native P2WPKH script; settlement role keys and
payouts stay independently pinned. This first profile spends 1..8 native P2WPKH
inputs, producing HTLC output 0 and optional change output 1, with no RBF.

plan() only observes/selects. Its canonical JSON must be durably persisted BEFORE
prepare(plan), which persistently locks only those inputs and asks the wallet to
sign locally constructed bytes. Persist the exact signed artifact BEFORE send.
Never call plan again after uncertainty or recover a missing plan from absence
of RPC history. Wallet locks exclude automatic selection, not manual external
spending; durable application ownership is the caller's responsibility. No
automatic unlock, reselection, fee increase, or replacement is provided.

validate(plan, raw, txid) independently verifies every native BIP143 signature,
the stable stripped ID, fee, exact inputs and outputs. receipt returns current
confirmed/pending/unknown/conflict status, separately reporting funding_unspent.
resolve emits {terms, receipt} only for confirmed, sufficiently deep, unspent
funding. Reorgs alter eligibility, never the agreed txid/vout or payout terms.
deadline_remaining is measured in this chain's blocks; the owner coordinator
must enforce its explicit funding reserve immediately before sending. This
adapter additionally refuses preparation/send at or beyond the refund height.
RPC observations trust the selected validating nodes; use txindex=1 for lookup.
"""

from decimal import Decimal
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .bitcoin import (BitcoinAdapter, Contract, MAX_MONEY, N, _Unavailable,
                      _compact, _hex, _integer, _parse, _u32, _u64, dsha, sha)
from .common import canonical


MAX_INPUTS = 8
MAX_COINS = 1000
SEQUENCE = 0xfffffffe


def _sats(value):
    if not isinstance(value, (str, Decimal, int)) or isinstance(value, bool):
        raise ValueError('RPC amount must be an exact decimal')
    result = Decimal(value) * 100_000_000
    if not result.is_finite() or result != result.to_integral_value() or not 0 <= result <= MAX_MONEY:
        raise ValueError('RPC amount is not bounded satoshi value')
    return int(result)


def _p2wpkh(value):
    raw = _hex(value, 22, 'native P2WPKH script')
    if raw[:2] != b'\x00\x14':
        raise ValueError('Native P2WPKH wallet input/change required')
    return raw


def _outpoint(item):
    return bytes.fromhex(item['txid'])[::-1] + _u32(item['vout'])


class BitcoinFundingAdapter:
    def __init__(self, node_rpc, wallet_rpc, terms):
        fields = {'contract', 'funding_fee_sats', 'change_address', 'change_script', 'min_input_confirmations'}
        if not callable(node_rpc) or not callable(wallet_rpc) or type(terms) is not dict or set(terms) != fields:
            raise ValueError('Exact native funding configuration and RPC callables required')
        self._terms = json.loads(canonical(terms))
        contract = self._terms['contract']
        if type(contract) is not dict or set(contract) != set(Contract.__dataclass_fields__) - {
                'funding_txid', 'funding_vout', 'funding_blockhash'}:
            raise ValueError('Unfunded settlement contract required')
        self.contract = Contract.parse(dict(contract, funding_txid='00' * 32, funding_vout=0))
        self.fee = _integer(self.terms['funding_fee_sats'], 1, MAX_MONEY - self.contract.funding_value_sats, 'funding fee')
        self.minimum = _integer(self.terms['min_input_confirmations'], 1, 1_000_000, 'input confirmations')
        self.change = _p2wpkh(self.terms['change_script'])
        address = self.terms['change_address']
        if type(address) is not str or not 14 <= len(address) <= 90 or not address.isascii() or any(c.isspace() for c in address):
            raise ValueError('Explicit native change address required')
        self.terms_hash = sha(canonical(self.terms)).hex()
        self._node, self._wallet = node_rpc, wallet_rpc
        self._chain = BitcoinAdapter(node_rpc, dict(contract, funding_txid='00' * 32, funding_vout=0))

    @property
    def terms(self):
        return json.loads(canonical(self._terms))

    def _wallet_call(self, method, params):
        try:
            return self._wallet(method, params)
        except Exception:
            raise _Unavailable('Wallet RPC failed: ' + method) from None

    def _remaining(self, snapshot):
        return self.contract.refund_height - snapshot[1]

    def _before_deadline(self, snapshot):
        if self._remaining(snapshot) <= 0:
            raise ValueError('Funding refund height has already been reached')

    def _change_owned(self):
        if self._wallet_call('getblockhash', [0]) != self.contract.genesis_hash:
            raise ValueError('Funding wallet genesis mismatch')
        info = self._wallet_call('getaddressinfo', [self.terms['change_address']])
        if (type(info) is not dict or info.get('ismine') is not True
                or info.get('scriptPubKey') != self.change.hex()):
            raise ValueError('Pinned change must belong to the funding wallet')

    def _input_current(self, item, snapshot):
        utxo = self._chain._call('gettxout', [item['txid'], item['vout'], True])
        if (type(utxo) is not dict or utxo.get('bestblock') != snapshot[0]
                or _sats(utxo.get('value')) != item['value_sats']
                or utxo.get('scriptPubKey', {}).get('hex') != item['script_pubkey']):
            raise ValueError('Planned input is absent, spent, or differs from current chain')
        confirmations = _integer(utxo.get('confirmations'), self.minimum, snapshot[1] + 1, 'input confirmations')
        if utxo.get('coinbase') is True and confirmations < 100:
            raise ValueError('Immature coinbase input')

    def _outputs(self, plan):
        result = [(self.contract.funding_value_sats, self.contract.output_script())]
        if plan['change_value_sats']:
            result.append((plan['change_value_sats'], self.change))
        return result

    def _unsigned(self, plan):
        inputs = plan['inputs']
        return (_u32(2) + _compact(len(inputs)) + b''.join(_outpoint(i) + b'\0' + _u32(SEQUENCE) for i in inputs)
                + self._encoded_outputs(plan) + _u32(0))

    def _encoded_outputs(self, plan):
        outputs = self._outputs(plan)
        return _compact(len(outputs)) + b''.join(_u64(value) + _compact(len(script)) + script for value, script in outputs)

    def _checked_plan(self, value):
        fields = {'version', 'terms_hash', 'expected_txid', 'inputs', 'change_value_sats',
                  'selected_height', 'selected_tip', 'deadline_remaining'}
        if type(value) is not dict or set(value) != fields or len(canonical(value)) > 8192:
            raise ValueError('Exact bounded saved funding plan required')
        plan = json.loads(canonical(value))
        if type(plan['version']) is not int or plan['version'] != 1 or plan['terms_hash'] != self.terms_hash:
            raise ValueError('Funding plan configuration binding differs')
        _hex(plan['expected_txid'], 32, 'expected funding txid')
        _hex(plan['selected_tip'], 32, 'selection tip')
        height = _integer(plan['selected_height'], 0, 2**32 - 1, 'selection height')
        remaining = _integer(plan['deadline_remaining'], 1, self.contract.refund_height, 'funding deadline remaining')
        if remaining != self.contract.refund_height - height:
            raise ValueError('Funding plan deadline differs from pinned contract')
        inputs = plan['inputs']
        if type(inputs) is not list or not 1 <= len(inputs) <= MAX_INPUTS:
            raise ValueError('Funding needs 1..8 pinned native inputs')
        identities = []
        for item in inputs:
            if type(item) is not dict or set(item) != {'txid', 'vout', 'value_sats', 'script_pubkey'}:
                raise ValueError('Exact planned input required')
            _hex(item['txid'], 32, 'input txid')
            _integer(item['vout'], 0, 2**32-1, 'input index')
            _integer(item['value_sats'], 1, MAX_MONEY, 'input value')
            _p2wpkh(item['script_pubkey'])
            identities.append((item['txid'], item['vout']))
        if identities != sorted(set(identities)):
            raise ValueError('Input order or uniqueness differs')
        change = _integer(plan['change_value_sats'], 0, MAX_MONEY, 'change value')
        if (0 < change < 546 or sum(i['value_sats'] for i in inputs) > MAX_MONEY
                or sum(i['value_sats'] for i in inputs) != self.contract.funding_value_sats + self.fee + change):
            raise ValueError('Funding principal, fee or change balance differs')
        if dsha(self._unsigned(plan))[::-1].hex() != plan['expected_txid']:
            raise ValueError('Saved plan stripped transaction identity differs')
        return plan

    def plan(self):
        snapshot = self._chain._snapshot()
        self._before_deadline(snapshot)
        self._change_owned()
        locked = self._wallet_call('listlockunspent', [])
        if type(locked) is not list or len(locked) > 10000:
            raise ValueError('Bounded wallet reservation list required')
        excluded = {(i['txid'], i['vout']) for i in locked}
        coins = self._wallet_call('listunspent', [self.minimum, 9999999, [], False, {'maximumCount': MAX_COINS}])
        if type(coins) is not list or len(coins) > MAX_COINS:
            raise ValueError('Bounded wallet coin result required')
        eligible = []
        seen = set()
        for coin in coins:
            if type(coin) is not dict or any(coin.get(field) is not True for field in ('spendable', 'solvable', 'safe')):
                continue
            try:
                script = _p2wpkh(coin.get('scriptPubKey')).hex()
            except ValueError:
                continue
            txid = _hex(coin.get('txid'), 32, 'wallet input txid').hex()
            vout = _integer(coin.get('vout'), 0, 2**32 - 1, 'wallet input index')
            identity = (txid, vout)
            if identity in seen:
                raise ValueError('Duplicate wallet coin')
            seen.add(identity)
            if identity not in excluded:
                eligible.append({'txid': txid, 'vout': vout, 'value_sats': _sats(coin.get('amount')), 'script_pubkey': script})
        # Bounded deterministic largest-first selection, with one fixed fee.
        eligible.sort(key=lambda i: (-i['value_sats'], i['txid'], i['vout']))
        selected, total = [], 0
        needed = self.contract.funding_value_sats + self.fee
        for item in eligible[:MAX_INPUTS]:
            self._input_current(item, snapshot)
            selected.append(item)
            total += item['value_sats']
            if total == needed or total >= needed + 546:
                break
        if not selected or total < needed or 0 < total-needed < 546:
            raise ValueError('Insufficient eligible native wallet inputs for fixed fee and non-dust change')
        selected.sort(key=lambda i: (i['txid'], i['vout']))
        plan = {'version': 1, 'terms_hash': self.terms_hash, 'expected_txid': '00' * 32,
                'inputs': selected, 'change_value_sats': total-needed, 'selected_height': snapshot[1],
                'selected_tip': snapshot[0], 'deadline_remaining': self._remaining(snapshot)}
        plan['expected_txid'] = dsha(self._unsigned(plan))[::-1].hex()
        self._chain._stable(snapshot)
        return self._checked_plan(plan)

    def _reserve(self, plan):
        locked = self._wallet_call('listlockunspent', [])
        if type(locked) is not list or len(locked) > 10000:
            raise ValueError('Bounded wallet reservation list required')
        existing = {(item['txid'], item['vout']) for item in locked}
        missing = [{'txid': item['txid'], 'vout': item['vout']} for item in plan['inputs']
                   if (item['txid'], item['vout']) not in existing]
        if missing and self._wallet_call('lockunspent', [False, missing, True]) is not True:
            raise ValueError('Could not persist planned wallet reservations')
        after = self._wallet_call('listlockunspent', [])
        if type(after) is not list or len(after) > 10000:
            raise ValueError('Bounded wallet reservation list required')
        if not {(i['txid'], i['vout']) for i in plan['inputs']} <= {(i['txid'], i['vout']) for i in after}:
            raise ValueError('Wallet reservation confirmation incomplete')

    def prepare(self, plan):
        plan = self._checked_plan(plan)
        snapshot = self._chain._snapshot()
        self._before_deadline(snapshot)
        self._change_owned()
        for item in plan['inputs']:
            self._input_current(item, snapshot)
        self._reserve(plan)
        previous = [{'txid': i['txid'], 'vout': i['vout'], 'scriptPubKey': i['script_pubkey'],
                     'amount': format(Decimal(i['value_sats']) / 100_000_000, '.8f')} for i in plan['inputs']]
        signed = self._wallet_call('signrawtransactionwithwallet', [self._unsigned(plan).hex(), previous, 'ALL'])
        if type(signed) is not dict or signed.get('complete') is not True:
            raise ValueError('Wallet did not completely sign the pinned funding transaction')
        raw = _hex(signed.get('hex'), None, 'signed funding wire')
        self.validate(plan, raw, plan['expected_txid'])
        self._chain._stable(snapshot)
        return raw, plan['expected_txid']

    def _signature_digest(self, plan, index):
        item = plan['inputs'][index]
        script = b'\x76\xa9\x14' + bytes.fromhex(item['script_pubkey'])[2:] + b'\x88\xac'
        encoded = self._encoded_outputs(plan)
        return dsha(_u32(2) + dsha(b''.join(_outpoint(i) for i in plan['inputs']))
                    + dsha(_u32(SEQUENCE) * len(plan['inputs'])) + _outpoint(item)
                    + _compact(len(script)) + script + _u64(item['value_sats']) + _u32(SEQUENCE)
                    + dsha(encoded[1:]) + _u32(0) + _u32(1))

    def validate(self, plan, raw, txid):
        plan = self._checked_plan(plan)
        if not isinstance(raw, bytes) or not 10 <= len(raw) <= 4096 or txid != plan['expected_txid']:
            raise ValueError('Bounded signed funding and expected txid required')
        parsed = _parse(raw)
        expected_inputs = [(i['txid'], i['vout'], b'', SEQUENCE) for i in plan['inputs']]
        if (parsed['version'] != 2 or parsed['locktime'] != 0 or not parsed['segwit']
                or parsed['txid'] != txid or parsed['inputs'] != expected_inputs
                or parsed['outputs'] != self._outputs(plan)):
            raise ValueError('Signed funding differs from immutable plan')
        for index, (item, stack) in enumerate(zip(plan['inputs'], parsed['witnesses'])):
            if len(stack) != 2 or len(stack[1]) != 33 or stack[1][0] not in (2, 3):
                raise ValueError('Native compressed P2WPKH witness required')
            signature, pubkey = stack
            if hashlib.new('ripemd160', sha(pubkey)).digest() != bytes.fromhex(item['script_pubkey'])[2:]:
                raise ValueError('Funding witness key differs from pinned prevout')
            if not 9 <= len(signature) <= 73 or signature[-1] != 1:
                raise ValueError('Funding requires DER SIGHASH_ALL signatures')
            r, s = utils.decode_dss_signature(signature[:-1])
            if not 1 <= r < N or not 1 <= s <= N//2 or utils.encode_dss_signature(r, s) != signature[:-1]:
                raise ValueError('Noncanonical funding signature')
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey)
            try:
                key.verify(signature[:-1], self._signature_digest(plan, index), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            except InvalidSignature:
                raise ValueError('Funding BIP143 input signature is invalid') from None
        return {'txid': txid, 'wtxid': parsed['wtxid'], 'raw_sha256': sha(raw).hex(),
                'fee_sats': self.fee, 'funding_value_sats': self.contract.funding_value_sats,
                'funding_vout': 0, 'change_value_sats': plan['change_value_sats'], 'vsize': parsed['vsize']}

    def receipt(self, plan, raw, txid):
        plan = self._checked_plan(plan)
        checked = self.validate(plan, raw, txid)
        result = dict(checked, status='unknown', confirmations=0, final=False, height=None,
                      block_hash=None, genesis_hash=self.contract.genesis_hash,
                      funding_unspent=None, deadline_remaining=None)
        try:
            snapshot = self._chain._snapshot()
            result.update(height=snapshot[1], deadline_remaining=self._remaining(snapshot))
            info, _, found = self._chain._transaction(txid)
            if found != raw:
                return dict(result, status='conflict', reason='Funding txid matches but full witness bytes differ')
            if info.get('blockhash'):
                block, confirmations = self._chain._included(info['blockhash'], snapshot)
                if info.get('confirmations') != confirmations:
                    raise ValueError('Funding inclusion confirmations disagree')
                status = 'confirmed'
            else:
                if info.get('confirmations', 0) != 0:
                    raise ValueError('Funding pending confirmations disagree')
                entry = self._chain._call('getmempoolentry', [txid])
                if type(entry) is not dict or entry.get('wtxid') != checked['wtxid']:
                    raise ValueError('Funding mempool witness differs')
                block, confirmations, status = None, 0, 'pending'
            # A known funding receipt must consume every planned input in the
            # same chain/mempool view. Absence alone never proves its execution.
            for item in plan['inputs']:
                if self._chain._call('gettxout', [item['txid'], item['vout'], status != 'confirmed']) is not None:
                    raise ValueError('Funding receipt contradicts still-unspent input')
            utxo = self._chain._call('gettxout', [txid, 0, True])
            if utxo is not None:
                if (type(utxo) is not dict or utxo.get('bestblock') != snapshot[0]
                        or _sats(utxo.get('value')) != self.contract.funding_value_sats
                        or utxo.get('scriptPubKey', {}).get('hex') != self.contract.output_script().hex()
                        or utxo.get('confirmations') != confirmations):
                    raise ValueError('Current funding UTXO contradicts exact receipt')
            self._chain._stable(snapshot)
            return dict(result, status=status, confirmations=confirmations, block_hash=block,
                        funding_unspent=utxo is not None, publicly_observed=True,
                        final=confirmations >= self.contract.min_confirmations)
        except Exception:
            return dict(result, reason='Could not establish exact funding in a stable current chain/mempool view')

    def send(self, plan, raw, txid):
        plan = self._checked_plan(plan)
        self.validate(plan, raw, txid)
        receipt = self.receipt(plan, raw, txid)
        if receipt['status'] in ('confirmed', 'pending'):
            return txid
        if receipt['status'] == 'conflict':
            raise ValueError('Observed funding witness conflicts with retained artifact')
        snapshot = self._chain._snapshot()
        self._before_deadline(snapshot)
        for item in plan['inputs']:
            self._input_current(item, snapshot)
        accepted = self._chain._call('testmempoolaccept', [[raw.hex()]])
        if (type(accepted) is not list or len(accepted) != 1 or type(accepted[0]) is not dict
                or accepted[0].get('txid') != txid or accepted[0].get('allowed') is not True):
            raise ValueError('Pinned funding is not currently admissible at its fixed fee')
        self._chain._stable(snapshot)
        result = self._chain._call('sendrawtransaction', [raw.hex()])
        if result != txid:
            raise ValueError('Funding broadcast acknowledgment differs from expected txid')
        return result

    def resolve(self, plan, raw, txid):
        receipt = self.receipt(plan, raw, txid)
        if receipt['status'] != 'confirmed' or receipt['final'] is not True or receipt['funding_unspent'] is not True:
            raise ValueError('Exact confirmed unspent funding is not currently qualified')
        # Do not pin an inclusion block as immutable terms: a reorg can include
        # the identical funding at another height without changing its outpoint.
        terms = dict(self.terms['contract'], funding_txid=txid, funding_vout=0)
        Contract.parse(terms)
        return {'terms': terms, 'receipt': receipt}
