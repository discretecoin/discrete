"""Native wallet funding with independent wire, input and fixed-fee checks.

The caller must persist a prepare-start marker before calling prepare, and the
returned exact draft before send. The existing native prepare RPC neither
reserves coins nor persists its response: an uncertain response must not cause
another preparation. selected_inputs are reservation keys for the caller's
durable store. They do not lock an independently operated native wallet.

Every funding signature is verified locally against the exact resolved source
outputs. Chain inclusion/spentness comes from the selected validating daemon.
Encrypted change ownership remains the authenticated native wallet's duty;
preparation binds its refund role/address and signs the complete change bytes.
"""
from dataclasses import dataclass, asdict
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

from .xds import Contract, _Reader, _parse, _integer, _hex, _h, _commit, SIGN_DOMAIN, _Unavailable
from .xds import TX_PQ, TX_PQ_V2, TX_SWAP_FUND, TX_SWAP_SPEND


NULLIFIER_DOMAIN = b'discrete-pq-nullifier-v1'
MAX_SOURCE_BYTES = 1024 * 1024


def _source(raw):
    """Bounded complete source parser; existing settlement parser stays strict."""
    if not isinstance(raw, bytes) or not 6 <= len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError('Invalid native source transaction size')
    r = _Reader(raw)
    version, family, outer_lock = r.var(8), r.var(8), r.var()
    if family in (TX_SWAP_FUND, TX_SWAP_SPEND):
        parsed = _parse(raw)
        for output in parsed['outputs']:
            output['lock'] = 0
        return parsed
    if version != 1 or family not in (0, TX_PQ, TX_PQ_V2):
        raise ValueError('Unsupported ordinary native funding source')
    count = r.var()
    if not 1 <= count <= (1 if family == 0 else 128):
        raise ValueError('Bounded native source input count required')
    signatures = 0
    for _ in range(count):
        tag = r.take(1)[0]
        if family == 0 and tag == 255:
            r.var(32)
        elif family in (TX_PQ, TX_PQ_V2) and tag == 16:
            r.take(32); r.var(32); r.take(1952 + 32)
            signatures += 1
        else:
            raise ValueError('Unexpected native source input')
    count = r.var()
    if not 1 <= count <= 4096:
        raise ValueError('Bounded native source output count required')
    outputs = []
    for _ in range(count):
        start = r.at
        amount, lock, tag = r.var(), r.var(), r.take(1)[0]
        if not amount or tag not in (16, 17) or (family in (TX_PQ, TX_PQ_V2) and tag != 16):
            raise ValueError('Unexpected native source output')
        if tag == 16:
            r.take(1088 + 56)
        commitment = r.take(32)
        outputs.append(dict(amount=amount, lock=lock, tag=tag, commitment=commitment, wire=raw[start:r.at]))
    extra = r.var()
    if extra > MAX_SOURCE_BYTES:
        raise ValueError('Bounded native source extra required')
    r.take(extra)
    r.take(signatures * 3309)
    if r.at != len(raw):
        raise ValueError('Trailing native source bytes')
    return dict(family=family, txid=_h(raw).hex(), outputs=outputs, outer_lock=outer_lock)


def _wire_hex(value):
    if type(value) is not str or len(value) > 2 * MAX_SOURCE_BYTES:
        raise ValueError('Bounded native source wire required')
    raw = bytes.fromhex(value)
    if raw.hex() != value:
        raise ValueError('Canonical native source wire required')
    return raw


def _nullifier(item):
    return _h(NULLIFIER_DOMAIN + item['pub'] + item['rho'] + item['prev'] + struct.pack('<I', item['index'])).hex()


@dataclass(frozen=True)
class FundingTerms:
    genesis_hash: str
    hashlock: str
    nonce: str
    claim_commitment: str
    refund_commitment: str
    claim_address: str
    refund_address: str
    refund_height: int
    funding_value_atoms: int
    net_amount_atoms: int
    fee_atoms: int
    min_confirmations: int

    @classmethod
    def parse(cls, values):
        if type(values) is not dict or set(values) != set(cls.__dataclass_fields__):
            raise ValueError('Complete fixed native funding terms required')
        values = dict(values)
        for name in ('genesis_hash', 'hashlock', 'nonce', 'claim_commitment', 'refund_commitment'):
            values[name] = _hex(values[name], 32, name).hex()
        for name in ('claim_address', 'refund_address'):
            address = values[name]
            if type(address) is not str or not 1 <= len(address) <= 8192 or not address.isascii() or any(c.isspace() for c in address):
                raise ValueError('Agreed native role address required')
        if values['claim_address'] == values['refund_address'] or values['claim_commitment'] == values['refund_commitment']:
            raise ValueError('Native funding roles must differ')
        for name, low, high in (('refund_height', 1, 2**32 - 1), ('funding_value_atoms', 2, 2**64 - 2),
                                ('net_amount_atoms', 1, 2**64 - 3), ('fee_atoms', 1, 1),
                                ('min_confirmations', 1, 1000000)):
            values[name] = _integer(values[name], low, high, name)
        if values['funding_value_atoms'] != values['net_amount_atoms'] + values['fee_atoms']:
            raise ValueError('Native escrow must include exactly one exit-fee atom')
        return cls(**values)


class XdsFundingAdapter:
    def __init__(self, rpc, terms, wallet=None):
        if not callable(rpc) or (wallet is not None and not callable(wallet)):
            raise ValueError('Native RPC callables required')
        self.rpc, self.wallet = rpc, wallet
        self.terms = FundingTerms.parse(terms)

    def plan(self):
        """Public immutable terms; coin selection belongs to native preparation."""
        return asdict(self.terms)

    def _call(self, method, params, wallet=False):
        try:
            target = self.wallet if wallet else self.rpc
            if target is None:
                raise ValueError('Signing wallet absent')
            return target(method, params)
        except Exception:
            raise _Unavailable('Native funding RPC failed: ' + method) from None

    def _snapshot(self):
        info = self._call('getinfo', {})
        if type(info) is not dict or info.get('status') != 'OK' or info.get('finality_fork_warning') is not False:
            raise _Unavailable('Native funding chain is unavailable or split')
        height = _integer(info.get('height'), 1, 2**32 - 1, 'native height')
        tip = _hex(info.get('top_block_hash'), 32, 'native tip').hex()
        if _integer(info.get('last_known_block_index'), 0, 2**32 - 1, 'known height') >= height:
            raise _Unavailable('Native daemon is behind known height')
        if type(info.get('min_fee')) is not int or info['min_fee'] != 1:
            raise _Unavailable('Native minimum fee differs from fixed one atom')
        return height, tip

    def _stable(self, snapshot):
        if self._snapshot() != snapshot:
            raise _Unavailable('Native chain changed during funding validation')

    def _read(self, txid, index, snapshot, tag=''):
        state = self._call('get_swap_outpoint', dict(txid=txid, index=index, spend_tag=tag))
        if (type(state) is not dict or state.get('status') != 'OK'
                or state.get('genesis_hash') != self.terms.genesis_hash
                or (state.get('height'), state.get('tip_hash')) != snapshot):
            raise _Unavailable('Native outpoint network/snapshot mismatch')
        for name in ('found', 'in_chain', 'in_pool', 'spent_known', 'spent', 'spent_in_pool'):
            if type(state.get(name)) is not bool:
                raise _Unavailable('Malformed native outpoint flags')
        _integer(state.get('height'), 1, 2**32 - 1, 'outpoint height')
        confirmations = _integer(state.get('confirmations'), 0, snapshot[0], 'outpoint confirmations')
        if state['in_chain']:
            height = _integer(state.get('block_height'), 0, snapshot[0] - 1, 'inclusion height')
            _hex(state.get('block_hash'), 32, 'inclusion block')
            if state['in_pool'] or confirmations != snapshot[0] - height:
                raise _Unavailable('Inconsistent native inclusion')
        elif confirmations or state.get('block_hash'):
            raise _Unavailable('Unconfirmed native outpoint has inclusion metadata')
        if not state['found']:
            if state['in_chain'] or state['in_pool']:
                raise _Unavailable('Missing native output has transaction membership')
            return state, None
        parsed = _source(_wire_hex(state.get('tx_as_hex')))
        if parsed['txid'] != txid or index >= len(parsed['outputs']):
            raise _Unavailable('Native source wire identity mismatch')
        if type(state.get('amount_atoms')) is not int or state['amount_atoms'] != parsed['outputs'][index]['amount']:
            raise _Unavailable('Native source wire amount mismatch')
        if tag and (not state['spent_known'] or state.get('spend_tag') != tag):
            raise _Unavailable('Native source nullifier/spentness mismatch')
        return state, parsed

    def _bound(self, raw, txid):
        parsed = _parse(raw)
        if parsed['family'] != TX_SWAP_FUND or parsed['txid'] != _hex(txid, 32, 'funding txid').hex():
            raise ValueError('Native funding family/identity mismatch')
        index = next(i for i, output in enumerate(parsed['outputs']) if output['tag'] == 18)
        terms = self.plan()
        del terms['net_amount_atoms']
        terms.update(funding_txid=txid, funding_vout=index, funding_wire=raw.hex())
        Contract.parse(terms)
        return parsed, terms

    def validate(self, raw, txid):
        """Resolve source wires, independently verify every signature and economics.

        Spent source inputs do not invalidate already accepted funding signatures.
        send separately requires current unspent sources before first transmission.
        """
        parsed, terms = self._bound(raw, txid)
        snapshot = self._snapshot()
        inputs, resolved, total, unspent, seen = [], [], 0, True, set()
        for item in parsed['inputs']:
            reference = (item['prev'].hex(), item['index'])
            if reference in seen:
                raise ValueError('Repeated native funding input')
            seen.add(reference)
            tag = _nullifier(item)
            state, source = self._read(*reference, snapshot, tag)
            if source is None or not state['in_chain'] or state['in_pool']:
                raise _Unavailable('Native funding source is not confirmed')
            output = source['outputs'][item['index']]
            if output['tag'] not in (16, 17) or _commit(item['pub'], item['rho']) != output['commitment']:
                raise ValueError('Native funding input authority mismatch')
            if output['lock'] > snapshot[0] - 1:
                raise _Unavailable('Native funding input is immature')
            total += output['amount']
            if total > 2**64 - 1:
                raise ValueError('Native funding input value overflow')
            resolved.append(output['wire'])
            unspent = unspent and not state['spent'] and not state['spent_in_pool']
            inputs.append(dict(txid=reference[0], vout=reference[1], amount_atoms=output['amount'], spend_tag=tag,
                               spent=state['spent'], spent_in_pool=state['spent_in_pool'],
                               reservation_key=self.terms.genesis_hash + ':' + reference[0] + ':' + str(reference[1])))
        total_out = sum(output['amount'] for output in parsed['outputs'])
        if total_out > 2**64 - 1 or total - total_out != 1:
            raise ValueError('Native funding must pay exactly one fee atom')
        common = (SIGN_DOMAIN + bytes.fromhex(self.terms.genesis_hash))
        tail = (struct.pack('<I', len(parsed['prefix'])) + parsed['prefix'] + struct.pack('<I', len(resolved))
                + b''.join(struct.pack('<I', len(output)) + output for output in resolved) + struct.pack('<Q', 1))
        for index, item in enumerate(parsed['inputs']):
            try:
                mldsa.MLDSA65PublicKey.from_public_bytes(item['pub']).verify(
                    parsed['signatures'][index], _h(common + struct.pack('<I', index) + tail))
            except InvalidSignature:
                raise ValueError('Invalid native funding input signature') from None
        self._stable(snapshot)
        return dict(txid=txid, terms=terms, selected_inputs=inputs, inputs_unspent=unspent,
                    height=snapshot[0], tip_hash=snapshot[1], funding_fee_atoms=1,
                    exit_fee_atoms=1, net_amount_atoms=self.terms.net_amount_atoms,
                    change_atoms=total_out - self.terms.funding_value_atoms)

    def prepare(self, refund_rho):
        if type(refund_rho) is not bytes or len(refund_rho) != 32:
            raise ValueError('Native refund rho must contain 32 bytes')
        c = self.terms
        role = self._call('swap_role', {'rho': refund_rho.hex()}, wallet=True)
        if (type(role) is not dict or role.get('genesis_hash') != c.genesis_hash
                or role.get('commitment') != c.refund_commitment or role.get('address') != c.refund_address):
            raise ValueError('Native funding wallet network/refund role/address mismatch')
        height, _ = self._snapshot()
        if height >= c.refund_height:
            raise _Unavailable('Native funding deadline has already arrived')
        response = self._call('swap_prepare_funding', dict(principal_atoms=c.funding_value_atoms,
            refund_height=c.refund_height, hashlock=c.hashlock, nonce=c.nonce,
            claim_commitment=c.claim_commitment, refund_rho=refund_rho.hex(), genesis_hash=c.genesis_hash), wallet=True)
        if (type(response) is not dict or type(response.get('fee_atoms')) is not int or response['fee_atoms'] != 1
                or type(response.get('principal_atoms')) is not int or response['principal_atoms'] != c.funding_value_atoms):
            raise ValueError('Native preparation returned inconsistent funding amounts')
        raw = _hex(response.get('tx_as_hex'), None, 'native funding wire')
        txid = _hex(response.get('tx_hash'), 32, 'native funding identity').hex()
        checked = self.validate(raw, txid)
        if not checked['inputs_unspent'] or checked['height'] >= c.refund_height:
            raise _Unavailable('Native funding changed while being prepared')
        for item in _parse(raw)['inputs']:
            if _commit(item['pub'], refund_rho).hex() != c.refund_commitment:
                raise ValueError('Prepared funding is not authorized by the agreed native wallet')
        return raw, txid

    def receipt(self, raw, txid):
        self._bound(raw, txid)
        base = dict(status='unknown', txid=txid, confirmations=0, final=False,
                    height=None, block_hash=None, tip_hash=None, publicly_observed=False)
        try:
            checked = self.validate(raw, txid)
            snapshot = self._snapshot()
            if snapshot != (checked['height'], checked['tip_hash']):
                raise _Unavailable('Native funding sources and receipt span different tips')
            state, parsed = self._read(txid, checked['terms']['funding_vout'], snapshot)
            if parsed is None or state.get('tx_as_hex') != raw.hex():
                raise _Unavailable('Exact native funding not observed')
            if state['in_chain']:
                if state['block_height'] >= self.terms.refund_height:
                    raise _Unavailable('Native funding included after its deadline')
                if not all(item['spent'] and not item['spent_in_pool'] for item in checked['selected_inputs']):
                    raise _Unavailable('Confirmed native funding source spentness differs')
                status = 'confirmed'
            elif state['in_pool']:
                if not all(item['spent_in_pool'] and not item['spent'] for item in checked['selected_inputs']):
                    raise _Unavailable('Pending native funding source spentness differs')
                status = 'pending'
            else:
                raise _Unavailable('Native funding has no current membership')
            self._stable(snapshot)
            return dict(base, status=status, height=snapshot[0], tip_hash=snapshot[1],
                        block_hash=state['block_hash'] or None, confirmations=state['confirmations'],
                        final=status == 'confirmed' and state['confirmations'] >= self.terms.min_confirmations,
                        publicly_observed=True)
        except (_Unavailable, ValueError, TypeError, AttributeError):
            return base

    def send(self, raw, txid):
        prior = self.receipt(raw, txid)
        if prior['status'] in ('pending', 'confirmed'):
            return txid
        checked = self.validate(raw, txid)
        if not checked['inputs_unspent'] or checked['height'] >= self.terms.refund_height:
            raise _Unavailable('Native funding input interference or expired deadline')
        self._call('sendrawtransaction', {'tx_as_hex': raw.hex()})
        receipt = self.receipt(raw, txid)
        if receipt['status'] not in ('pending', 'confirmed'):
            raise _Unavailable('Native funding acknowledgment lacks an exact receipt')
        return txid

    def resolve(self, raw, txid):
        checked = self.validate(raw, txid)
        return dict(terms=checked['terms'], receipt=self.receipt(raw, txid))
