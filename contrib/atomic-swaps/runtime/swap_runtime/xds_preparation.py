"""Durable native prepare RPC, bound independently to one retained operation.

Only a caller's first attempt may create an operation. A resumed attempt looks
up its exact ID; absence never authorizes another prepare. The wallet persists
the selected draft before signing and the final bytes before returning them.
"""
import hashlib
import struct

from .xds import _hex, _commit, _parse, _Unavailable


DOMAIN = b'discrete-swap-funding-operation-v1\0'
FIELDS = {'status', 'operation_id', 'request_hash', 'draft_hash', 'tx_hash',
          'tx_as_hex', 'fee_atoms', 'principal_atoms'}


def _canonical_hash(value, name):
    raw = _hex(value, 32, name)
    if type(value) is not str or raw.hex() != value:
        raise ValueError('Canonical native operation field required')
    return raw


def request(adapter, rho, operation_id):
    if type(rho) is not bytes or len(rho) != 32:
        raise ValueError('Native refund rho must contain 32 bytes')
    _canonical_hash(operation_id, 'native operation ID')
    c = adapter.terms
    return dict(operation_id=operation_id, principal_atoms=c.funding_value_atoms,
        refund_height=c.refund_height, hashlock=c.hashlock, nonce=c.nonce,
        claim_commitment=c.claim_commitment, refund_rho=rho.hex(), genesis_hash=c.genesis_hash)


def request_hash(adapter, rho, operation_id):
    q = request(adapter, rho, operation_id)
    encoded = (DOMAIN + bytes.fromhex(q['genesis_hash']) + bytes.fromhex(operation_id)
        + struct.pack('<QI', q['principal_atoms'], q['refund_height'])
        + b''.join(bytes.fromhex(q[name]) for name in ('hashlock', 'nonce', 'claim_commitment', 'refund_rho')))
    return hashlib.sha3_256(encoded).hexdigest()


def capabilities(adapter):
    value = adapter._call('swap_funding_capabilities', {}, wallet=True)
    expected = {'version', 'durable_prepare', 'lookup', 'max_operations', 'max_wire_bytes'}
    if (type(value) is not dict or set(value) != expected
            or type(value['version']) is not int or value['version'] != 1
            or value['durable_prepare'] is not True or value['lookup'] is not True
            or type(value['max_operations']) is not int or not 1 <= value['max_operations'] <= 100000
            or type(value['max_wire_bytes']) is not int or value['max_wire_bytes'] != 65536):
        raise ValueError('Durable native funding capability not established')
    return value


def scan_ready(adapter):
    """Read-only readiness before a NEW durable operation can become uncertain.

    Daemon height counts blocks; wallet height is the last scanned block index.
    This does not replace the native source/scan checks inside preparation.
    """
    snapshot = adapter._snapshot()
    value = adapter._call('swap_scan_height', {}, wallet=True)
    if (type(value) is not dict or set(value) != {'height'}
            or type(value['height']) is not int or not 0 <= value['height'] <= 2**32 - 1):
        raise ValueError('Exact bounded native wallet scan height required')
    return adapter._snapshot() == snapshot and value['height'] + 1 >= snapshot[0]


def _response(adapter, rho, operation_id, value):
    if (type(value) is not dict or set(value) != FIELDS or value['operation_id'] != operation_id
            or value['status'] not in ('absent', 'draft', 'prepared')
            or type(value['fee_atoms']) is not int or type(value['principal_atoms']) is not int):
        raise ValueError('Invalid native operation response')
    if value['status'] == 'absent':
        if (any(value[k] != '' for k in ('request_hash', 'draft_hash', 'tx_hash', 'tx_as_hex'))
                or value['fee_atoms'] != 0 or value['principal_atoms'] != 0):
            raise ValueError('Inconsistent absent native operation')
        raise _Unavailable('Retained native preparation is absent; no replacement is authorized')
    if value['request_hash'] != request_hash(adapter, rho, operation_id):
        raise ValueError('Native operation terms differ from the retained request')
    _canonical_hash(value['draft_hash'], 'native draft hash')
    if value['fee_atoms'] != 1 or value['principal_atoms'] != adapter.terms.funding_value_atoms:
        raise ValueError('Native operation returned inconsistent funding amounts')
    if value['status'] == 'draft':
        if value['tx_hash'] != '' or value['tx_as_hex'] != '':
            raise ValueError('Unsigned native draft cannot expose prepared wire')
        return None
    if type(value['tx_as_hex']) is not str or not 0 < len(value['tx_as_hex']) <= 2 * 65536:
        raise ValueError('Bounded prepared native wire required')
    raw = _hex(value['tx_as_hex'], None, 'native funding wire')
    if raw.hex() != value['tx_as_hex']:
        raise ValueError('Canonical native funding wire required')
    txid = _canonical_hash(value['tx_hash'], 'native funding identity').hex()
    checked = adapter.validate(raw, txid)
    if not checked['inputs_unspent'] or checked['height'] >= adapter.terms.refund_height:
        raise _Unavailable('Retained native funding inputs changed or deadline arrived')
    for item in _parse(raw)['inputs']:
        if _commit(item['pub'], rho).hex() != adapter.terms.refund_commitment:
            raise ValueError('Prepared funding is not authorized by the agreed native wallet')
    return raw, txid


def prepare(adapter, rho, operation_id, *, resume=False):
    """One lookup, and at most one exact prepare/resume RPC; never a retry loop."""
    if type(resume) is not bool:
        raise ValueError('Explicit native operation phase required')
    q = request(adapter, rho, operation_id)
    c = adapter.terms
    role = adapter._call('swap_role', {'rho': rho.hex()}, wallet=True)
    if (type(role) is not dict or role.get('genesis_hash') != c.genesis_hash
            or role.get('commitment') != c.refund_commitment or role.get('address') != c.refund_address):
        raise ValueError('Native funding wallet network/refund role/address mismatch')
    if adapter._snapshot()[0] >= c.refund_height:
        raise _Unavailable('Native funding deadline has already arrived')
    if resume:
        saved = adapter._call('swap_get_funding_preparation', {'operation_id': operation_id}, wallet=True)
        result = _response(adapter, rho, operation_id, saved)
        if result is not None:
            return result
    value = adapter._call('swap_prepare_funding_once', q, wallet=True)
    result = _response(adapter, rho, operation_id, value)
    if result is None:
        raise _Unavailable('Exact native funding draft remains incomplete')
    if resume and saved['draft_hash'] != value['draft_hash']:
        raise ValueError('Native operation changed its retained draft')
    return result
