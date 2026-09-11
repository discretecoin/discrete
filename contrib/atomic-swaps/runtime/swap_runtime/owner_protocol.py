"""Signed public owner messages and explicit, chain-native scheduling bounds.

The shared directory is an untrusted transport, never a database or chain oracle.
Only publish funding AFTER the coordinator independently observes those exact
bytes in the selected chain. A signed funding message does not prove inclusion,
unspentness or agreement with the offer; the receiving funding adapter must
verify all three. Never put private preparation metadata or settlement bytes in
the public body. Accepted messages belong in the owner's durable private store.

Publication reserves a name exclusively, fsyncs a complete staging file, then
atomically hard-links it to the final name without replacing anything. This is
the portable no-replace equivalent of rename; filesystems without hard links
fail closed. Reservation and staging files remain as crash evidence. A partial
publication is an error requiring explicit reconciliation, never absence.

Scheduling uses declared upper/lower time bounds and safety margins. These are
operator assumptions, not measured block times or guarantees of finality. All
helpers here are offline and make no RPC requests.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from .bitcoin import N, pubkey
from .bitcoin_funding import BitcoinFundingAdapter
from .common import canonical, hex_bytes, integer, strict_json, sync_directory
from .solana_funding import SolanaFundingAdapter
from .xds_funding import FundingTerms


MAX_BYTES = 256 * 1024
DOMAIN = b'discrete-owner-public-exchange-v1\0'
ROLES = ('xds-owner', 'foreign-owner')
KINDS = ('accept', 'funding', 'cancel')
OFFER_FIELDS = {'version', 'swap_id', 'foreign_chain', 'xds', 'foreign', 'policy', 'schedule'}
POLICY_FIELDS = {'min_xds_confirmations', 'xds_claim_budget_blocks', 'foreign_claim_budget_units',
                 'max_observation_seconds', 'solana_fee_attempt_reserve'}
SCHEDULE_FIELDS = {'xds_min_funding_blocks', 'foreign_min_funding_units',
                   'foreign_min_before_xds_fund', 'foreign_min_before_xds_claim',
                   'max_observation_seconds', 'xds_block_upper_ms', 'foreign_unit_lower_ms',
                   'safety_margin_ms'}


def _bounded(value):
    """Strict JSON values, bounded before serialization (including cycles)."""
    if type(value) in (bytes, str):
        if not 1 <= len(value) <= MAX_BYTES:
            raise ValueError('Public JSON exceeds size bound')
        try:
            raw = value.encode('utf-8') if type(value) is str else value
        except UnicodeError:
            raise ValueError('Invalid public JSON') from None
        if not 1 <= len(raw) <= MAX_BYTES:
            raise ValueError('Public JSON exceeds size bound')
        try:
            value = strict_json(raw)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            raise ValueError('Invalid public JSON') from None
    stack, nodes = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 16384:
            raise ValueError('Public JSON exceeds structural bound')
        if type(item) is dict:
            if len(item) > 4096 or any(type(k) is not str or len(k) > 256 for k in item):
                raise ValueError('Invalid public JSON fields')
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            if len(item) > 4096:
                raise ValueError('Public JSON exceeds list bound')
            stack.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            if len(item) > MAX_BYTES:
                raise ValueError('Public JSON exceeds string bound')
        elif type(item) is int:
            if not -(2**63) <= item <= 2**64 - 1:
                raise ValueError('Public JSON integer exceeds bound')
        elif item is not None and type(item) is not bool:
            raise ValueError('Unsupported public JSON value')
    try:
        raw = canonical(value)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ValueError('Invalid public JSON') from None
    if len(raw) > MAX_BYTES:
        raise ValueError('Public JSON exceeds size bound')
    return strict_json(raw)


def _no_rpc(*_):
    raise AssertionError('Offer validation must remain offline')


def validate_offer(offer):
    """Return a detached validated offer; accept dict or bounded strict JSON."""
    offer = _bounded(offer)
    if type(offer) is not dict or set(offer) != OFFER_FIELDS or type(offer['version']) is not int or offer['version'] != 1:
        raise ValueError('Exact version-one owner offer required')
    if type(offer['swap_id']) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,80}', offer['swap_id']) is None:
        raise ValueError('Bounded safe swap identity required')
    native = FundingTerms.parse(offer['xds'])
    if native.min_confirmations < 11:
        raise ValueError('Native funding requires at least eleven confirmations')
    chain = offer['foreign_chain']
    try:
        if chain == 'bitcoin':
            foreign = BitcoinFundingAdapter(_no_rpc, _no_rpc, offer['foreign'])
            foreign_lock = foreign.contract.hashlock.hex()
            foreign_confirmations = foreign.contract.min_confirmations
        elif chain == 'solana':
            foreign = SolanaFundingAdapter(_no_rpc, offer['foreign'])
            foreign_lock = foreign.terms['hashlock']
            foreign_confirmations = foreign.terms['max_finality_lag_slots']
        else:
            raise ValueError('Unsupported foreign chain')
    except (ValueError, TypeError, KeyError):
        raise ValueError('Invalid foreign owner funding terms') from None
    if native.hashlock != foreign_lock:
        raise ValueError('Both chains must bind the same hashlock')
    p, s = offer['policy'], offer['schedule']
    if type(p) is not dict or set(p) != POLICY_FIELDS:
        raise ValueError('Exact settlement policy required')
    for name, low, high in (('min_xds_confirmations', 11, 100000), ('xds_claim_budget_blocks', 2, 100000),
                           ('foreign_claim_budget_units', 1, 10000000), ('max_observation_seconds', 1, 15),
                           ('solana_fee_attempt_reserve', 2, 10)):
        integer(p[name], name, low, high)
    if p['min_xds_confirmations'] < native.min_confirmations:
        raise ValueError('Settlement policy cannot weaken funding confirmation requirement')
    if type(s) is not dict or set(s) != SCHEDULE_FIELDS:
        raise ValueError('Exact declared scheduling assumptions required')
    for name in SCHEDULE_FIELDS:
        integer(s[name], name, 0 if name == 'safety_margin_ms' else 1, 2**53 - 1)
    if s['max_observation_seconds'] > p['max_observation_seconds']:
        raise ValueError('Scheduling observation age exceeds settlement policy')
    if s['xds_min_funding_blocks'] <= p['min_xds_confirmations'] + p['xds_claim_budget_blocks']:
        raise ValueError('Native funding floor must include confirmations and claim reserve')
    if s['foreign_min_funding_units'] <= foreign_confirmations + p['foreign_claim_budget_units']:
        raise ValueError('Foreign funding floor must include finality and claim reserve')
    if chain == 'solana' and s['foreign_min_funding_units'] < foreign.terms['min_funding_window_slots']:
        raise ValueError('Scheduling floor cannot weaken Solana funding window')
    if (s['foreign_min_before_xds_fund'] < s['foreign_min_funding_units']
            or s['foreign_min_before_xds_fund'] < s['foreign_min_before_xds_claim']
            or s['foreign_min_before_xds_claim'] < p['foreign_claim_budget_units']):
        raise ValueError('Foreign scheduling reserves are inconsistent')
    return offer


def offer_hash(offer):
    return hashlib.sha256(canonical(validate_offer(offer))).hexdigest()


def _identity(offer, role):
    if role not in ROLES:
        raise ValueError('Unsupported owner role')
    if offer['foreign_chain'] == 'bitcoin':
        return offer['foreign']['contract']['claim_pubkey' if role == 'xds-owner' else 'refund_pubkey']
    return offer['foreign']['claim_payer' if role == 'xds-owner' else 'owner']


def owner_key(chain, value):
    """Decode a canonical private scalar or standard 64-byte Solana keypair."""
    try:
        if chain == 'bitcoin':
            scalar = int.from_bytes(hex_bytes(value, 32, 'owner key'), 'big')
            if not 1 <= scalar < N:
                raise ValueError('Invalid scalar')
            return ec.derive_private_key(scalar, ec.SECP256K1())
        if chain == 'solana':
            return Keypair.from_bytes(hex_bytes(value, 64, 'owner key'))
    except Exception:
        raise ValueError('Invalid owner signing key') from None
    raise ValueError('Unsupported owner signing chain')


def validate_owner_key(offer, role, key):
    offer = validate_offer(offer)
    identity = _identity(offer, role)
    try:
        if offer['foreign_chain'] == 'bitcoin':
            valid = isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256K1) and pubkey(key).hex() == identity
        else:
            valid = isinstance(key, Keypair) and str(key.pubkey()) == identity
    except Exception:
        valid = False
    if not valid:
        raise ValueError('Signing key differs from pinned owner identity')
    return identity


def schedule_ready(offer, xds_height, foreign_height, phase):
    offer = validate_offer(offer)
    integer(xds_height, 'native height', 0, 2**32 - 1)
    integer(foreign_height, 'foreign height', 0, 2**64 - 1)
    p, s = offer['policy'], offer['schedule']
    xds_remaining = offer['xds']['refund_height'] - xds_height
    deadline = offer['foreign']['contract']['refund_height'] if offer['foreign_chain'] == 'bitcoin' else offer['foreign']['deadline_slot']
    foreign_remaining = deadline - foreign_height
    if phase == 'funding':
        xds_floor, foreign_floor = s['xds_min_funding_blocks'], s['foreign_min_before_xds_fund']
    elif phase == 'second-funding':
        xds_floor, foreign_floor = s['xds_min_funding_blocks'], s['foreign_min_funding_units']
    elif phase == 'first-claim':
        xds_floor, foreign_floor = p['xds_claim_budget_blocks'], s['foreign_min_before_xds_claim']
    else:
        raise ValueError('Unsupported scheduling phase')
    return (xds_remaining >= xds_floor and foreign_remaining >= foreign_floor
            and foreign_remaining * s['foreign_unit_lower_ms'] > xds_remaining * s['xds_block_upper_ms'] + s['safety_margin_ms'])


def _reparse(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def _same(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


class PublicExchange:
    """Immutable signed messages; authenticity is independent of folder trust."""
    def __init__(self, directory, offer):
        self._offer = validate_offer(offer)
        self.offer_hash = offer_hash(self._offer)
        self.directory = Path(os.path.abspath(directory))
        try:
            for path in (self.directory, *self.directory.parents):
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or _reparse(info):
                    raise ValueError('Regular exchange directory required')
            self._directory_stat = self.directory.lstat()
        except OSError:
            raise ValueError('Existing regular exchange directory required') from None

    def _check_directory(self):
        try:
            for path in (self.directory, *self.directory.parents):
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or _reparse(info):
                    raise ValueError('Exchange directory changed')
            if not _same(self._directory_stat, self.directory.lstat()):
                raise ValueError('Exchange directory changed')
        except OSError:
            raise ValueError('Exchange directory changed') from None

    def _paths(self, role, kind):
        if role not in ROLES or kind not in KINDS:
            raise ValueError('Unsupported public message role or kind')
        stem = self.offer_hash + '.' + role + '.' + kind
        return tuple(self.directory / (stem + suffix) for suffix in ('.json', '.reserve', '.pending'))

    @staticmethod
    def _exists(path):
        try:
            path.lstat()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            raise ValueError('Cannot inspect public message') from None

    def _body(self, kind, body):
        body = _bounded(body)
        if type(body) is not dict:
            raise ValueError('Exact public message body required')
        if kind in ('accept', 'cancel'):
            if set(body) != {'offer_hash'} or body['offer_hash'] != self.offer_hash:
                raise ValueError('Public message differs from agreed offer')
        elif kind == 'funding':
            if set(body) != {'plan', 'raw', 'txid'} or type(body['plan']) is not dict:
                raise ValueError('Exact public funding artifact required')
            raw = body['raw']
            if type(raw) is not str or not raw or len(raw) % 2:
                raise ValueError('Canonical public funding wire required')
            try:
                if bytes.fromhex(raw).hex() != raw:
                    raise ValueError('Noncanonical wire')
            except ValueError:
                raise ValueError('Canonical public funding wire required') from None
            txid = body['txid']
            # Native and Bitcoin IDs are hexadecimal; Solana signatures base58.
            if type(txid) is not str or re.fullmatch(r'[A-Za-z0-9]{1,128}', txid) is None:
                raise ValueError('Bounded public funding transaction identity required')
        else:
            raise ValueError('Unsupported public message kind')
        return body

    def _verify(self, raw, role, kind):
        envelope = _bounded(raw)
        if (type(envelope) is not dict or set(envelope) != {'version', 'offer_hash', 'role', 'kind', 'body', 'signature'}
                or type(envelope['version']) is not int or envelope['version'] != 1
                or envelope['offer_hash'] != self.offer_hash or envelope['role'] != role or envelope['kind'] != kind
                or canonical(envelope) != raw):
            raise ValueError('Noncanonical or mismatched public envelope')
        body = self._body(kind, envelope['body'])
        message = DOMAIN + canonical({k: v for k, v in envelope.items() if k != 'signature'})
        try:
            value = envelope['signature']
            signature = bytes.fromhex(value)
            if signature.hex() != value:
                raise ValueError('Noncanonical signature')
            identity = _identity(self._offer, role)
            if self._offer['foreign_chain'] == 'bitcoin':
                r, s = utils.decode_dss_signature(signature)
                if not 1 <= r < N or not 1 <= s <= N // 2 or utils.encode_dss_signature(r, s) != signature:
                    raise ValueError('Noncanonical signature')
                public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(identity))
                public.verify(signature, hashlib.sha256(message).digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            elif len(signature) != 64 or not Signature.from_bytes(signature).verify(Pubkey.from_string(identity), message):
                raise ValueError('Invalid signature')
        except Exception:
            raise ValueError('Invalid public owner signature') from None
        return body

    def read(self, role, kind):
        """Return verified public body, None for absence, or fail on uncertainty."""
        self._check_directory()
        final, reservation, pending = self._paths(role, kind)
        if not self._exists(final):
            if self._exists(reservation) or self._exists(pending):
                raise ValueError('Incomplete public message requires reconciliation')
            return None
        try:
            before = final.lstat()
            if _reparse(before) or not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_BYTES:
                raise ValueError('Bounded regular public message required')
            fd = os.open(final, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or not _same(before, opened):
                    raise ValueError('Public message changed during read')
                raw = stream.read(MAX_BYTES + 1)
                after = os.fstat(stream.fileno())
                if len(raw) != before.st_size or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                    raise ValueError('Public message changed during read')
            if not _same(before, final.lstat()) or _reparse(final.lstat()):
                raise ValueError('Public message changed during read')
        except OSError:
            raise ValueError('Cannot read public message') from None
        self._check_directory()
        return self._verify(raw, role, kind)

    def publish(self, role, kind, body, key):
        """Publish once; only an already verified identical body is idempotent."""
        self._check_directory()
        final, reservation, pending = self._paths(role, kind)
        validate_owner_key(self._offer, role, key)
        body = self._body(kind, body)
        existing = self.read(role, kind)
        if existing is not None:
            if existing != body:
                raise ValueError('Public message already has a different immutable body')
            return final
        envelope = dict(version=1, offer_hash=self.offer_hash, role=role, kind=kind, body=body)
        message = DOMAIN + canonical(envelope)
        if self._offer['foreign_chain'] == 'bitcoin':
            signature = key.sign(hashlib.sha256(message).digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            r, s = utils.decode_dss_signature(signature)
            signature = utils.encode_dss_signature(r, min(s, N - s))
        else:
            signature = bytes(key.sign_message(message))
        raw = canonical(dict(envelope, signature=signature.hex()))
        if len(raw) > MAX_BYTES:
            raise ValueError('Public envelope exceeds size bound')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
        try:
            fd = os.open(reservation, flags, 0o600)
        except FileExistsError:
            existing = self.read(role, kind)
            if existing == body:
                return final
            raise ValueError('Public message publication is already reserved') from None
        except OSError:
            raise ValueError('Cannot reserve public message') from None
        try:
            with os.fdopen(fd, 'wb') as reserved:
                reserved.write(b'owner-public-v1\n')
                reserved.flush()
                os.fsync(reserved.fileno())
            self._check_directory()
            fd = os.open(pending, flags, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                staged = os.fstat(stream.fileno())
                check = pending.lstat()
                if _reparse(check) or not _same(staged, check):
                    raise ValueError('Public staging file changed')
                self._check_directory()
                os.link(pending, final, follow_symlinks=False)
                if not _same(staged, final.lstat()) or _reparse(final.lstat()):
                    raise ValueError('Public publication changed')
            sync_directory(self.directory)
        except OSError:
            raise ValueError('Public publication incomplete; reconcile retained evidence') from None
        if self.read(role, kind) != body:
            raise ValueError('Published public message differs')
        return final
