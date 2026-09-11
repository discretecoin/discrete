"""Pinned Bitcoin P2WSH settlement, adapted from the frozen v05 BIP143 builder.

``BitcoinAdapter(rpc, terms)`` takes a callable ``rpc(method, params)`` and an
immutable contract mapping (hex strings are canonical lowercase, amounts satoshi):
genesis_hash, hashlock, claim_pubkey, refund_pubkey, refund_height, funding_txid,
funding_vout, funding_value_sats, claim_script, refund_script, fee_sats,
min_confirmations. Optional funding_blockhash enables non-txindex funding lookup.

``prepare(kind, key, secret=None)`` returns (wire bytes, txid); the caller must
durably journal these bytes BEFORE broadcasting or exposing a claim preimage.
Kinds are foreign-claim / foreign-refund. ``validate`` independently parses and
verifies the wire, BIP143 signature, role, hashlock and every economic field.
It returns kind, txid, wtxid, fee_sats, amount_sats, destination_script (and secret
hex for a claim). ``send`` validates then transmits precisely those bytes.

``observe`` status: unspent / spent / unknown. ``receipt`` status: confirmed /
pending / unknown / conflict. Observations include confirmations, height (tip),
block_hash (funding/inclusion block when known), genesis_hash, refund_eligible.
Receipt additionally includes txid/wtxid and final (confirmation threshold).
Only exact observed full wire with current membership gets publicly_observed=True.
``expected_txid(kind)`` computes the agreed SegWit stripped ID in advance.
``verify_public_spend(candidate_txid, kind)`` verifies a supplied public spend;
its secret/raw fields are public witness evidence even if finality is unknown.
No missing RPC result is evidence of nonexecution. A spent observation identifies
no winner; a witness mismatch is conflict even when the stripped txid is equal.
All RPC evidence is from the supplied node, not independent Bitcoin consensus
verification. Require an authenticated, independently operated validating node.
"""

from dataclasses import dataclass
from decimal import Decimal, DecimalException
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MAX_MONEY = 21_000_000 * 100_000_000
KINDS = ("foreign-claim", "foreign-refund")


def sha(value):
    return hashlib.sha256(value).digest()


def dsha(value):
    return sha(sha(value))


def _u32(value):
    return struct.pack("<I", value)


def _u64(value):
    return struct.pack("<Q", value)


def _compact(value):
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b"\xfd" + struct.pack("<H", value)
    return b"\xfe" + _u32(value)


def _push(value):
    if len(value) > 75:
        raise ValueError("only minimal short pushes")
    return bytes([len(value)]) + value


def pubkey(key):
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid " + name)
    return value


def _hex(value, size, name):
    if not isinstance(value, str) or value != value.lower():
        raise ValueError("noncanonical " + name)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("invalid " + name) from exc
    if raw.hex() != value or (size is not None and len(raw) != size):
        raise ValueError("invalid " + name)
    return raw


def _destination(value):
    raw = _hex(value, None, "destination script")
    allowed = (
        len(raw) == 22 and raw[:2] == b"\x00\x14",
        len(raw) == 34 and raw[:2] in (b"\x00\x20", b"\x51\x20"),
        len(raw) == 25 and raw[:3] == b"\x76\xa9\x14" and raw[-2:] == b"\x88\xac",
        len(raw) == 23 and raw[:2] == b"\xa9\x14" and raw[-1:] == b"\x87",
    )
    if not any(allowed):
        raise ValueError("destination must be a supported standard payment script")
    return raw


@dataclass(frozen=True)
class Contract:
    genesis_hash: str
    hashlock: bytes
    claim_pubkey: bytes
    refund_pubkey: bytes
    refund_height: int
    funding_txid: str
    funding_vout: int
    funding_value_sats: int
    claim_script: bytes
    refund_script: bytes
    fee_sats: int
    min_confirmations: int
    funding_blockhash: str | None = None

    @classmethod
    def parse(cls, terms):
        if not isinstance(terms, dict):
            raise ValueError("contract must be a mapping")
        required = set(cls.__dataclass_fields__) - {"funding_blockhash"}
        if set(terms) - set(cls.__dataclass_fields__) or required - set(terms):
            raise ValueError("unexpected or missing contract fields")
        genesis = _hex(terms["genesis_hash"], 32, "genesis hash").hex()
        txid = _hex(terms["funding_txid"], 32, "funding txid").hex()
        hashlock = _hex(terms["hashlock"], 32, "hashlock")
        roles = []
        for name in ("claim_pubkey", "refund_pubkey"):
            key = _hex(terms[name], 33, name)
            if key[0] not in (2, 3):
                raise ValueError("compressed role key required")
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), key)
            roles.append(key)
        if roles[0] == roles[1]:
            raise ValueError("claim and refund roles must differ")
        height = _integer(terms["refund_height"], 17, 499_999_999, "refund height")
        vout = _integer(terms["funding_vout"], 0, 2**32 - 1, "funding vout")
        value = _integer(terms["funding_value_sats"], 547, MAX_MONEY, "funding value")
        fee = _integer(terms["fee_sats"], 1, value - 546, "fee")
        confirmations = _integer(terms["min_confirmations"], 1, 1_000_000, "confirmations")
        block = terms.get("funding_blockhash")
        if block is not None:
            block = _hex(block, 32, "funding block hash").hex()
        return cls(genesis, hashlock, *roles, height, txid, vout, value,
                   _destination(terms["claim_script"]), _destination(terms["refund_script"]),
                   fee, confirmations, block)

    def script(self):
        height = self.refund_height.to_bytes((self.refund_height.bit_length() + 7) // 8, "little")
        height += b"\0" if height[-1] & 128 else b""
        # Exact donor script: IF SIZE 32 EQUALVERIFY SHA256 H EQUALVERIFY A
        # CHECKSIG ELSE Ht CLTV DROP B CHECKSIG ENDIF.
        return (b"\x63\x82" + _push(b"\x20") + b"\x88\xa8" + _push(self.hashlock)
                + b"\x88" + _push(self.claim_pubkey) + b"\xac\x67" + _push(height)
                + b"\xb1\x75" + _push(self.refund_pubkey) + b"\xac\x68")

    def output_script(self):
        return b"\x00\x20" + sha(self.script())


class _Reader:
    def __init__(self, raw):
        self.raw = raw
        self.at = 0

    def take(self, count):
        if count < 0 or self.at + count > len(self.raw):
            raise ValueError("truncated transaction")
        result = self.raw[self.at:self.at + count]
        self.at += count
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), "little")

    def compact(self, maximum):
        lead = self.integer(1)
        size = {253: 2, 254: 4, 255: 8}.get(lead)
        value = self.integer(size) if size else lead
        if (size and value < {2: 253, 4: 65536, 8: 2**32}[size]) or value > maximum:
            raise ValueError("noncanonical or oversized compact size")
        return value

    def blob(self, maximum=100_000):
        return self.take(self.compact(maximum))


def _parse(raw):
    """Strict bounded wire parser, independent of RPC decoderawtransaction."""
    if not isinstance(raw, bytes) or not 10 <= len(raw) <= 1_000_000:
        raise ValueError("invalid transaction bytes")
    r = _Reader(raw)
    version = r.integer(4)
    segwit = raw[4:5] == b"\0"
    if segwit and r.take(2) != b"\0\x01":
        raise ValueError("unsupported witness flags")
    start = r.at
    count = r.compact(20_000)
    if not count:
        raise ValueError("empty input set")
    inputs = []
    for _ in range(count):
        inputs.append((r.take(32)[::-1].hex(), r.integer(4), r.blob(10_000), r.integer(4)))
    outputs = []
    for _ in range(r.compact(20_000)):
        outputs.append((r.integer(8), r.blob(10_000)))
    body = raw[start:r.at]
    witnesses = []
    if segwit:
        for _ in inputs:
            witnesses.append([r.blob() for _ in range(r.compact(1000))])
        if not any(witnesses):
            raise ValueError("superfluous witness record")
    locktime = r.integer(4)
    if r.at != len(raw):
        raise ValueError("trailing transaction bytes")
    stripped = _u32(version) + body + _u32(locktime)
    return {"version": version, "segwit": segwit, "inputs": inputs, "outputs": outputs,
            "witnesses": witnesses, "locktime": locktime,
            "txid": dsha(stripped)[::-1].hex(), "wtxid": dsha(raw)[::-1].hex(),
            "vsize": (len(stripped) * 3 + len(raw) + 3) // 4}


def _digest(contract, destination, locktime):
    previous = bytes.fromhex(contract.funding_txid)[::-1] + _u32(contract.funding_vout)
    sequence = _u32(0xfffffffe)
    script = contract.script()
    output = _u64(contract.funding_value_sats - contract.fee_sats) + _compact(len(destination)) + destination
    return dsha(_u32(2) + dsha(previous) + dsha(sequence) + previous
                + _compact(len(script)) + script + _u64(contract.funding_value_sats)
                + sequence + dsha(output) + _u32(locktime) + _u32(1))


class _Unavailable(Exception):
    pass


class BitcoinAdapter:
    def __init__(self, rpc, terms):
        if not callable(rpc):
            raise ValueError("RPC must be callable")
        self._rpc = rpc
        self.contract = Contract.parse(terms)

    def expected_txid(self, kind):
        if kind not in KINDS:
            raise ValueError("unknown spend kind")
        c = self.contract
        claim = kind == "foreign-claim"
        destination = c.claim_script if claim else c.refund_script
        vin = b"\x01" + bytes.fromhex(c.funding_txid)[::-1] + _u32(c.funding_vout) + b"\0" + _u32(0xfffffffe)
        output = b"\x01" + _u64(c.funding_value_sats - c.fee_sats) + _compact(len(destination)) + destination
        return dsha(_u32(2) + vin + output + _u32(0 if claim else c.refund_height))[::-1].hex()

    def prepare(self, kind, key, secret=None):
        c = self.contract
        if kind not in KINDS:
            raise ValueError("unknown spend kind")
        claim = kind == "foreign-claim"
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256K1):
            raise ValueError("secp256k1 private key required")
        if pubkey(key) != (c.claim_pubkey if claim else c.refund_pubkey):
            raise ValueError("wrong signing role")
        if claim:
            if not isinstance(secret, bytes) or len(secret) != 32 or sha(secret) != c.hashlock:
                raise ValueError("incorrect preimage")
        elif secret is not None:
            raise ValueError("refund must not contain a preimage")
        destination = c.claim_script if claim else c.refund_script
        locktime = 0 if claim else c.refund_height
        signature = key.sign(_digest(c, destination, locktime), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(signature)
        signature = utils.encode_dss_signature(r, min(s, N - s)) + b"\x01"
        stack = [signature, secret, b"\x01", c.script()] if claim else [signature, b"", c.script()]
        vin = b"\x01" + bytes.fromhex(c.funding_txid)[::-1] + _u32(c.funding_vout) + b"\0" + _u32(0xfffffffe)
        output = b"\x01" + _u64(c.funding_value_sats - c.fee_sats) + _compact(len(destination)) + destination
        raw = (_u32(2) + b"\0\x01" + vin + output + _compact(len(stack))
               + b"".join(_compact(len(item)) + item for item in stack) + _u32(locktime))
        txid = dsha(_u32(2) + vin + output + _u32(locktime))[::-1].hex()
        self.validate(kind, raw, txid)
        return raw, txid

    def validate(self, kind, raw, txid):
        if kind not in KINDS or not isinstance(raw, bytes) or len(raw) > 1024:
            raise ValueError("invalid spend")
        _hex(txid, 32, "txid")
        c, parsed = self.contract, _parse(raw)
        claim = kind == "foreign-claim"
        destination = c.claim_script if claim else c.refund_script
        locktime = 0 if claim else c.refund_height
        if (parsed["txid"] != txid or parsed["version"] != 2 or not parsed["segwit"]
                or parsed["inputs"] != [(c.funding_txid, c.funding_vout, b"", 0xfffffffe)]
                or parsed["outputs"] != [(c.funding_value_sats - c.fee_sats, destination)]
                or parsed["locktime"] != locktime):
            raise ValueError("wire does not match pinned transaction terms")
        stack = parsed["witnesses"][0]
        if claim:
            if (len(stack) != 4 or len(stack[1]) != 32 or sha(stack[1]) != c.hashlock
                    or stack[2] != b"\x01" or stack[3] != c.script()):
                raise ValueError("invalid claim witness")
        elif len(stack) != 3 or stack[1] != b"" or stack[2] != c.script():
            raise ValueError("invalid refund witness")
        signature = stack[0]
        if not 9 <= len(signature) <= 73 or signature[-1] != 1:
            raise ValueError("strict DER SIGHASH_ALL signature required")
        try:
            r, s = utils.decode_dss_signature(signature[:-1])
            if not 1 <= r < N or not 1 <= s <= N // 2 or utils.encode_dss_signature(r, s) != signature[:-1]:
                raise ValueError("noncanonical ECDSA signature")
            role = c.claim_pubkey if claim else c.refund_pubkey
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), role)
            key.verify(signature[:-1], _digest(c, destination, locktime),
                       ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except InvalidSignature as exc:
            raise ValueError("incorrect BIP143 role signature") from exc
        result = {"kind": kind, "txid": txid, "wtxid": parsed["wtxid"], "fee_sats": c.fee_sats,
                  "amount_sats": c.funding_value_sats - c.fee_sats,
                  "destination_script": destination.hex(), "vsize": parsed["vsize"]}
        if claim:
            result["secret"] = stack[1].hex()
        return result

    def _call(self, method, params):
        try:
            return self._rpc(method, params)
        except Exception as exc:
            # Do not expose credentials/response bodies through an observation.
            raise _Unavailable("RPC call failed: " + method) from exc

    def _snapshot(self):
        c = self.contract
        if self._call("getblockhash", [0]) != c.genesis_hash:
            raise _Unavailable("genesis mismatch")
        info = self._call("getblockchaininfo", [])
        if not isinstance(info, dict) or info.get("initialblockdownload") is not False:
            raise _Unavailable("node is not synchronized")
        tip = _hex(info.get("bestblockhash"), 32, "best block hash").hex()
        height = _integer(info.get("blocks"), 0, 2**32 - 1, "chain height")
        headers = _integer(info.get("headers"), 0, 2**32 - 1, "headers")
        if headers != height:
            raise _Unavailable("node headers and blocks disagree")
        return tip, height

    def _stable(self, snapshot):
        if self._snapshot() != snapshot:
            raise _Unavailable("chain tip changed during observation")

    def _included(self, block, snapshot):
        block = _hex(block, 32, "inclusion block hash").hex()
        header = self._call("getblockheader", [block, True])
        if not isinstance(header, dict) or header.get("hash") != block:
            raise _Unavailable("malformed inclusion header")
        height = _integer(header.get("height"), 0, snapshot[1], "inclusion height")
        confirmations = snapshot[1] - height + 1
        if header.get("confirmations") != confirmations or self._call("getblockhash", [height]) != block:
            raise _Unavailable("inclusion is not in the current best chain")
        return block, confirmations

    def _transaction(self, txid, block=None):
        params = [txid, True] + ([block] if block else [])
        result = self._call("getrawtransaction", params)
        if not isinstance(result, dict):
            raise _Unavailable("transaction unavailable")
        raw = _hex(result.get("hex"), None, "RPC transaction bytes")
        parsed = _parse(raw)
        if parsed["txid"] != txid or result.get("txid") != txid or result.get("hash") != parsed["wtxid"]:
            raise _Unavailable("RPC transaction identity mismatch")
        return result, parsed, raw

    def observe(self):
        c = self.contract
        base = {"status": "unknown", "confirmations": 0, "height": None,
                "block_hash": None, "genesis_hash": c.genesis_hash,
                "refund_eligible": False, "final": False}
        try:
            snapshot = self._snapshot()
            base["height"] = snapshot[1]
            utxo = self._call("gettxout", [c.funding_txid, c.funding_vout, True])
            if utxo is not None:
                if not isinstance(utxo, dict) or utxo.get("bestblock") != snapshot[0]:
                    raise _Unavailable("UTXO snapshot mismatch")
                amount = utxo.get("value")
                # Binary floats are not safe evidence for satoshi equality.
                if not isinstance(amount, (str, Decimal, int)) or isinstance(amount, bool):
                    raise _Unavailable("RPC amounts must be parsed as Decimal")
                sats = Decimal(amount) * Decimal(100_000_000)
                if not sats.is_finite() or sats != c.funding_value_sats:
                    raise _Unavailable("funding amount mismatch")
                if utxo.get("scriptPubKey", {}).get("hex") != c.output_script().hex():
                    raise _Unavailable("funding script mismatch")
                confirmations = _integer(utxo.get("confirmations"), 0, snapshot[1] + 1, "confirmations")
                # Require confirmed funding to independently bind amount/script to
                # an exact transaction and a block in the current best chain.
                info, parsed, _ = self._transaction(c.funding_txid, c.funding_blockhash)
                if c.funding_vout >= len(parsed["outputs"]) or parsed["outputs"][c.funding_vout] != (c.funding_value_sats, c.output_script()):
                    raise _Unavailable("funding transaction output mismatch")
                if confirmations:
                    block, actual = self._included(info.get("blockhash"), snapshot)
                    if actual != confirmations or info.get("confirmations") != actual:
                        raise _Unavailable("funding confirmation mismatch")
                else:
                    block = None
                    if info.get("blockhash") or info.get("confirmations", 0) != 0:
                        raise _Unavailable("inconsistent unconfirmed funding")
                self._stable(snapshot)
                return dict(base, status="unspent", confirmations=confirmations, block_hash=block,
                            final=confirmations >= c.min_confirmations,
                            refund_eligible=snapshot[1] >= c.refund_height and confirmations >= c.min_confirmations)
            info, parsed, _ = self._transaction(c.funding_txid, c.funding_blockhash)
            if c.funding_vout >= len(parsed["outputs"]) or parsed["outputs"][c.funding_vout] != (c.funding_value_sats, c.output_script()):
                raise _Unavailable("funding transaction output mismatch")
            block, confirmations = self._included(info.get("blockhash"), snapshot)
            if info.get("confirmations") != confirmations:
                raise _Unavailable("funding confirmation mismatch")
            self._stable(snapshot)
            return dict(base, status="spent", block_hash=block, confirmations=confirmations,
                        reason="confirmed funding has no UTXO; spender and outcome remain unidentified")
        except (_Unavailable, ValueError, TypeError, DecimalException, AttributeError) as exc:
            return dict(base, reason=str(exc))

    def receipt(self, kind, raw, txid):
        checked = self.validate(kind, raw, txid)
        c = self.contract
        base = {"status": "unknown", "confirmations": 0, "height": None,
                "block_hash": None, "genesis_hash": c.genesis_hash, "refund_eligible": False,
                "txid": txid, "wtxid": checked["wtxid"], "final": False}
        try:
            snapshot = self._snapshot()
            base["height"] = snapshot[1]
            info, _, found = self._transaction(txid)
            if found != raw:
                return dict(base, status="conflict", reason="txid matches but full witness bytes differ")
            if info.get("blockhash"):
                block, confirmations = self._included(info["blockhash"], snapshot)
                if info.get("confirmations") != confirmations:
                    raise _Unavailable("spend confirmation mismatch")
                # A claimed confirmed spend cannot coexist with its funding UTXO
                # in either chain or mempool. Null alone is never a receipt.
                if self._call("gettxout", [c.funding_txid, c.funding_vout, False]) is not None:
                    raise _Unavailable("confirmed spend contradicts funding UTXO")
                self._stable(snapshot)
                return dict(base, status="confirmed", confirmations=confirmations, block_hash=block,
                            final=confirmations >= c.min_confirmations, publicly_observed=True)
            if info.get("confirmations", 0) != 0:
                raise _Unavailable("unconfirmed transaction has inconsistent confirmations")
            entry = self._call("getmempoolentry", [txid])
            if not isinstance(entry, dict) or entry.get("wtxid") != checked["wtxid"]:
                raise _Unavailable("mempool witness identity mismatch")
            if self._call("gettxout", [c.funding_txid, c.funding_vout, True]) is not None:
                raise _Unavailable("mempool spend contradicts funding UTXO")
            self._stable(snapshot)
            return dict(base, status="pending", publicly_observed=True)
        except (_Unavailable, ValueError, TypeError, AttributeError) as exc:
            return dict(base, reason=str(exc))

    def send(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        # Genesis/synchronization checks prevent a valid spend reaching a wrong
        # RPC network. The durable coordinator handles receipt-before-retry.
        self._snapshot()
        result = self._call("sendrawtransaction", [raw.hex()])
        if result != txid:
            raise _Unavailable("broadcast acknowledgment does not match txid")
        return result

    def verify_public_spend(self, candidate_txid, kind):
        """Bounded lookup, no chain scan; persist any validated revealed secret.

        A valid witness establishes secret exposure, not confirmation/finality.
        Only the receipt's status/final fields establish its current chain state.
        The fixed terms exclude arbitrary fee/destination replacements.
        """
        if candidate_txid != self.expected_txid(kind):
            raise ValueError("candidate does not match agreed stripped transaction")
        try:
            self._snapshot()
            _, _, raw = self._transaction(candidate_txid)
            checked = self.validate(kind, raw, candidate_txid)
        except (_Unavailable, ValueError, TypeError, AttributeError) as exc:
            return {"status": "unknown", "kind": kind, "txid": candidate_txid,
                    "final": False, "reason": str(exc)}
        result = self.receipt(kind, raw, candidate_txid)
        result.update(kind=kind, raw=raw.hex())
        if "secret" in checked:
            result["secret"] = checked["secret"]
        return result
