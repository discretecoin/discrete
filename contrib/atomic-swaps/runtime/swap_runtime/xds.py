"""Bounded native XDS observation and settlement through an authenticated wallet.

The current native v1 profile fixes the exit fee at one atom (0.01 XDS).
Contract terms pin the full funding wire and both wallet addresses. Pure wire
validation checks the complete SHA3 transaction ID, funding contract, role
commitment, ML-DSA-65 signature, hashlock, and single PQ payout amount. The role
holder's signature authorizes that encrypted payout; publicly proving its
recipient requires decryption and remains the authenticated native wallet's
responsibility. No keys are exported. Native wallet preparation currently
requires the explicitly enabled isolated laboratory; this adapter does not
enable signing or consensus activation on another network.

All chain state is evidence from the supplied validating daemon. ``final`` is
the configured confirmation threshold, not a cross-chain finality guarantee.
Missing or inconsistent RPC evidence is always unknown. Valid public claim
witnesses remain exposure evidence even when their chain receipt is unknown.
"""

from dataclasses import dataclass
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa


KINDS = ("xds-claim", "xds-refund")
TX_PQ = 0x01
TX_PQ_V2 = 0x04
TX_SWAP_FUND = 0x06
TX_SWAP_SPEND = 0x05
SPEND_DOMAIN = b"discrete-pq-spend-commit-v1"
SIGN_DOMAIN = b"discrete-swap-tx-sign-v1\0"
TAG_DOMAIN = b"XDS/SwapSpent/v1\0"


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid " + name)
    return value


def _hex(value, size, name):
    if not isinstance(value, str) or len(value) > (2 * size if size is not None else 131072) or value != value.lower():
        raise ValueError("noncanonical " + name)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("invalid " + name) from exc
    if raw.hex() != value or (size is not None and len(raw) != size):
        raise ValueError("invalid " + name)
    return raw


def _h(value):
    # Discrete's cn_fast_hash was replaced with FIPS 202 SHA3, not Keccak.
    return hashlib.sha3_256(value).digest()


def _commit(pub, rho):
    # PqDerive excludes the domain NUL; SwapValidation includes it above.
    return _h(SPEND_DOMAIN + pub + rho)


def _kind(kind):
    if kind not in KINDS:
        raise ValueError("unsupported XDS intent")
    return 1 if kind == "xds-claim" else 2


class _Reader:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def take(self, count):
        if self.at + count > len(self.raw):
            raise ValueError("truncated XDS transaction")
        data = self.raw[self.at:self.at + count]
        self.at += count
        return data

    def var(self, bits=64):
        value = 0
        for shift in range(0, bits, 7):
            byte = self.take(1)[0]
            value |= (byte & 127) << shift
            if not byte & 128:
                if (shift and byte == 0) or value >= 1 << bits:
                    raise ValueError("noncanonical XDS varint")
                return value
        raise ValueError("oversized XDS varint")


def _parse(raw):
    """Parse only the exact bounded native v1 swap family; no generic decoder."""
    if not isinstance(raw, bytes) or not 8 <= len(raw) <= 65536:
        raise ValueError("invalid XDS wire length")
    r = _Reader(raw)
    version, family, unlock = r.var(8), r.var(8), r.var()
    if version != 1 or family not in (TX_SWAP_FUND, TX_SWAP_SPEND) or unlock:
        raise ValueError("unsupported XDS family/version/lock")
    count = r.var()
    if not 1 <= count <= (8 if family == TX_SWAP_FUND else 1):
        raise ValueError("invalid XDS input count")
    inputs = []
    for _ in range(count):
        if r.take(1)[0] != (0x10 if family == TX_SWAP_FUND else 0x20):
            raise ValueError("invalid XDS input type")
        prev, index = r.take(32), r.var(32)
        branch = r.var(8) if family == TX_SWAP_SPEND else None
        if family == TX_SWAP_SPEND and branch not in (1, 2):
            raise ValueError("invalid XDS branch")
        pub, rho = r.take(1952), r.take(32)
        secret = r.take(32) if branch == 1 else b""
        inputs.append(dict(prev=prev, index=index, branch=branch, pub=pub, rho=rho, secret=secret))
    count = r.var()
    if not 1 <= count <= 2:
        raise ValueError("invalid XDS output count")
    outputs = []
    for _ in range(count):
        start = r.at
        amount, lock, tag = r.var(), r.var(), r.take(1)[0]
        if not amount or lock:
            raise ValueError("invalid XDS output amount/lock")
        output = dict(amount=amount, tag=tag)
        if tag == 0x12 and family == TX_SWAP_FUND:
            if tuple(r.var(8) for _ in range(4)) != (1, 1, 1, 1):
                raise ValueError("unsupported XDS contract policy")
            for field in ("nonce", "hashlock", "claim_commitment", "refund_commitment"):
                output[field] = r.take(32)
            output["refund_height"] = r.var(32)
            if not output["refund_height"] or amount <= 1:
                raise ValueError("unspendable XDS contract")
        elif tag == 0x10:
            output.update(kem=r.take(1088), ciphertext=r.take(56), commitment=r.take(32))
        else:
            raise ValueError("invalid XDS output type")
        output["wire"] = raw[start:r.at]
        outputs.append(output)
    if sum(o["tag"] == 0x12 for o in outputs) != (1 if family == TX_SWAP_FUND else 0):
        raise ValueError("invalid XDS contract count")
    prefix = raw[:r.at]
    signatures = [r.take(3309) for _ in inputs]
    if r.at != len(raw):
        raise ValueError("trailing XDS transaction bytes")
    return dict(family=family, inputs=inputs, outputs=outputs, prefix=prefix,
                signatures=signatures, txid=_h(raw).hex())


@dataclass(frozen=True)
class Contract:
    genesis_hash: str
    hashlock: bytes
    nonce: bytes
    claim_commitment: bytes
    refund_commitment: bytes
    claim_address: str
    refund_address: str
    refund_height: int
    funding_txid: str
    funding_vout: int
    funding_value_atoms: int
    fee_atoms: int
    min_confirmations: int
    funding_wire: bytes

    @classmethod
    def parse(cls, terms):
        if not isinstance(terms, dict) or set(terms) != set(cls.__dataclass_fields__):
            raise ValueError("missing or unexpected XDS contract fields")
        values = dict(terms)
        for key in ("genesis_hash", "funding_txid"):
            values[key] = _hex(values[key], 32, key).hex()
        for key in ("hashlock", "nonce", "claim_commitment", "refund_commitment"):
            values[key] = _hex(values[key], 32, key)
        for key in ("claim_address", "refund_address"):
            address = values[key]
            if not isinstance(address, str) or not 1 <= len(address) <= 8192 or not address.isascii() or any(c.isspace() for c in address):
                raise ValueError("invalid agreed XDS wallet address")
        if values["claim_commitment"] == values["refund_commitment"] or values["claim_address"] == values["refund_address"]:
            raise ValueError("XDS roles must differ")
        for key, low, high in (("refund_height", 1, 2**32 - 1), ("funding_vout", 0, 1),
                               ("funding_value_atoms", 2, 2**64 - 2), ("fee_atoms", 1, 1),
                               ("min_confirmations", 1, 1_000_000)):
            values[key] = _integer(values[key], low, high, key)
        values["funding_wire"] = _hex(values["funding_wire"], None, "funding wire")
        contract = cls(**values)
        parsed = _parse(contract.funding_wire)
        if parsed["family"] != TX_SWAP_FUND or parsed["txid"] != contract.funding_txid or contract.funding_vout >= len(parsed["outputs"]):
            raise ValueError("XDS funding identity mismatch")
        output = parsed["outputs"][contract.funding_vout]
        if output["tag"] != 0x12 or output["amount"] != contract.funding_value_atoms:
            raise ValueError("XDS funding output mismatch")
        for key in ("hashlock", "nonce", "claim_commitment", "refund_commitment", "refund_height"):
            if output[key] != getattr(contract, key):
                raise ValueError("XDS funding contract mismatch: " + key)
        return contract


class _Unavailable(Exception):
    pass


class XdsAdapter:
    def __init__(self, rpc, terms, wallet=None):
        self._rpc, self._wallet = rpc, wallet
        self.contract = Contract.parse(terms)
        self._funding_output = _parse(self.contract.funding_wire)["outputs"][self.contract.funding_vout]["wire"]

    def validate(self, kind, raw, txid):
        branch = _kind(kind)
        txid = _hex(txid, 32, "transaction id").hex()
        tx, c = _parse(raw), self.contract
        if tx["family"] != TX_SWAP_SPEND or tx["txid"] != txid or len(tx["outputs"]) != 1:
            raise ValueError("XDS settlement identity/shape mismatch")
        item, output = tx["inputs"][0], tx["outputs"][0]
        expected = c.claim_commitment if branch == 1 else c.refund_commitment
        if (item["prev"].hex() != c.funding_txid or item["index"] != c.funding_vout
                or item["branch"] != branch or _commit(item["pub"], item["rho"]) != expected):
            raise ValueError("XDS funding outpoint or role mismatch")
        if branch == 1 and hashlib.sha256(item["secret"]).digest() != c.hashlock:
            raise ValueError("XDS claim hashlock mismatch")
        if output["amount"] != c.funding_value_atoms - c.fee_atoms:
            raise ValueError("XDS settlement amount/fee mismatch")
        transcript = (SIGN_DOMAIN + bytes.fromhex(c.genesis_hash) + struct.pack("<I", 0)
                      + struct.pack("<I", len(tx["prefix"])) + tx["prefix"] + struct.pack("<I", 1)
                      + struct.pack("<I", len(self._funding_output)) + self._funding_output
                      + struct.pack("<Q", c.fee_atoms))
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(item["pub"]).verify(tx["signatures"][0], _h(transcript))
        except InvalidSignature as exc:
            raise ValueError("invalid XDS role signature") from exc
        result = dict(kind=kind, txid=txid, fee_atoms=c.fee_atoms,
                      amount_atoms=output["amount"], payout_commitment=output["commitment"].hex())
        if branch == 1:
            result["secret"] = item["secret"].hex()
        return result

    def _call(self, method, params, wallet=False):
        try:
            selected = self._wallet if wallet else self._rpc
            if selected is None:
                raise _Unavailable("native signing wallet is not configured")
            return selected(method, params)
        except Exception:
            # A transport exception can contain an authenticated URL or body.
            raise _Unavailable("XDS RPC call failed: " + method) from None

    def _info(self):
        info = self._call("getinfo", {})
        if not isinstance(info, dict) or info.get("status") != "OK" or info.get("finality_fork_warning") is not False:
            raise _Unavailable("XDS daemon unavailable or finality fork warning")
        height = _integer(info.get("height"), 1, 2**32 - 1, "XDS height")
        tip = _hex(info.get("top_block_hash"), 32, "XDS tip").hex()
        if _integer(info.get("last_known_block_index"), 0, 2**32 - 1, "known block index") >= height:
            raise _Unavailable("XDS daemon is behind known network height")
        if _integer(info.get("min_fee"), 1, 2**64 - 1, "native minimum fee") != self.contract.fee_atoms:
            raise _Unavailable("XDS fee policy differs from fixed contract")
        return height, tip

    def _outpoint(self, txid, index, snapshot):
        state = self._call("get_swap_outpoint", dict(txid=txid, index=index, spend_tag=""))
        if not isinstance(state, dict) or state.get("status") != "OK":
            raise _Unavailable("XDS outpoint unavailable")
        if state.get("genesis_hash") != self.contract.genesis_hash:
            raise _Unavailable("XDS genesis mismatch")
        if (state.get("height"), state.get("tip_hash")) != snapshot:
            raise _Unavailable("XDS outpoint snapshot mismatch")
        for field in ("found", "in_chain", "in_pool", "spent_known", "spent", "spent_in_pool"):
            if type(state.get(field)) is not bool:
                raise _Unavailable("malformed XDS state flags")
        _integer(state.get("height"), 1, 2**32 - 1, "outpoint height")
        confirmations = _integer(state.get("confirmations"), 0, snapshot[0], "XDS confirmations")
        if state["in_chain"]:
            height = _integer(state.get("block_height"), 0, snapshot[0] - 1, "XDS inclusion height")
            _hex(state.get("block_hash"), 32, "XDS inclusion block")
            if state["in_pool"] or confirmations != snapshot[0] - height:
                raise _Unavailable("XDS inclusion inconsistency")
        elif confirmations or state.get("block_hash"):
            raise _Unavailable("XDS unconfirmed inclusion inconsistency")
        if state["found"]:
            wire = _hex(state.get("tx_as_hex"), None, "observed XDS wire")
            parsed = _parse(wire)
            if parsed["txid"] != txid or index >= len(parsed["outputs"]):
                raise _Unavailable("XDS observed transaction identity mismatch")
            if _integer(state.get("amount_atoms"), 1, 2**64 - 1, "observed amount") != parsed["outputs"][index]["amount"]:
                raise _Unavailable("XDS observed amount mismatch")
        return state

    def _funding(self, snapshot):
        c = self.contract
        state = self._outpoint(c.funding_txid, c.funding_vout, snapshot)
        if not state["found"] or not state["in_chain"] or not state["spent_known"]:
            raise _Unavailable("XDS funding is not confirmed with known spentness")
        tag = _h(TAG_DOMAIN + bytes.fromhex(c.genesis_hash) + bytes.fromhex(c.funding_txid)
                 + struct.pack("<I", c.funding_vout)).hex()
        if state.get("tx_as_hex") != c.funding_wire.hex() or state.get("spend_tag") != tag:
            raise _Unavailable("XDS funding wire or spend-tag mismatch")
        return state

    def _stable(self, snapshot):
        if self._info() != snapshot:
            raise _Unavailable("XDS chain changed during observation")

    def observe(self):
        c = self.contract
        base = dict(status="unknown", confirmations=0, height=None, block_hash=None, tip_hash=None,
                    genesis_hash=c.genesis_hash, refund_eligible=False, final=False, fees_ready=False)
        try:
            snapshot = self._info()
            state = self._funding(snapshot)
            self._stable(snapshot)
            spent = state["spent"] or state["spent_in_pool"]
            final = state["confirmations"] >= c.min_confirmations and not spent
            return dict(base, status="spent" if spent else "unspent", confirmations=state["confirmations"],
                        height=snapshot[0], block_hash=state["block_hash"], tip_hash=snapshot[1], final=final,
                        refund_eligible=final and snapshot[0] >= c.refund_height, fees_ready=not spent)
        except (_Unavailable, ValueError, TypeError, AttributeError) as exc:
            return dict(base, reason=str(exc))

    def prepare(self, kind, rho, secret=None):
        branch, c = _kind(kind), self.contract
        if not isinstance(rho, bytes) or len(rho) != 32:
            raise ValueError("XDS role rho must be 32 bytes")
        if branch == 1:
            if not isinstance(secret, bytes) or len(secret) != 32 or hashlib.sha256(secret).digest() != c.hashlock:
                raise ValueError("XDS claim secret mismatch")
        elif secret is not None:
            raise ValueError("XDS refund must not carry a secret")
        role = self._call("swap_role", {"rho": rho.hex()}, wallet=True)
        expected_commitment = c.claim_commitment if branch == 1 else c.refund_commitment
        expected_address = c.claim_address if branch == 1 else c.refund_address
        if not isinstance(role, dict) or role.get("genesis_hash") != c.genesis_hash or role.get("commitment") != expected_commitment.hex() or role.get("address") != expected_address:
            raise ValueError("native wallet network/role/address mismatch")
        observed = self.observe()
        if observed["status"] != "unspent" or not observed["final"] or (branch == 2 and not observed["refund_eligible"]):
            raise _Unavailable("XDS funding is not eligible for requested preparation")
        prepared = self._call("swap_prepare_spend", dict(funding_txid=c.funding_txid, output_index=c.funding_vout,
            branch=branch, rho=rho.hex(), secret=secret.hex() if branch == 1 else "", genesis_hash=c.genesis_hash), wallet=True)
        if not isinstance(prepared, dict) or type(prepared.get("fee_atoms")) is not int or prepared.get("fee_atoms") != c.fee_atoms or type(prepared.get("principal_atoms")) is not int or prepared.get("principal_atoms") != c.funding_value_atoms:
            raise ValueError("native wallet preparation amount/fee mismatch")
        wire = _hex(prepared.get("tx_as_hex"), None, "prepared XDS wire")
        txid = _hex(prepared.get("tx_hash"), 32, "prepared XDS txid").hex()
        self.validate(kind, wire, txid)
        item = _parse(wire)["inputs"][0]
        if item["rho"] != rho or (branch == 1 and item["secret"] != secret):
            raise ValueError("native wallet witness differs from request")
        return wire, txid

    def receipt(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        c = self.contract
        base = dict(status="unknown", confirmations=0, height=None, block_hash=None, tip_hash=None,
                    genesis_hash=c.genesis_hash, txid=txid, final=False, refund_eligible=False,
                    publicly_observed=False)
        try:
            snapshot = self._info()
            funding = self._funding(snapshot)
            state = self._outpoint(txid, 0, snapshot)
            if not state["found"] or state.get("tx_as_hex") != raw.hex():
                raise _Unavailable("exact XDS settlement not observed")
            if state["in_chain"]:
                if not funding["spent"]:
                    raise _Unavailable("XDS confirmed spend contradicts funding spentness")
                if _kind(kind) == 2 and state["block_height"] < c.refund_height:
                    raise _Unavailable("XDS refund inclusion predates its deadline")
                status = "confirmed"
            elif state["in_pool"] and funding["spent_in_pool"] and not funding["spent"]:
                status = "pending"
            else:
                raise _Unavailable("XDS settlement membership is inconsistent")
            self._stable(snapshot)
            return dict(base, status=status, height=snapshot[0], confirmations=state["confirmations"],
                        block_hash=state["block_hash"] or None, tip_hash=snapshot[1], publicly_observed=True,
                        final=status == "confirmed" and state["confirmations"] >= c.min_confirmations)
        except (_Unavailable, ValueError, TypeError, AttributeError) as exc:
            return dict(base, reason=str(exc))

    def send(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        prior = self.receipt(kind, raw, txid)
        if prior["status"] in ("pending", "confirmed"):
            return txid
        observed = self.observe()
        if observed["status"] != "unspent" or not observed["final"] or (kind == "xds-refund" and not observed["refund_eligible"]):
            raise _Unavailable("XDS funding unavailable before exact transmission")
        self._call("sendrawtransaction", {"tx_as_hex": raw.hex()})
        # A generic OK or duplicate response is not an exact-wire receipt.
        receipt = self.receipt(kind, raw, txid)
        if receipt["status"] not in ("pending", "confirmed"):
            raise _Unavailable("XDS transmission has no exact local receipt")
        return txid

    def verify_public_spend(self, candidate_txid, kind):
        _kind(kind)
        candidate_txid = _hex(candidate_txid, 32, "public XDS txid").hex()
        base = dict(status="unknown", kind=kind, txid=candidate_txid, final=False)
        try:
            # Validate the witness before interpreting mutable chain metadata.
            response = self._call("get_swap_outpoint", dict(txid=candidate_txid, index=0, spend_tag=""))
            if not isinstance(response, dict):
                raise _Unavailable("public XDS transaction unavailable")
            raw = _hex(response.get("tx_as_hex"), None, "public XDS wire")
            checked = self.validate(kind, raw, candidate_txid)
        except (_Unavailable, ValueError, TypeError, AttributeError) as exc:
            return dict(base, reason=str(exc))
        result = self.receipt(kind, raw, candidate_txid)
        result.update(kind=kind, raw=raw.hex())
        if "secret" in checked:
            result["secret"] = checked["secret"]
        return result
