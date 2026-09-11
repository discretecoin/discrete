import copy
import hashlib
import struct
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from swap_runtime.xds import XdsAdapter, Contract, _parse, _h, _commit, _Unavailable, SIGN_DOMAIN, TAG_DOMAIN


def var(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


class Fixture:
    def __init__(self):
        self.keys = [mldsa.MLDSA65PrivateKey.generate() for _ in range(2)]
        self.pubs = [key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) for key in self.keys]
        self.rhos = [bytes([20 + n]) * 32 for n in range(2)]
        self.secret = b"s" * 32
        self.terms = dict(genesis_hash="11" * 32, hashlock=hashlib.sha256(self.secret).hexdigest(),
            nonce="22" * 32, claim_commitment=_commit(self.pubs[0], self.rhos[0]).hex(),
            refund_commitment=_commit(self.pubs[1], self.rhos[1]).hex(), claim_address="claim-wallet",
            refund_address="refund-wallet", refund_height=80, funding_txid="", funding_vout=0,
            funding_value_atoms=1001, fee_atoms=1, min_confirmations=11, funding_wire="")
        self.output = (var(1001) + b"\0\x12\x01\x01\x01\x01" + bytes.fromhex(self.terms["nonce"])
                       + bytes.fromhex(self.terms["hashlock"]) + bytes.fromhex(self.terms["claim_commitment"])
                       + bytes.fromhex(self.terms["refund_commitment"]) + var(80))
        self.funding = (b"\x01\x06\0\x01\x10" + b"i" * 32 + b"\0" + self.pubs[1]
                        + self.rhos[1] + b"\x01" + self.output + b"\0" * 3309)
        self.terms.update(funding_wire=self.funding.hex(), funding_txid=_h(self.funding).hex())
        self.height = 30
        self.entries = {}
        self.sent = []
        self.lost_ack = False
        self.info_patch, self.funding_patch = {}, {}
        self.wallet_calls = []
        self.wallet_patch = {}
        self.adapter = XdsAdapter(self.rpc, self.terms, self.wallet)

    def wire(self, kind="xds-claim", amount=1000, output_count=1):
        index = 0 if kind == "xds-claim" else 1
        payout = var(amount) + b"\0\x10" + b"k" * 1088 + b"e" * 56 + b"c" * 32
        prefix = (b"\x01\x05\0\x01\x20" + bytes.fromhex(self.terms["funding_txid"]) + b"\0"
                  + bytes([index + 1]) + self.pubs[index] + self.rhos[index]
                  + (self.secret if index == 0 else b"") + var(output_count) + payout * output_count)
        transcript = (SIGN_DOMAIN + bytes.fromhex(self.terms["genesis_hash"]) + struct.pack("<I", 0)
                      + struct.pack("<I", len(prefix)) + prefix + struct.pack("<I", 1)
                      + struct.pack("<I", len(self.output)) + self.output + struct.pack("<Q", 1))
        raw = prefix + self.keys[index].sign(_h(transcript))
        return raw, _h(raw).hex()

    def state(self, wire=None, block=None):
        parsed = _parse(wire) if wire else None
        return dict(status="OK", height=self.height, tip_hash=_h(str(self.height).encode()).hex(),
            genesis_hash=self.terms["genesis_hash"], found=wire is not None, in_chain=block is not None,
            in_pool=wire is not None and block is None, spent_known=False, spent=False,
            spent_in_pool=False, block_height=block or 0, block_hash=_h(str(block).encode()).hex() if block is not None else "",
            confirmations=self.height - block if block is not None else 0,
            amount_atoms=parsed["outputs"][0]["amount"] if parsed else 0,
            tx_as_hex=wire.hex() if wire else "", spend_tag="")

    def rpc(self, method, params):
        if method == "getinfo":
            return dict(dict(status="OK", height=self.height, top_block_hash=_h(str(self.height).encode()).hex(),
                finality_fork_warning=False, last_known_block_index=self.height - 1, min_fee=1), **self.info_patch)
        if method == "get_swap_outpoint":
            if params["txid"] == self.terms["funding_txid"]:
                state = self.state(self.funding, 10)
                state.update(spent_known=True, spent=any(block is not None for _, block in self.entries.values()),
                    spent_in_pool=any(block is None for _, block in self.entries.values()),
                    spend_tag=_h(TAG_DOMAIN + bytes.fromhex(self.terms["genesis_hash"])
                        + bytes.fromhex(self.terms["funding_txid"]) + struct.pack("<I", 0)).hex())
                state.update(self.funding_patch)
                return state
            return self.state(*self.entries[params["txid"]]) if params["txid"] in self.entries else self.state()
        if method == "sendrawtransaction":
            raw = bytes.fromhex(params["tx_as_hex"])
            txid = _parse(raw)["txid"]
            self.sent.append(raw)
            self.entries[txid] = (raw, None)
            if self.lost_ack:
                self.lost_ack = False
                raise TimeoutError("https://user:password@private.invalid")
            return {"status": "OK"}
        raise AssertionError(method)

    def wallet(self, method, params):
        self.wallet_calls.append(method)
        if method == "swap_role":
            index = self.rhos.index(bytes.fromhex(params["rho"]))
            result = dict(genesis_hash=self.terms["genesis_hash"],
                commitment=_commit(self.pubs[index], self.rhos[index]).hex(),
                address=self.terms["claim_address" if index == 0 else "refund_address"])
        elif method == "swap_prepare_spend":
            raw, txid = self.wire("xds-claim" if params["branch"] == 1 else "xds-refund")
            result = dict(tx_as_hex=raw.hex(), tx_hash=txid, fee_atoms=1, principal_atoms=1001)
        else:
            raise AssertionError(method)
        result.update(self.wallet_patch)
        return result


class XdsTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.a = self.f.adapter

    def test_sha3_chain_id_uses_fips_padding(self):
        self.assertEqual(_h(b"").hex(), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        self.assertEqual(_parse(self.f.funding)["txid"], self.f.terms["funding_txid"])

    def test_funding_six_and_settlement_five_have_distinct_wire_families(self):
        self.assertEqual(_parse(self.f.funding)["family"], 0x06)
        self.assertEqual(Contract.parse(self.f.terms).funding_txid, self.f.terms["funding_txid"])
        for kind in ("xds-claim", "xds-refund"):
            raw, txid = self.f.wire(kind)
            self.assertEqual(_parse(raw)["family"], 0x05)
            self.assertEqual(self.a.validate(kind, raw, txid)["fee_atoms"], 1)

    def test_old_four_funding_is_rejected_even_with_rebound_identity(self):
        old = self.f.funding[:1] + b"\x04" + self.f.funding[2:]
        terms = dict(self.f.terms, funding_wire=old.hex(), funding_txid=_h(old).hex())
        with self.assertRaises(ValueError):
            _parse(old)
        with self.assertRaises(ValueError):
            Contract.parse(terms)
        self.assertEqual(self.f.sent, [])

    def test_both_roles_have_valid_signatures_and_exact_fee(self):
        for kind in ("xds-claim", "xds-refund"):
            raw, txid = self.f.wire(kind)
            result = self.a.validate(kind, raw, txid)
            self.assertEqual((result["fee_atoms"], result["amount_atoms"]), (1, 1000))
            self.assertEqual("secret" in result, kind == "xds-claim")

    def test_funding_wire_must_match_every_pinned_contract_field(self):
        for field in ("nonce", "hashlock", "claim_commitment", "refund_commitment", "funding_txid"):
            terms = dict(self.f.terms, **{field: "aa" * 32})
            with self.subTest(field=field), self.assertRaises(ValueError):
                Contract.parse(terms)
        for field, value in (("refund_height", 81), ("funding_value_atoms", 1002), ("funding_vout", 1),
                              ("fee_atoms", 2), ("fee_atoms", True), ("min_confirmations", 0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                Contract.parse(dict(self.f.terms, **{field: value}))
        with self.assertRaises(ValueError):
            Contract.parse(dict(self.f.terms, unexpected=1))

    def test_role_branch_genesis_signature_and_txid_cannot_be_substituted(self):
        raw, txid = self.f.wire()
        for kind, wire, identity in (("xds-refund", raw, txid), ("xds-claim", raw, "00" * 32),
            ("xds-claim", raw[:-1] + bytes([raw[-1] ^ 1]), _h(raw[:-1] + bytes([raw[-1] ^ 1])).hex())):
            with self.assertRaises(ValueError):
                self.a.validate(kind, wire, identity)
        wrong_chain = XdsAdapter(self.f.rpc, dict(self.f.terms, genesis_hash="44" * 32))
        with self.assertRaises(ValueError):
            wrong_chain.validate("xds-claim", raw, txid)

    def test_role_signed_bad_fee_or_split_payout_is_still_rejected(self):
        for kwargs in ({"amount": 999}, {"output_count": 2}):
            wire, identity = self.f.wire(**kwargs)
            with self.assertRaises(ValueError):
                self.a.validate("xds-claim", wire, identity)

    def test_canonical_varints_complete_length_and_bounded_counts(self):
        raw, _ = self.f.wire()
        for wire in (b"\x81\0" + raw[1:], raw + b"\0", raw[:3] + b"\x7f" + raw[4:], b"x" * 65537):
            with self.assertRaises(ValueError):
                _parse(wire)
        for length in range(len(raw)):
            with self.assertRaises(ValueError):
                _parse(raw[:length])

    def test_observe_requires_exact_funding_network_spentness_and_confirmations(self):
        observed = self.a.observe()
        self.assertEqual(observed["status"], "unspent")
        self.assertEqual(observed["tip_hash"], self.f.rpc("getinfo", {})["top_block_hash"])
        for patch in ({"genesis_hash": "44" * 32}, {"spent_known": False}, {"spend_tag": "44" * 32},
                      {"amount_atoms": 1002}, {"confirmations": 5}, {"in_pool": True}, {"spent": 1}):
            self.f.funding_patch = patch
            with self.subTest(patch=patch):
                self.assertEqual(self.a.observe()["status"], "unknown")

    def test_fork_lag_fee_drift_and_tip_change_fail_closed(self):
        for patch in ({"finality_fork_warning": True}, {"last_known_block_index": 31}, {"min_fee": 2}):
            self.f.info_patch = patch
            self.assertEqual(self.a.observe()["status"], "unknown")
        self.f.info_patch = {}
        original = self.f.rpc
        calls = 0
        def moving(method, params):
            nonlocal calls
            if method == "getinfo":
                calls += 1
                if calls == 2:
                    self.f.height += 1
            return original(method, params)
        self.assertEqual(XdsAdapter(moving, self.f.terms).observe()["status"], "unknown")

    def test_same_height_tip_replacement_cannot_look_like_a_stable_snapshot(self):
        original = self.f.rpc
        calls = 0
        def replacing(method, params):
            nonlocal calls
            response = original(method, params)
            if method == "getinfo":
                calls += 1
                if calls == 2:
                    response["top_block_hash"] = "99" * 32
            return response
        adapter = XdsAdapter(replacing, self.f.terms)
        observed = adapter.observe()
        self.assertEqual(observed["status"], "unknown")
        self.assertIsNone(observed["tip_hash"])
        raw, txid = self.f.wire()
        self.f.entries[txid] = (raw, None)
        calls = 0
        receipt = adapter.receipt("xds-claim", raw, txid)
        self.assertEqual(receipt["status"], "unknown")
        self.assertFalse(receipt["publicly_observed"])

    def test_prepare_checks_wallet_role_address_and_network_before_signing(self):
        for patch in ({"address": "another-wallet"}, {"genesis_hash": "44" * 32}, {"commitment": "44" * 32}):
            self.f.wallet_patch = patch
            self.f.wallet_calls.clear()
            with self.assertRaises(ValueError):
                self.a.prepare("xds-claim", self.f.rhos[0], self.f.secret)
            self.assertEqual(self.f.wallet_calls, ["swap_role"])

    def test_prepare_verifies_returned_wire_and_does_not_broadcast(self):
        raw, identity = self.a.prepare("xds-claim", self.f.rhos[0], self.f.secret)
        self.a.validate("xds-claim", raw, identity)
        self.assertEqual(self.f.sent, [])
        for patch in ({"tx_hash": "44" * 32}, {"fee_atoms": True}, {"principal_atoms": 1002}):
            self.f.wallet_patch = patch
            with self.assertRaises(ValueError):
                self.a.prepare("xds-claim", self.f.rhos[0], self.f.secret)

    def test_refund_prepare_obeys_current_height(self):
        with self.assertRaises(_Unavailable):
            self.a.prepare("xds-refund", self.f.rhos[1])
        self.f.height = 80
        self.assertTrue(self.a.observe()["refund_eligible"])
        raw, txid = self.a.prepare("xds-refund", self.f.rhos[1])
        self.a.validate("xds-refund", raw, txid)

    def test_lost_ack_reuses_exact_bytes_and_never_resigns_or_rebroadcasts_known_wire(self):
        raw, txid = self.f.wire()
        self.f.lost_ack = True
        with self.assertRaises(_Unavailable) as error:
            self.a.send("xds-claim", raw, txid)
        self.assertNotIn("password", str(error.exception))
        self.assertEqual(self.a.receipt("xds-claim", raw, txid)["status"], "pending")
        self.assertEqual(self.a.send("xds-claim", raw, txid), txid)
        self.assertEqual(self.f.sent, [raw])
        self.assertEqual(self.f.wallet_calls, [])

    def test_receipt_tracks_current_inclusion_and_reorg_instead_of_remembering_finality(self):
        raw, txid = self.f.wire()
        self.f.entries[txid] = (raw, 15)
        result = self.a.receipt("xds-claim", raw, txid)
        self.assertTrue(result["final"])
        self.assertTrue(result["publicly_observed"])
        self.assertEqual(result["tip_hash"], self.f.rpc("getinfo", {})["top_block_hash"])
        self.f.entries[txid] = (raw, None)
        result = self.a.receipt("xds-claim", raw, txid)
        self.assertEqual(result["status"], "pending")
        self.assertFalse(result["final"])
        self.assertTrue(result["publicly_observed"])
        self.f.entries.clear()
        result = self.a.receipt("xds-claim", raw, txid)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["publicly_observed"])

    def test_receipt_requires_spentness_and_valid_refund_inclusion(self):
        raw, txid = self.f.wire()
        self.f.entries[txid] = (raw, 15)
        self.f.funding_patch = {"spent": False}
        self.assertEqual(self.a.receipt("xds-claim", raw, txid)["status"], "unknown")
        self.f.funding_patch = {}
        raw, txid = self.f.wire("xds-refund")
        self.f.entries = {txid: (raw, 15)}
        self.assertEqual(self.a.receipt("xds-refund", raw, txid)["status"], "unknown")

    def test_valid_public_secret_is_retained_when_mutable_chain_evidence_is_unknown(self):
        raw, txid = self.f.wire()
        self.f.entries[txid] = (raw, None)
        self.f.info_patch = {"finality_fork_warning": True}
        result = self.a.verify_public_spend(txid, "xds-claim")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["secret"], self.f.secret.hex())
        self.assertEqual(result["raw"], raw.hex())
        self.assertFalse(result["final"])

    def test_invalid_public_signature_never_yields_secret(self):
        raw, _ = self.f.wire()
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
        txid = _h(raw).hex()
        self.f.entries[txid] = (raw, None)
        result = self.a.verify_public_spend(txid, "xds-claim")
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("secret", result)


if __name__ == "__main__":
    unittest.main()
