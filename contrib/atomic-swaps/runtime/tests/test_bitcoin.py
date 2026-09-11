"""Bitcoin adapter contract/wire/reconciliation invariants; no external network."""
from dataclasses import FrozenInstanceError
from decimal import Decimal
import struct
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from swap_runtime.bitcoin import BitcoinAdapter, Contract, N, _compact, _digest, _parse, dsha, pubkey, sha


def terms():
    claimant = ec.derive_private_key(12345, ec.SECP256K1())
    refunder = ec.derive_private_key(67890, ec.SECP256K1())
    return {"genesis_hash": "01" * 32, "hashlock": sha(b"s" * 32).hex(),
            "claim_pubkey": pubkey(claimant).hex(), "refund_pubkey": pubkey(refunder).hex(),
            "refund_height": 300, "funding_txid": "02" * 32, "funding_vout": 0,
            "funding_value_sats": 100_000, "claim_script": "0014" + "03" * 20,
            "refund_script": "0014" + "04" * 20, "fee_sats": 1000, "min_confirmations": 6}


class FakeCore:
    def __init__(self):
        self.terms = terms()
        c = Contract.parse(self.terms)
        output = struct.pack("<Q", c.funding_value_sats) + _compact(len(c.output_script())) + c.output_script()
        self.funding = (struct.pack("<I", 2) + b"\x01" + b"\x99" * 32 + struct.pack("<I", 0)
                        + b"\0" + struct.pack("<I", 0xffffffff) + b"\x01" + output + struct.pack("<I", 0))
        self.terms["funding_txid"] = dsha(self.funding)[::-1].hex()
        self.height = 300
        self.fundheight = 290
        self.spendheight = 300
        self.tip = "05" * 32
        self.fundblock = "06" * 32
        self.spendblock = "07" * 32
        self.best = {0: self.terms["genesis_hash"], self.fundheight: self.fundblock, self.spendheight: self.spendblock}
        self.unspent = True
        self.funding_visible = True
        self.mined = False
        self.spend = None
        self.calls = []
        self.errors = {}
        self.overrides = {}
        self.lost_ack = False
        self.tip_reads = 0
        self.change_tip = False

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method in self.errors:
            raise self.errors[method]
        if method in self.overrides:
            return self.overrides[method]
        if method == "getblockchaininfo":
            self.tip_reads += 1
            return {"bestblockhash": "08" * 32 if self.change_tip and self.tip_reads > 1 else self.tip,
                    "blocks": self.height, "headers": self.height, "initialblockdownload": False}
        if method == "getblockhash":
            return self.best[params[0]]
        if method == "getblockheader":
            height = self.fundheight if params[0] == self.fundblock else self.spendheight
            return {"hash": params[0], "height": height,
                    "confirmations": self.height - height + 1 if self.best.get(height) == params[0] else -1}
        if method == "gettxout":
            if not self.unspent:
                return None
            c = Contract.parse(self.terms)
            return {"bestblock": self.tip, "confirmations": self.height - self.fundheight + 1,
                    "value": Decimal("0.001"), "scriptPubKey": {"hex": c.output_script().hex()}}
        if method == "getrawtransaction":
            funding = params[0] == self.terms["funding_txid"]
            raw = self.funding if funding and self.funding_visible else self.spend if not funding else None
            if raw is None:
                raise RuntimeError("No such mempool or blockchain transaction")
            parsed = _parse(raw)
            result = {"hex": raw.hex(), "txid": parsed["txid"], "hash": parsed["wtxid"]}
            if funding or self.mined:
                height = self.fundheight if funding else self.spendheight
                result.update(blockhash=self.fundblock if funding else self.spendblock,
                              confirmations=self.height - height + 1)
            return result
        if method == "getmempoolentry":
            if not self.spend or self.mined:
                raise RuntimeError("not in mempool")
            return {"wtxid": _parse(self.spend)["wtxid"]}
        if method == "sendrawtransaction":
            self.spend = bytes.fromhex(params[0])
            self.unspent = False
            if self.lost_ack:
                raise TimeoutError("simulated response lost after accepted send")
            return _parse(self.spend)["txid"]
        raise AssertionError(method)


class BitcoinTests(unittest.TestCase):
    def setUp(self):
        self.core = FakeCore()
        self.adapter = BitcoinAdapter(self.core.rpc, self.core.terms)
        self.a = ec.derive_private_key(12345, ec.SECP256K1())
        self.b = ec.derive_private_key(67890, ec.SECP256K1())
        self.raw, self.txid = self.adapter.prepare("foreign-claim", self.a, b"s" * 32)

    def test_contract_is_frozen_and_copies_caller_terms(self):
        self.core.terms["fee_sats"] = 2
        self.assertEqual(self.adapter.contract.fee_sats, 1000)
        with self.assertRaises(FrozenInstanceError):
            self.adapter.contract.fee_sats = 3

    def test_rejects_unknown_missing_and_noncanonical_contract_fields(self):
        for field, value in (("unexpected", True), ("funding_vout", True), ("fee_sats", 0),
                             ("funding_value_sats", 1000), ("refund_height", 500_000_000),
                             ("refund_height", 16), ("min_confirmations", 0), ("genesis_hash", "ab " * 32),
                             ("funding_txid", "AB" * 32), ("claim_pubkey", "02" + "ff" * 32),
                             ("claim_script", "6a01ff"), ("hashlock", "01" * 31)):
            with self.subTest(field=field, value=value):
                changed = dict(self.core.terms, **{field: value})
                with self.assertRaises(ValueError):
                    BitcoinAdapter(self.core.rpc, changed)
        changed = dict(self.core.terms)
        changed.pop("genesis_hash")
        with self.assertRaises(ValueError):
            BitcoinAdapter(self.core.rpc, changed)

    def test_rejects_identical_roles(self):
        changed = dict(self.core.terms, refund_pubkey=self.core.terms["claim_pubkey"])
        with self.assertRaises(ValueError):
            BitcoinAdapter(self.core.rpc, changed)

    def test_builder_and_independent_validation_bind_both_roles(self):
        claim = self.adapter.validate("foreign-claim", self.raw, self.txid)
        self.assertEqual(claim["amount_sats"], 99_000)
        self.assertEqual(claim["fee_sats"], 1000)
        self.assertEqual(claim["secret"], (b"s" * 32).hex())
        self.assertEqual(claim["destination_script"], self.core.terms["claim_script"])
        raw, txid = self.adapter.prepare("foreign-refund", self.b)
        refund = self.adapter.validate("foreign-refund", raw, txid)
        self.assertNotIn("secret", refund)
        self.assertEqual(refund["destination_script"], self.core.terms["refund_script"])

    def test_builder_rejects_wrong_role_secret_and_key_curve(self):
        cases = [("foreign-claim", self.b, b"s" * 32), ("foreign-refund", self.a, None),
                 ("foreign-refund", self.b, b"s" * 32), ("foreign-claim", self.a, b"s" * 31),
                 ("foreign-claim", self.a, b"x" * 32), ("claim", self.a, b"s" * 32),
                 ("foreign-claim", ec.generate_private_key(ec.SECP256R1()), b"s" * 32)]
        for args in cases:
            with self.subTest(kind=args[0]), self.assertRaises(ValueError):
                self.adapter.prepare(*args)

    def test_same_txid_does_not_validate_wrong_preimage(self):
        wrong = self.raw.replace(b"s" * 32, b"x" * 32)
        self.assertEqual(_parse(wrong)["txid"], self.txid)
        with self.assertRaises(ValueError):
            self.adapter.validate("foreign-claim", wrong, self.txid)

    def test_same_txid_does_not_validate_wrong_role_signature(self):
        parsed = _parse(self.raw)
        old = parsed["witnesses"][0][0]
        signature = self.b.sign(_digest(self.adapter.contract, self.adapter.contract.claim_script, 0),
                                ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(signature)
        wrong = utils.encode_dss_signature(r, min(s, N - s)) + b"\x01"
        raw = self.raw.replace(bytes([len(old)]) + old, bytes([len(wrong)]) + wrong)
        self.assertEqual(_parse(raw)["txid"], self.txid)
        with self.assertRaisesRegex(ValueError, "role signature"):
            self.adapter.validate("foreign-claim", raw, self.txid)

    def test_high_s_and_other_sighash_rejected(self):
        old = _parse(self.raw)["witnesses"][0][0]
        r, s = utils.decode_dss_signature(old[:-1])
        for replacement in (utils.encode_dss_signature(r, N - s) + b"\x01", old[:-1] + b"\x02"):
            raw = self.raw.replace(bytes([len(old)]) + old, bytes([len(replacement)]) + replacement)
            with self.assertRaises(ValueError):
                self.adapter.validate("foreign-claim", raw, self.txid)

    def test_wire_mutations_rejected_even_with_recomputed_txid(self):
        mutations = []
        for offset in (0, 7, 39, 44, 49, 59):
            raw = bytearray(self.raw)
            raw[offset] ^= 1
            mutations.append(bytes(raw))
        mutations += [self.raw + b"\0", self.raw[:-1], self.raw[:6] + b"\xfd\x01\x00" + self.raw[7:]]
        for raw in mutations:
            with self.subTest(offset=raw[:64].hex()), self.assertRaises(ValueError):
                txid = _parse(raw)["txid"]
                self.adapter.validate("foreign-claim", raw, txid)

    def test_refund_cannot_be_validated_as_claim(self):
        raw, txid = self.adapter.prepare("foreign-refund", self.b)
        with self.assertRaises(ValueError):
            self.adapter.validate("foreign-claim", raw, txid)

    def test_confirmed_unspent_funding_and_refund_height_boundary(self):
        observed = self.adapter.observe()
        self.assertEqual(observed["status"], "unspent")
        self.assertEqual(observed["confirmations"], 11)
        self.assertTrue(observed["refund_eligible"])
        self.core.height = 299
        self.assertFalse(self.adapter.observe()["refund_eligible"])

    def test_wrong_genesis_or_initial_download_is_unknown(self):
        self.core.best[0] = "99" * 32
        self.assertEqual(self.adapter.observe()["status"], "unknown")
        with self.assertRaises(Exception):
            self.adapter.send("foreign-claim", self.raw, self.txid)
        self.assertFalse(any(m == "sendrawtransaction" for m, _ in self.core.calls))
        self.core = FakeCore()
        self.core.overrides["getblockchaininfo"] = {"initialblockdownload": True}
        self.assertEqual(BitcoinAdapter(self.core.rpc, self.core.terms).observe()["status"], "unknown")

    def test_missing_funding_is_unknown_not_refundable(self):
        self.core.unspent = False
        self.core.funding_visible = False
        observed = self.adapter.observe()
        self.assertEqual(observed["status"], "unknown")
        self.assertFalse(observed["refund_eligible"])

    def test_chain_proven_funding_without_utxo_is_spent_without_winner(self):
        self.core.unspent = False
        observed = self.adapter.observe()
        self.assertEqual(observed["status"], "spent")
        self.assertFalse(observed["refund_eligible"])
        self.assertFalse(observed["final"])

    def test_float_amount_and_changed_script_or_value_are_unknown(self):
        good = self.core.rpc("gettxout", [])
        for delta in ({"value": 0.001}, {"value": Decimal("0.00100001")},
                      {"value": "NaN"}, {"value": Decimal("1e999999999")},
                      {"scriptPubKey": {"hex": "0020" + "ff" * 32}}):
            self.core.overrides["gettxout"] = dict(good, **delta)
            with self.subTest(delta=delta):
                self.assertEqual(self.adapter.observe()["status"], "unknown")

    def test_funding_confirmation_disagreement_or_orphan_block_is_unknown(self):
        good = self.core.rpc("gettxout", [])
        self.core.overrides["gettxout"] = dict(good, confirmations=12)
        self.assertEqual(self.adapter.observe()["status"], "unknown")
        self.core.overrides.clear()
        self.core.best[self.core.fundheight] = "ff" * 32
        self.assertEqual(self.adapter.observe()["status"], "unknown")

    def test_tip_change_during_observation_never_final(self):
        self.core.change_tip = True
        observed = self.adapter.observe()
        self.assertEqual(observed["status"], "unknown")
        self.assertFalse(observed["final"])

    def test_send_reuses_exact_bytes_and_ack_identity(self):
        self.assertEqual(self.adapter.send("foreign-claim", self.raw, self.txid), self.txid)
        self.assertEqual(self.adapter.send("foreign-claim", self.raw, self.txid), self.txid)
        sends = [params for method, params in self.core.calls if method == "sendrawtransaction"]
        self.assertEqual(sends, [[self.raw.hex()], [self.raw.hex()]])
        self.core.overrides["sendrawtransaction"] = "ff" * 32
        with self.assertRaises(Exception):
            self.adapter.send("foreign-claim", self.raw, self.txid)

    def test_invalid_wire_never_reaches_rpc(self):
        self.core.calls.clear()
        with self.assertRaises(ValueError):
            self.adapter.send("foreign-claim", self.raw + b"\0", self.txid)
        self.assertEqual(self.core.calls, [])

    def test_lost_ack_reconciles_exact_mempool_transaction(self):
        self.core.lost_ack = True
        with self.assertRaises(Exception):
            self.adapter.send("foreign-claim", self.raw, self.txid)
        receipt = self.adapter.receipt("foreign-claim", self.raw, self.txid)
        self.assertEqual(receipt["status"], "pending")
        self.assertFalse(receipt["final"])
        self.assertTrue(receipt["publicly_observed"])

    def test_missing_receipt_is_unknown_after_restart(self):
        receipt = BitcoinAdapter(self.core.rpc, self.core.terms).receipt("foreign-claim", self.raw, self.txid)
        self.assertEqual(receipt["status"], "unknown")
        self.assertFalse(receipt["final"])
        self.assertNotEqual(receipt.get("publicly_observed"), True)

    def test_same_txid_different_valid_signature_is_conflict(self):
        other, txid = self.adapter.prepare("foreign-claim", self.a, b"s" * 32)
        self.assertEqual(txid, self.txid)
        self.assertNotEqual(other, self.raw)
        self.adapter.send("foreign-claim", other, txid)
        result = self.adapter.receipt("foreign-claim", self.raw, self.txid)
        self.assertEqual(result["status"], "conflict")

    def test_confirmed_receipt_requires_threshold_and_spent_input(self):
        self.adapter.send("foreign-claim", self.raw, self.txid)
        self.core.mined = True
        self.assertEqual(self.adapter.receipt("foreign-claim", self.raw, self.txid)["status"], "confirmed")
        self.assertFalse(self.adapter.receipt("foreign-claim", self.raw, self.txid)["final"])
        self.core.height += 5
        self.assertTrue(self.adapter.receipt("foreign-claim", self.raw, self.txid)["final"])
        self.assertTrue(self.adapter.receipt("foreign-claim", self.raw, self.txid)["publicly_observed"])
        self.core.unspent = True
        self.assertEqual(self.adapter.receipt("foreign-claim", self.raw, self.txid)["status"], "unknown")

    def test_orphan_receipt_unknown_then_reaccepted_mempool_pending(self):
        self.adapter.send("foreign-claim", self.raw, self.txid)
        self.core.mined = True
        self.core.best[self.core.spendheight] = "ff" * 32
        self.assertEqual(self.adapter.receipt("foreign-claim", self.raw, self.txid)["status"], "unknown")
        self.core.mined = False
        self.assertEqual(self.adapter.receipt("foreign-claim", self.raw, self.txid)["status"], "pending")

    def test_mempool_witness_mismatch_is_unknown(self):
        self.adapter.send("foreign-claim", self.raw, self.txid)
        self.core.overrides["getmempoolentry"] = {"wtxid": "ff" * 32}
        self.assertEqual(self.adapter.receipt("foreign-claim", self.raw, self.txid)["status"], "unknown")

    def test_rpc_failure_does_not_disclose_response_or_claim_success(self):
        self.core.errors["gettxout"] = RuntimeError("secret RPC credential must not propagate")
        result = self.adapter.observe()
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("credential", repr(result))

    def test_public_spend_helper_binds_expected_id_and_exposes_validated_secret(self):
        self.assertEqual(self.adapter.expected_txid("foreign-claim"), self.txid)
        with self.assertRaises(ValueError):
            self.adapter.verify_public_spend("ff" * 32, "foreign-claim")
        self.adapter.send("foreign-claim", self.raw, self.txid)
        found = self.adapter.verify_public_spend(self.txid, "foreign-claim")
        self.assertEqual(found["status"], "pending")
        self.assertEqual(found["secret"], (b"s" * 32).hex())
        self.assertEqual(found["raw"], self.raw.hex())

    def test_public_secret_retained_even_when_reorg_prevents_finality(self):
        self.adapter.send("foreign-claim", self.raw, self.txid)
        self.core.mined = True
        self.core.best[self.core.spendheight] = "ff" * 32
        found = self.adapter.verify_public_spend(self.txid, "foreign-claim")
        self.assertEqual(found["status"], "unknown")
        self.assertFalse(found["final"])
        self.assertEqual(found["secret"], (b"s" * 32).hex())

    def test_public_spend_with_invalid_witness_never_exposes_secret(self):
        self.core.spend = self.raw.replace(b"s" * 32, b"x" * 32)
        found = self.adapter.verify_public_spend(self.txid, "foreign-claim")
        self.assertEqual(found["status"], "unknown")
        self.assertNotIn("secret", found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
