"""Offline transport/journal guards. These tests do not qualify any chain outcome."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from solders.hash import Hash
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

import driver as d


class FakeRpc:
    commitment = "confirmed"
    genesis = str(Hash.from_bytes(bytes([1]) * 32))

    def __init__(self):
        self.calls = []
        self.wires = []
        self.drop_next_send = False
        self.height = 10
        self.before_send = lambda: None

    def guard(self):
        pass

    def config(self, *args):
        return {"commitment": self.commitment}

    def call(self, method, params=None):
        self.calls.append(method)
        if method == "getLatestBlockhash":
            return {"context": {"slot": 11}, "value": {"blockhash": str(Hash.from_bytes(bytes([2]) * 32)), "lastValidBlockHeight": 300}}
        if method == "getFeeForMessage":
            return {"value": 5000}
        if method == "getSignatureStatuses":
            return {"value": [None]}
        if method == "getBlockHeight":
            return self.height
        if method == "sendTransaction":
            self.before_send()
            self.wires.append(params[0])
            if self.drop_next_send:
                self.drop_next_send = False
                raise OSError("synthetic lost response")
            return str(Transaction.from_bytes(base64.b64decode(params[0])).signatures[0])
        raise AssertionError(method)


class Guards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = d.Store(Path(self.tmp.name))
        self.rpc = FakeRpc()
        self.sender = d.Sender(self.rpc, self.store, 1)
        self.payer = Keypair.from_seed(bytes([1]) * 32)
        self.destination = Keypair.from_seed(bytes([3]) * 32).pubkey()
        self.ix = transfer(TransferParams(from_pubkey=self.payer.pubkey(), to_pubkey=self.destination, lamports=7))

    def prepare(self):
        return self.sender.prepare("01-test", [self.ix], self.payer, debit=7)

    def test_endpoint_rejects_aliases_credentials_paths_and_external_before_socket(self):
        invalid = ["http://localhost:8899", "http://127.1:8899", "http://[::1]:8899", "http://2130706433:8899",
                   "http://0.0.0.0:8899", "https://127.0.0.1:8899", "http://127.0.0.1:8899@192.0.2.1",
                   "http://user@127.0.0.1:8899", "http://127.0.0.1:8899/path", "http://127.0.0.1:8899?q=1",
                   "http://127.0.0.1:8899#frag", "http://127.0.0.1", "http://192.0.2.1:8899", "http://127.0.0.1:8899\n"]
        with patch.object(d.http.client, "HTTPConnection") as connection:
            for endpoint in invalid:
                with self.subTest(endpoint=endpoint), self.assertRaises(d.GateError):
                    d.Rpc(endpoint, self.rpc.genesis)
            self.assertEqual(d.endpoint_port("http://127.0.0.1:8899/"), 8899)
            connection.assert_not_called()

    def test_redirect_response_is_rejected_without_following(self):
        class Response:
            status = 302

        class Connection:
            def request(self, *args): pass
            def getresponse(self): return Response()
            def close(self): pass

        with patch.object(d.http.client, "HTTPConnection", return_value=Connection()) as connection:
            with self.assertRaises(d.GateError):
                d.Rpc("http://127.0.0.1:8899", self.rpc.genesis).call("getGenesisHash")
            self.assertEqual(connection.call_count, 1)
            self.assertEqual(connection.call_args.args, ("127.0.0.1", 8899))

    def test_genesis_mismatch_is_fatal(self):
        rpc = d.Rpc("http://127.0.0.1:8899", self.rpc.genesis)
        with patch.object(rpc, "call", return_value=str(Hash.default())) as call:
            with self.assertRaises(d.GateError):
                rpc.guard()
            call.assert_called_once_with("getGenesisHash")

    def test_signed_wire_and_attempt_marker_exist_before_handoff(self):
        record = self.prepare()
        self.assertEqual(self.store.read("01-test")["state"], "prepared")
        self.assertNotIn("sendTransaction", self.rpc.calls)

        def before_send():
            durable = self.store.read("01-test")
            self.assertEqual(durable["state"], "attempt-started")
            self.assertEqual(len(durable["send_attempts"]), 1)
            self.assertEqual(durable["wire"], record["wire"])
            d.verify_record(durable, self.rpc.genesis)

        self.rpc.before_send = before_send
        self.sender.handoff(record)

    def test_uncertain_delivery_reuses_identical_wire_and_signature(self):
        record = self.prepare()
        self.rpc.drop_next_send = True
        self.sender.handoff(record)
        reread = self.sender.prepare("01-test", [self.ix], self.payer, debit=7)
        self.sender.handoff(reread)
        self.assertEqual(self.rpc.wires, [record["wire"], record["wire"]])
        self.assertEqual(self.rpc.calls.count("getLatestBlockhash"), 1)
        self.assertEqual(self.store.read("01-test")["txid"], record["txid"])
        self.assertEqual(self.store.read("01-test")["send_attempts"][0]["result"], "delivery-uncertain")

    def test_changed_intent_cannot_replace_existing_label(self):
        self.prepare()
        changed = transfer(TransferParams(from_pubkey=self.payer.pubkey(), to_pubkey=self.destination, lamports=8))
        with self.assertRaises(d.GateError):
            self.sender.prepare("01-test", [changed], self.payer, debit=8)
        self.assertEqual(self.rpc.calls.count("getLatestBlockhash"), 1)
        self.assertEqual(self.rpc.wires, [])

    def test_semantic_record_tampering_is_detected_by_decoded_message(self):
        record = self.prepare()
        record["intent"]["instructions"][0]["data"] = d.b64(b"wrong")
        with self.assertRaises(d.GateError):
            d.verify_record(record, self.rpc.genesis)

    def test_expiry_without_receipt_does_not_resign_or_send_new_intent(self):
        record = self.prepare()
        self.rpc.height = 301
        with self.assertRaises(d.GateError):
            self.sender.finish(record)
        self.assertEqual(self.rpc.calls.count("getLatestBlockhash"), 1)
        self.assertEqual(self.rpc.wires, [])
        self.assertEqual(self.store.read("01-test")["state"], "expired-without-qualified-receipt")

    def test_receipt_requires_exact_wire_expected_error_and_exact_fee_debit(self):
        record = self.prepare()
        original_call = self.rpc.call
        result = {"slot": 12, "transaction": [record["wire"], "base64"],
                  "meta": {"err": None, "fee": 5000, "preBalances": [100_000], "postBalances": [94_993]}}

        def call(method, params=None):
            if method == "getSignatureStatuses":
                return {"value": [{"slot": 12, "confirmationStatus": "confirmed", "err": None}]}
            if method == "getTransaction":
                return result
            return original_call(method, params)

        self.rpc.call = call
        self.assertEqual(self.sender.receipt(record)["fee"], 5000)
        saved = copy.deepcopy(result)
        for changed in ("wire", "fee", "debit", "error"):
            result.clear()
            result.update(copy.deepcopy(saved))
            if changed == "wire": result["transaction"][0] = d.b64(b"other")
            if changed == "fee": result["meta"]["fee"] = 5001
            if changed == "debit": result["meta"]["postBalances"][0] -= 1
            if changed == "error": result["meta"]["err"] = {"InstructionError": [0, {"Custom": 1}]}
            with self.subTest(changed=changed), self.assertRaises(d.GateError):
                self.sender.receipt(record)

    def test_invalid_private_payer_is_not_echoed(self):
        path = Path(self.tmp.name) / "bad-key.json"
        d.atomic_json(path, ["DO_NOT_ECHO_SYNTHETIC_KEY_MARKER"])
        with self.assertRaises(d.GateError) as raised:
            d.load_payer(path)
        self.assertNotIn("DO_NOT_ECHO", str(raised.exception))

    def test_old_receipt_or_primary_acceptance_cannot_qualify_uncertain_duplicate(self):
        record = {"send_attempts": [{"result": "accepted-for-relay"}, {"result": "delivery-uncertain"}]}
        with self.assertRaises(d.GateError):
            d.require_duplicate_ingress(record, 1)
        record["send_attempts"].append({"result": "accepted-for-relay"})
        self.assertEqual(d.require_duplicate_ingress(record, 1), [2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
