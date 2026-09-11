"""Offline business-rule and journal tests. No network, subprocess or chain qualification."""
import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bindings import sol, xds, localnet, verify_pins
from paired import PairFixture, Policy, admission_from_observations, observe_admission, validate_public_witness
from runner import persist_admission, persist_coordinated, send_coordinated
import runner


def state_bytes(f, status=1):
    return (b"XDSV0001" + bytes([status, f.bump]) + bytes(6) + sol.u64(sol.AMOUNT) + sol.u64(f.deadline)
            + f.hashlock + bytes(f.vault.pubkey()) + bytes(sol.MINT) + bytes(f.claim.pubkey()) + bytes(f.refund.pubkey()))


class Fixtures(unittest.TestCase):
    def setUp(self):
        # Any accidental HTTP/daemon action fails before a socket/process is made.
        self.http = patch.object(sol.http.client, "HTTPConnection", side_effect=AssertionError("offline test attempted HTTP"))
        self.process = patch.object(localnet.subprocess, "Popen", side_effect=AssertionError("offline test attempted subprocess"))
        self.http.start()
        self.process.start()
        self.addCleanup(self.http.stop)
        self.addCleanup(self.process.stop)
        self.bob = sol.Keypair.from_seed(bytes([81]) * 32)
        self.alice = sol.Keypair.from_seed(bytes([82]) * 32)
        self.secret = bytes([83]) * 32
        self.f = PairFixture(self.bob, self.alice, hashlib.sha256(self.secret).digest())
        self.f.deadline = 300
        self.policy = Policy()
        self.c = {"id": "swap", "terms": {"hashlock": self.f.hashlock.hex(), "refund_height": 70, "genesis_hash": "xds-genesis"},
                  "fund": {"tx_hash": "fund-id", "tx_as_hex": "aa"}, "foreign_funding_slot": 100,
                  "settlement": {"tx_hash": "claim-id", "tx_as_hex": "bb"}}
        self.snap = {"state_hex": state_bytes(self.f).hex(), "context_slot": 100, "commitment": "finalized",
                     "balances": {"vault": sol.AMOUNT, "source": sol.SUPPLY - sol.AMOUNT, "claim": 0, "refund": 0}}
        self.outpoint = {"status": "OK", "found": True, "in_chain": True, "spent_known": True, "spent": False,
                         "spent_in_pool": False, "amount_atoms": 1001, "tx_as_hex": "aa", "genesis_hash": "xds-genesis",
                         "height": 40, "block_height": 29, "confirmations": 11}

    def admission(self, **changes):
        data = dict(c=self.c, f=self.f, outpoint=self.outpoint, snapshot=self.snap, processed_slot=132,
                    fee=5000, fee_balance=10000, balance_slot=100, quote_slot=100, observed_seconds=1.0, policy=self.policy)
        data.update(changes)
        return admission_from_observations(**data)

    def test_frozen_dependencies_match(self):
        self.assertEqual(len(verify_pins()), 5)

    def test_per_swap_hashlock_is_in_funding_and_exact_state(self):
        funding = self.f.ix(0)
        self.assertEqual(bytes(funding.data)[17:], self.f.hashlock)
        self.assertNotEqual(self.f.hashlock, hashlib.sha256(sol.SECRET).digest())
        self.f.expect(self.snap, 1, sol.AMOUNT, sol.SUPPLY - sol.AMOUNT, 0, 0)
        other = PairFixture(self.bob, self.alice, hashlib.sha256(bytes([84]) * 32).digest())
        other.deadline = 300
        self.assertNotEqual(bytes(other.ix(0).data)[17:], bytes(funding.data)[17:])

    def test_no_implicit_claim_preimage_and_closed_instructions(self):
        for op, preimage in ((1, None), (1, sol.SECRET), (3, None), (True, self.secret), (0, self.secret), (2, self.secret)):
            with self.subTest(op=op), self.assertRaises(sol.GateError):
                self.f.ix(op, preimage)
        self.assertEqual(bytes(self.f.ix(1, self.secret).data), b"\1" + self.secret)
        self.assertEqual(bytes(self.f.ix(2).data), b"\2")

    def test_distinct_owners_required(self):
        with self.assertRaises(sol.GateError):
            PairFixture(self.bob, self.bob, self.f.hashlock)

    def test_actual_units_and_strict_budget_boundary(self):
        self.assertTrue(self.admission().allow_first_exposure())
        at_boundary = self.admission(processed_slot=172)
        self.assertEqual(at_boundary.foreign_claim_remaining, 128)
        self.assertFalse(at_boundary.allow_first_exposure())
        self.assertTrue(self.admission(processed_slot=171).allow_first_exposure())
        self.c["terms"]["refund_height"] = 42
        self.assertFalse(self.admission().allow_first_exposure())

    def test_underconfirmed_and_inconsistent_xds_observations(self):
        self.outpoint.update(confirmations=10, block_height=30)
        self.assertFalse(self.admission().allow_first_exposure())
        self.outpoint["confirmations"] = 11
        with self.assertRaises(sol.GateError):
            self.admission()

    def test_foreign_consumed_zeros_and_wrong_destination_are_rejected(self):
        for mutation in ("claimed", "refunded", "empty", "destination", "balance"):
            snapshot = copy.deepcopy(self.snap)
            raw = bytearray.fromhex(snapshot["state_hex"])
            if mutation == "claimed": raw[8] = 2
            if mutation == "refunded": raw[8] = 3
            if mutation == "empty": raw = bytearray(192)
            if mutation == "destination": raw[128] ^= 1
            if mutation == "balance": snapshot["balances"]["vault"] -= 1
            snapshot["state_hex"] = raw.hex()
            with self.subTest(mutation=mutation), self.assertRaises(sol.GateError):
                self.admission(snapshot=snapshot)

    def test_xds_unspent_exact_wire_amount_and_genesis_required(self):
        for key, value in (("spent", True), ("spent_in_pool", True), ("spent_known", False), ("amount_atoms", 1000),
                           ("tx_as_hex", "ac"), ("genesis_hash", "another"), ("found", False), ("in_chain", False)):
            changed = {**self.outpoint, key: value}
            with self.subTest(key=key), self.assertRaises(sol.GateError):
                self.admission(outpoint=changed)

    def test_freshness_finality_and_actual_fee_balance(self):
        for changed in ({"observed_seconds": 16}, {"balance_slot": 99}, {"quote_slot": 133},
                        {"processed_slot": 197}, {"fee_balance": 9999}):
            with self.subTest(changed=changed):
                self.assertFalse(self.admission(**changed).allow_first_exposure())
        with self.assertRaises(sol.GateError):
            self.admission(snapshot={**self.snap, "commitment": "confirmed"})
        with self.assertRaises(sol.GateError):
            self.admission(fee=None)

    def test_lowering_confirmations_or_mixing_unbounded_policy_is_rejected(self):
        for p in (Policy(xds_confirmations=10), Policy(foreign_claim_budget_slots=1), Policy(max_observation_seconds=16)):
            with self.assertRaises(sol.GateError):
                p.validate()

    def account_response(self):
        def account(data, owner):
            return {"owner": str(owner), "executable": False, "data": [sol.b64(data), "base64"]}
        values = [account(state_bytes(self.f), sol.PID)]
        for name, owner in (("vault", self.f.authority), ("source", self.bob.pubkey()),
                            ("claim", self.alice.pubkey()), ("refund", self.bob.pubkey())):
            data = bytearray(165)
            data[:32], data[32:64] = bytes(sol.MINT), bytes(owner)
            data[64:72] = sol.u64(self.snap["balances"][name])
            data[108] = 1
            values.append(account(data, sol.TOKEN))
        return {"context": {"slot": 100}, "value": values}

    def test_context_is_preserved_with_absence_and_authority_guards(self):
        response = self.account_response()
        rpc = SimpleNamespace(commitment="finalized", config=lambda slot: {"commitment": "finalized", "minContextSlot": slot},
                              call=lambda method, params: response)
        snapshot = self.f.snapshot(rpc, 100)
        self.assertEqual(snapshot, self.snap)
        with self.assertRaises(sol.GateError):
            self.f.snapshot(rpc, 101)
        data = bytearray(sol.unb64(response["value"][3]["data"][0]))
        data[32:64] = bytes(self.bob.pubkey())
        response["value"][3]["data"][0] = sol.b64(data)
        with self.assertRaises(sol.GateError):
            self.f.snapshot(rpc, 100)
        response["value"][0] = None
        with self.assertRaises(sol.GateError):
            self.f.snapshot(rpc, 100)

    def test_rpc_supplier_uses_finalized_accounts_and_processed_clock_without_send(self):
        calls = []
        def call(method, params):
            calls.append((method, params))
            if method == "getMultipleAccounts": return self.account_response()
            if method == "getLatestBlockhash":
                return {"context": {"slot": 100}, "value": {"blockhash": str(sol.Hash.default())}}
            if method == "getFeeForMessage": return {"context": {"slot": 100}, "value": 5000}
            if method == "getBalance": return {"context": {"slot": 100}, "value": 10000}
            if method == "getSlot": return 132
            raise AssertionError(method)
        rpc = SimpleNamespace(commitment="finalized", guard=lambda: None, call=call,
                              config=lambda slot=None: {"commitment": "finalized", "minContextSlot": slot})
        x = SimpleNamespace(n=SimpleNamespace(outpoint=lambda txid: self.outpoint))
        decision, evidence = observe_admission(x, self.c, self.f, rpc, self.policy)
        self.assertTrue(decision.allow_first_exposure())
        self.assertEqual(evidence["foreign"]["context_slot"], 100)
        self.assertEqual(calls[-1], ("getSlot", [{"commitment": "processed", "minContextSlot": 100}]))
        self.assertNotIn("sendTransaction", [m for m, _ in calls])
        self.assertEqual(calls[0][1][1]["commitment"], "finalized")

    def witness(self):
        w = {"prev_txid": "fund-id", "prev_out_index": 0, "branch": 1, "secret": self.secret.hex()}
        return ({"status": "OK", "txs_as_hex": ["bb"]},
                {"transaction": {"inBlockchain": True, "hash": "claim-id", "fee": 1, "txType": 5, "blockHash": "block",
                                 "inputs": [{"type": "20", "data": {"input": w}}]}},
                {"in_chain": True, "block_hash": "block", "tx_as_hex": "bb"})

    def test_public_witness_binds_wire_main_chain_input_and_both_hashlocks(self):
        raw, details, outpoint = self.witness()
        # Local known secret is deliberately wrong; the extractor must use public transaction data.
        self.c["secret"] = bytes(32)
        self.assertEqual(validate_public_witness(self.c, self.f, raw, details, outpoint), self.secret)
        for mutation in ("wire", "pool", "fee", "fund", "branch", "preimage"):
            r, d, o = copy.deepcopy(self.witness())
            if mutation == "wire": r["txs_as_hex"] = ["cc"]
            if mutation == "pool": d["transaction"]["inBlockchain"] = False
            if mutation == "fee": d["transaction"]["fee"] = 2
            if mutation == "fund": d["transaction"]["inputs"][0]["data"]["input"]["prev_txid"] = "another"
            if mutation == "branch": d["transaction"]["inputs"][0]["data"]["input"]["branch"] = 2
            if mutation == "preimage": d["transaction"]["inputs"][0]["data"]["input"]["secret"] = bytes(32).hex()
            with self.subTest(mutation=mutation), self.assertRaises(sol.GateError):
                validate_public_witness(self.c, self.f, r, d, o)

    def test_endpoint_control_char_alias_and_external_rejected_offline(self):
        for endpoint in ("http://localhost:8899", "http://127.0.0.1:8899\n", "http://192.0.2.1:8899"):
            with self.assertRaises(sol.GateError):
                sol.Rpc(endpoint, str(sol.Hash.default()), "finalized")


class JournalGuards(unittest.TestCase):
    admission = Fixtures.admission

    def setUp(self):
        Fixtures.setUp(self)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = sol.Store(Path(temp.name))
        journal = xds.Journal(self.store.root / "coordinator.db", bytes([41]) * 32, True)
        self.addCleanup(journal.close)
        self.c["foreign"] = self.f.public_terms(str(sol.Hash.default()))
        journal.register("swap", {"fixture_only": True, "foreign": self.c["foreign"]})
        self.x = SimpleNamespace(journal=journal)
        self.sent = []
        owner = self
        class Rpc:
            genesis = str(sol.Hash.default())
            commitment = "finalized"
            def guard(self): pass
            def config(self, slot=None): return {"commitment": "finalized"}
            def call(self, method, params):
                if method == "getLatestBlockhash":
                    return {"context": {"slot": 100}, "value": {"blockhash": str(sol.Hash.from_bytes(bytes([88])*32)), "lastValidBlockHeight": 500}}
                if method == "getFeeForMessage": return {"context": {"slot": 100}, "value": 5000}
                if method == "sendTransaction":
                    intent = journal.intent("swap", owner.active_kind)
                    owner.assertEqual(intent["stage"], "attempt-started")
                    owner.assertEqual(intent["payload"], sol.unb64(params[0]))
                    durable = owner.store.read("13-test")
                    owner.assertEqual(durable["state"], "attempt-started")
                    owner.assertEqual(durable["wire"], params[0])
                    owner.sent.append(params[0])
                    raise OSError("offline uncertainty")
                raise AssertionError(method)
        self.sender = sol.Sender(Rpc(), self.store, 1)
        self.record = self.sender.prepare("13-test", [self.f.ix(0)], self.bob, [self.f.state])
        self.active_kind = "foreign-fund"

    def test_both_journals_precede_foreign_send_and_uncertain_retry_keeps_bytes(self):
        persist_coordinated(self.x, self.c, "foreign-fund", self.sender, self.record)
        self.assertEqual(self.sent, [])
        # Use the real handoff but stop before receipt polling; no chain success is fabricated.
        def finish(record):
            self.sender.handoff(record)
            raise TimeoutError("offline response uncertainty")
        with patch.object(self.sender, "finish", side_effect=finish):
            for _ in range(2):
                with self.assertRaises(TimeoutError):
                    send_coordinated(self.x, self.c, "foreign-fund", self.sender, self.record)
        self.assertEqual(self.sent, [self.record["wire"], self.record["wire"]])
        self.assertEqual(self.x.journal.intent("swap", "foreign-fund")["txid"], self.record["txid"])

    def test_unqualified_foreign_claim_cannot_disclose_first(self):
        record = self.sender.prepare("14-claim", [self.f.ix(1, self.secret)], self.alice)
        persist_coordinated(self.x, self.c, "foreign-claim", self.sender, record)
        with self.assertRaisesRegex(ValueError, "fresh first-exposure"):
            send_coordinated(self.x, self.c, "foreign-claim", self.sender, record)
        self.assertFalse(self.x.journal.exposed("swap"))
        self.assertEqual(self.sent, [])

    def test_first_xds_handoff_uses_fresh_admission_and_commits_sticky_exposure_before_send(self):
        j = self.x.journal
        j.prepare("swap", "xds-claim", b"owned synthetic wire", "synthetic-xds-txid")
        self.outpoint.update(confirmations=1, block_height=39)
        with self.assertRaisesRegex(ValueError, "fresh first-exposure"):
            j.broadcast("swap", "xds-claim", lambda *_: self.fail("underconfirmed send"), self.admission)
        self.assertFalse(j.exposed("swap"))
        self.assertEqual(j.intent("swap", "xds-claim")["stage"], "prepared")
        self.outpoint.update(confirmations=11, block_height=29)
        def uncertain(wire, txid):
            self.assertTrue(j.exposed("swap"))
            self.assertEqual(j.intent("swap", "xds-claim")["stage"], "attempt-started")
            self.assertEqual((wire, txid), (b"owned synthetic wire", "synthetic-xds-txid"))
            raise TimeoutError("offline uncertainty")
        with self.assertRaises(TimeoutError):
            j.broadcast("swap", "xds-claim", uncertain, self.admission)
        self.outpoint["spent"] = True
        with self.assertRaises(TimeoutError):
            j.broadcast("swap", "xds-claim", uncertain, lambda: self.fail("protective retry must preserve exposure"))
        self.assertTrue(j.exposed("swap"))

    def test_reject_coordinator_link_after_unjournaled_attempt(self):
        self.record["state"] = "attempt-started"
        self.store.save(self.record["label"], self.record)
        with self.assertRaises(sol.GateError):
            persist_coordinated(self.x, self.c, "foreign-fund", self.sender, self.record)
        self.assertIsNone(self.x.journal.intent("swap", "foreign-fund"))

    def test_coordinator_rejects_wrong_kind_or_other_fixture(self):
        with self.assertRaises(sol.GateError):
            persist_coordinated(self.x, self.c, "foreign-claim", self.sender, self.record)
        other = PairFixture(self.bob, self.alice, self.f.hashlock)
        other.deadline = self.f.deadline
        record = self.sender.prepare("14-other-fixture", [other.ix(0)], self.bob, [other.state])
        with self.assertRaises(sol.GateError):
            persist_coordinated(self.x, self.c, "foreign-fund", self.sender, record)
        self.assertEqual(self.sent, [])

    def test_persistence_delay_is_in_first_exposure_age_and_cannot_send_stale_admission(self):
        result = self.admission()
        self.assertTrue(result.allow_first_exposure())
        original_persist = sol.atomic_json
        for elapsed, allowed in ((15.0, True), (15.001, False)):
            with self.subTest(elapsed=elapsed):
                swap = "age-" + str(elapsed)
                j = self.x.journal
                j.register(swap, {"fixture_only": True})
                j.prepare(swap, "xds-claim", b"owned synthetic claim", "age-test-txid")
                clock, sends = [101.0], []
                evidence_path = self.store.root / (swap + ".json")
                def delayed_persist(path, value):
                    original_persist(path, value)
                    clock[0] = 100.0 + elapsed
                def supplier():
                    return persist_admission(result, {"observation_seconds": 1.0}, [], evidence_path, 100.0, self.policy)
                with patch.object(sol, "atomic_json", side_effect=delayed_persist), \
                     patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]):
                    if allowed:
                        j.broadcast(swap, "xds-claim", lambda *args: sends.append(args), supplier)
                    else:
                        with self.assertRaisesRegex(sol.GateError, "aged out while persisting"):
                            j.broadcast(swap, "xds-claim", lambda *args: sends.append(args), supplier)
                self.assertTrue(evidence_path.exists())
                self.assertEqual(j.exposed(swap), allowed)
                self.assertEqual(bool(sends), allowed)
                self.assertEqual(j.intent(swap, "xds-claim")["stage"], "attempt-started" if allowed else "prepared")


if __name__ == "__main__":
    unittest.main(verbosity=2)
