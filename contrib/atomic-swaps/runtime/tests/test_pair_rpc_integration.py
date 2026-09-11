"""Opt-in two-owner Session XDS/Bitcoin settlement on two real private ledgers.

PAIR_RPC_INTEGRATION=1, BITCOIND and SWAP_BUILD_DIR are required. The existing
fixtures only own processes, prepare synthetic funding and advance the clocks.
Both Session adapters and LocalRpc transports are the actual runtime code; no
ledger/admission result is mocked. Block budgets are controlled regtest policy,
not evidence for public-network deadlines or finality. Retained node and wallet
directories contain synthetic private material and are not publication artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from swap_runtime.rpc import LocalRpc
from swap_runtime.session import Session
from swap_runtime.xds import _Unavailable

import test_bitcoin_rpc_integration as bitcoin_fixture
import test_xds_rpc_integration as xds_fixture


def reopen_pair_child():
    """A fresh interpreter recovers by real receipts without any signing wallet."""
    request = json.loads(sys.stdin.buffer.read())
    native = LocalRpc(request["xds_endpoint"]).daemon
    cookie = (Path(request["bitcoin_directory"]) / "regtest/.cookie").read_text().strip()
    foreign = LocalRpc(request["bitcoin_endpoint"], cookie)
    sends = []
    def read_native(method, params):
        if method == "sendrawtransaction":
            sends.append(method)
            raise AssertionError("fresh receipt recovery must not transmit")
        return native(method, params)
    with Session(request["path"], bytes.fromhex(request["key"]), request["swap_id"],
                 read_native, foreign) as session:
        result = session.broadcast("xds-claim")
        intent = session.journal.intent(session.id, "xds-claim")
        _, observed = session.observe()
        if (result["action"] != "reconciled" or result["receipt"]["status"] != "pending"
                or not result["receipt"]["publicly_observed"] or sends
                or observed["foreign"]["status"] != "unspent" or not observed["foreign"]["final"]):
            raise AssertionError("coupled receipt recovery did not bind both real ledgers")
        print(json.dumps(dict(action=result["action"], receipt=result["receipt"]["status"],
            payload_sha256=hashlib.sha256(intent["payload"]).hexdigest(), txid=intent["txid"],
            exposed=session.journal.exposed(session.id), stage=intent["stage"],
            foreign_genesis=observed["foreign"]["genesis_hash"], sends=len(sends))))


@unittest.skipUnless(os.environ.get("PAIR_RPC_INTEGRATION") == "1" and
                     bitcoin_fixture.BITCOIND and Path(bitcoin_fixture.BITCOIND).is_file(),
                     "set PAIR_RPC_INTEGRATION=1, BITCOIND and SWAP_BUILD_DIR for owned pair")
class PairRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xds_fixture.XdsRpcIntegration.setUpClass()
        try:
            bitcoin_fixture.BitcoinRpcIntegration.setUpClass()
        except BaseException:
            xds_fixture.XdsRpcIntegration.tearDownClass()
            raise
        cls.native = xds_fixture.XdsRpcIntegration("runTest")
        cls.bitcoin = bitcoin_fixture.BitcoinRpcIntegration("runTest")
        cls.directory = cls.native.directory

    @classmethod
    def tearDownClass(cls):
        try:
            bitcoin_fixture.BitcoinRpcIntegration.tearDownClass()
        finally:
            xds_fixture.XdsRpcIntegration.tearDownClass()

    def transports(self):
        x, b = self.native.x, self.bitcoin.node
        daemon = LocalRpc("http://127.0.0.1:" + str(x.n.rpc)).daemon
        foreign = LocalRpc("http://127.0.0.1:" + str(b.port), b.auth)
        alice = LocalRpc("http://127.0.0.1:" + str(x.alice.rpc), x.alice.auth).wallet
        bob = LocalRpc("http://127.0.0.1:" + str(x.bob.rpc), x.bob.auth).wallet
        return daemon, foreign, alice, bob

    def fund_pair(self, name, native_delay=80, bitcoin_delay=32):
        _, secret, foreign = self.bitcoin.fund(delay=bitcoin_delay)
        contract = self.native.x.fund(secret=secret, delay=native_delay)
        self.native.x.mine(10)
        native = self.native.adapter(contract)
        self.native.ready(native)
        terms = {key: value.hex() if isinstance(value, bytes) else value
                 for key, value in vars(native.contract).items()}
        self.assertEqual(terms["hashlock"], foreign["hashlock"])
        config = dict(version=1, swap_id=name, role="foreign-owner", foreign_chain="bitcoin",
            xds=terms, foreign=foreign,
            policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2,
                foreign_claim_budget_units=2, max_observation_seconds=15, solana_fee_attempt_reserve=2))
        return contract, config

    def test_01_two_real_ledgers_claim_lost_ack_child_restart_and_ordinary_outputs(self):
        x, b = self.native.x, self.bitcoin.node
        x.bob.synced()
        before = x.bob.balance()
        contract, config = self.fund_pair("pair-success")
        daemon, foreign, alice, bob = self.transports()
        bob_path, bob_key = self.directory / "pair-success-bob.sqlite", os.urandom(32)
        sends, holder = [], []
        def lost_ack(method, params):
            if method != "sendrawtransaction":
                return daemon(method, params)
            current = holder[0]
            intent = current.journal.intent(current.id, "xds-claim")
            self.assertEqual(intent["stage"], "attempt-started")
            self.assertTrue(current.journal.exposed(current.id))
            self.assertEqual(params["tx_as_hex"], intent["payload"].hex())
            daemon(method, params)
            sends.append(params["tx_as_hex"])
            raise TimeoutError("owned native acceptance followed by dropped acknowledgment")
        with Session(bob_path, bob_key, config["swap_id"], lost_ack, foreign,
                     wallet=bob, config=config) as session:
            holder.append(session)
            admission, observed = session.observe()
            self.assertTrue(admission.allow_first_exposure(), observed)
            self.assertEqual(observed["foreign"]["genesis_hash"], b.rpc("getblockhash", [0]))
            session.prepare("xds-claim", contract["rho_b"], contract["secret"])
            intent = session.journal.intent(session.id, "xds-claim")
            xds_wire, xds_id = intent["payload"], intent["txid"]
            with self.assertRaises(_Unavailable):
                session.broadcast("xds-claim")
            self.assertEqual(sends, [xds_wire.hex()])

        request = dict(path=str(bob_path), key=bob_key.hex(), swap_id=config["swap_id"],
            xds_endpoint="http://127.0.0.1:" + str(x.n.rpc),
            bitcoin_endpoint="http://127.0.0.1:" + str(b.port), bitcoin_directory=str(b.path))
        env = dict(os.environ)
        runtime = Path(__file__).resolve().parents[1]
        env["PYTHONPATH"] = str(runtime) + os.pathsep + env.get("PYTHONPATH", "")
        child = subprocess.run([sys.executable, "-B", __file__, "--reopen-pair-child"],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=runtime, env=env, timeout=45, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))
        reopened = json.loads(child.stdout)
        self.assertEqual(reopened["payload_sha256"], hashlib.sha256(xds_wire).hexdigest())
        self.assertEqual(reopened["txid"], xds_id)
        self.assertEqual(reopened["foreign_genesis"], config["foreign"]["genesis_hash"])
        self.assertEqual(reopened["stage"], "attempt-started")
        self.assertTrue(reopened["exposed"])
        self.assertEqual(reopened["sends"], 0)

        alice_config = dict(config, role="xds-owner")
        alice_path, alice_key = self.directory / "pair-success-alice.sqlite", os.urandom(32)
        with Session(alice_path, alice_key, config["swap_id"], daemon, foreign,
                     wallet=alice, config=alice_config) as session:
            # The second owner may obtain the preimage only from the real public
            # native claim. The first owner's private secret is never passed here.
            with self.assertRaises(ValueError):
                session.prepare("foreign-claim", self.bitcoin.a)
            session.prepare("foreign-claim", self.bitcoin.a, public_xds_txid=xds_id)
            intent = session.journal.intent(session.id, "foreign-claim")
            btc_wire, btc_id = intent["payload"], intent["txid"]
            self.assertTrue(session.journal.exposed(session.id))
            self.assertEqual(session.broadcast("foreign-claim")["txid"], btc_id)
            self.assertEqual(session.reconcile("foreign-claim")["status"], "pending")
            b.mine(2)
            self.assertTrue(session.reconcile("foreign-claim")["final"])
            self.assertEqual(session.journal.intent(session.id, "foreign-claim")["payload"], btc_wire)
        x.mine(11)
        with Session(bob_path, bob_key, config["swap_id"], daemon, foreign) as session:
            self.assertTrue(session.reconcile("xds-claim")["final"])
            self.assertEqual(session.journal.intent(session.id, "xds-claim")["payload"], xds_wire)
        self.assertEqual(sends, [xds_wire.hex()])
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, "paired XDS payout scanned", 60)

        # Both settled outputs then traverse the existing ordinary wallet path.
        ordinary = x.bob.call("transfer", dict(destinations=[dict(address=contract["a"]["address"], amount=900)],
            fee=1, unlock_height=0, payment_id="", extra=""))
        x.mine()
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 99, "paired ordinary XDS change scanned", 60)
        self.assertTrue(x.n.outpoint(ordinary["tx_hash"])["in_chain"])
        destination = b.rpc("getnewaddress", [], wallet=True)
        unsigned = b.rpc("createrawtransaction", [[dict(txid=btc_id, vout=0)], {destination: "0.00098"}])
        signed = b.rpc("signrawtransactionwithwallet", [unsigned], wallet=True)
        self.assertTrue(signed["complete"])
        ordinary_id = b.rpc("sendrawtransaction", [signed["hex"]])
        b.mine()
        self.assertIsNotNone(b.rpc("gettxout", [ordinary_id, 0]))

    def test_02_two_real_ledgers_abandoned_pair_refunds_net_principals_without_exposure(self):
        x, b = self.native.x, self.bitcoin.node
        x.alice.synced()
        before = x.alice.balance()
        contract, config = self.fund_pair("pair-abandoned", native_delay=24, bitcoin_delay=8)
        daemon, foreign, alice, bob = self.transports()
        alice_config = dict(config, role="xds-owner")
        with Session(self.directory / "pair-refund-alice.sqlite", os.urandom(32), config["swap_id"],
                     daemon, foreign, wallet=alice, config=alice_config) as native_owner:
            with Session(self.directory / "pair-refund-bob.sqlite", os.urandom(32), config["swap_id"],
                         daemon, foreign, wallet=bob, config=config) as foreign_owner:
                with self.assertRaises(_Unavailable):
                    native_owner.prepare("xds-refund", contract["rho_a"])
                foreign_owner.prepare("foreign-refund", self.bitcoin.b)
                with self.assertRaises(ValueError):
                    foreign_owner.broadcast("foreign-refund")
                self.assertFalse(native_owner.journal.exposed(config["swap_id"]))
                self.assertFalse(foreign_owner.journal.exposed(config["swap_id"]))
                x.mine(config["xds"]["refund_height"] - x.n.info()["height"])
                b.mine(config["foreign"]["refund_height"] - b.rpc("getblockcount", []))
                native_owner.prepare("xds-refund", contract["rho_a"])
                native_intent = native_owner.journal.intent(config["swap_id"], "xds-refund")
                foreign_intent = foreign_owner.journal.intent(config["swap_id"], "foreign-refund")
                self.assertEqual(native_owner.broadcast("xds-refund")["txid"], native_intent["txid"])
                self.assertEqual(foreign_owner.broadcast("foreign-refund")["txid"], foreign_intent["txid"])
                x.mine(11)
                b.mine(2)
                for owner, kind, intent in ((native_owner, "xds-refund", native_intent),
                                             (foreign_owner, "foreign-refund", foreign_intent)):
                    receipt = owner.reconcile(kind)
                    self.assertEqual(receipt["status"], "confirmed")
                    self.assertTrue(receipt["final"])
                    self.assertFalse(owner.journal.exposed(config["swap_id"]))
                    self.assertEqual(owner.journal.intent(config["swap_id"], kind)["payload"], intent["payload"])
                self.assertIsNotNone(b.rpc("gettxout", [foreign_intent["txid"], 0]))
        self.native.lab.wait_for(lambda: x.alice.balance() == before - 2, "paired XDS refund net two fees", 60)


if __name__ == "__main__":
    if sys.argv[1:] == ["--reopen-pair-child"]:
        reopen_pair_child()
    else:
        unittest.main(verbosity=2)
