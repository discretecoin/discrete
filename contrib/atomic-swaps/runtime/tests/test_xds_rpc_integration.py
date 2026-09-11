"""Opt-in owned XDS processes: XDS_RPC_INTEGRATION=1 and SWAP_BUILD_DIR.

XDS_TEST_DATA retains synthetic wallet/node state outside the source tree.
The frozen lab harness supplies process ownership and controlled private links;
the adapter under test uses only the new native observation API and wallet RPC.
"""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from swap_runtime.xds import XdsAdapter, _Unavailable


class BoundedForeignObservation:
    """Only this foreign-chain observation is mocked in the Session scenario."""
    def observe(self):
        return dict(status="unspent", final=True, height=100, confirmations=20,
                    block_hash="77" * 32, refund_eligible=False)


def session_adapters(config, daemon, foreign, wallet):
    return {"xds": XdsAdapter(daemon, config["xds"], wallet), "foreign": BoundedForeignObservation()}


def reopen_session_child():
    """Separate process: real daemon reads, no wallet and no permitted send."""
    from swap_runtime.session import Session
    request = json.loads(sys.stdin.buffer.read())
    root = Path(__file__).resolve().parents[4]
    sys.path.insert(0, str(root / "contrib/atomic-swaps/lab/swap-vps-v05/linux-harness"))
    import xds_localnet as lab
    def daemon(method, params):
        if method == "sendrawtransaction":
            raise AssertionError("receipt recovery must not transmit again")
        return lab.http(request["daemon_port"], "/" + method, params)
    with patch("swap_runtime.session._adapters", session_adapters):
        with Session(request["path"], bytes.fromhex(request["journal_key"]), request["swap_id"], daemon, None) as session:
            result = session.broadcast("xds-claim")
            intent = session.journal.intent(session.id, "xds-claim")
            digest = hashlib.sha256(intent["payload"]).hexdigest()
            if digest != request["payload_sha256"] or result["action"] != "reconciled" or result["receipt"]["status"] != "pending":
                raise AssertionError("separate-process recovery did not reconcile exact pending bytes")
            print(json.dumps(dict(action=result["action"], status=result["receipt"]["status"],
                payload_sha256=digest, stage=intent["stage"], exposed=session.journal.exposed(session.id))))


@unittest.skipUnless(os.environ.get("XDS_RPC_INTEGRATION") == "1", "owned XDS RPC integration is opt-in")
class XdsRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[4]
        harness = root / "contrib/atomic-swaps/lab/swap-vps-v05/linux-harness"
        sys.path.insert(0, str(harness))
        import xds_localnet as lab
        import test_xds_wallet_network as fixture
        parent = os.environ.get("XDS_TEST_DATA")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        cls.directory = Path(tempfile.mkdtemp(prefix="xds-runtime-", dir=parent))
        cls.previous_root, cls.lab, cls.fixture = lab.ROOT, lab, fixture
        lab.ROOT = cls.directory
        try:
            fixture.WalletNetwork.setUpClass()
            cls.x = fixture.WalletNetwork("runTest")
        except BaseException:
            lab.ROOT = cls.previous_root
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.fixture.WalletNetwork.tearDownClass()
        finally:
            cls.lab.ROOT = cls.previous_root

    def adapter(self, contract, refund=False, daemon=None):
        terms = contract["terms"]
        self.assertEqual(contract["fund"]["fee_atoms"], 1)
        pinned = dict(genesis_hash=terms["genesis_hash"], hashlock=terms["hashlock"], nonce=terms["nonce"],
            claim_commitment=contract["b"]["commitment"], refund_commitment=contract["a"]["commitment"],
            claim_address=contract["b"]["address"], refund_address=contract["a"]["address"],
            refund_height=terms["refund_height"], funding_txid=contract["fund"]["tx_hash"],
            funding_vout=0, funding_value_atoms=terms["principal_atoms"], fee_atoms=1,
            min_confirmations=11, funding_wire=contract["fund"]["tx_as_hex"])
        wallet = self.x.alice if refund else self.x.bob
        return XdsAdapter(daemon or self.rpc, pinned, lambda method, params: wallet.call(method, params))

    def rpc(self, method, params):
        return self.x.n.call("/" + method, params)

    def ready(self, adapter):
        def check():
            state = adapter.observe()
            return state if state["status"] == "unspent" and state["final"] else False
        return self.lab.wait_for(check, "adapter confirmed funding", 45)

    def test_01_real_native_claim_signature_wire_public_witness_and_final_receipt(self):
        contract = self.x.fund(delay=80)
        self.x.mine(10)
        adapter = self.adapter(contract)
        ready = self.ready(adapter)
        self.assertTrue(ready["fees_ready"])
        self.assertEqual(ready["tip_hash"], self.x.n.info()["top_block_hash"])
        wire, txid = adapter.prepare("xds-claim", contract["rho_b"], contract["secret"])
        self.assertEqual(adapter.validate("xds-claim", wire, txid)["fee_atoms"], 1)
        self.assertEqual(adapter.send("xds-claim", wire, txid), txid)
        pending = adapter.receipt("xds-claim", wire, txid)
        self.assertEqual(pending["status"], "pending")
        self.assertTrue(pending["publicly_observed"])
        # Lost finality evidence cannot erase an independently verified witness.
        def warned(method, params):
            value = self.rpc(method, params)
            if method == "getinfo":
                value["finality_fork_warning"] = True
            return value
        public = self.adapter(contract, daemon=warned).verify_public_spend(txid, "xds-claim")
        self.assertEqual(public["status"], "unknown")
        self.assertEqual(public["secret"], contract["secret"].hex())
        self.x.mine(11)
        receipt = adapter.receipt("xds-claim", wire, txid)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertTrue(receipt["final"])
        self.assertTrue(receipt["publicly_observed"])
        self.assertEqual(receipt["tip_hash"], self.x.n.info()["top_block_hash"])
        self.assertEqual(adapter.send("xds-claim", wire, txid), txid)
        self.lab.wait_for(lambda: self.x.bob.balance() >= 1000, "native self payout scanned", 45)

    def test_02_native_refund_lost_ack_recovers_exact_bytes_after_wallet_restart(self):
        contract = self.x.fund(delay=24)
        self.x.mine(10)
        calls = []
        lost = [True]
        def transport(method, params):
            value = self.rpc(method, params)
            if method == "sendrawtransaction":
                calls.append(params["tx_as_hex"])
                if lost[0]:
                    lost[0] = False
                    raise TimeoutError("deliberately dropped acknowledgment")
            return value
        adapter = self.adapter(contract, refund=True, daemon=transport)
        self.ready(adapter)
        with self.assertRaises(_Unavailable):
            adapter.prepare("xds-refund", contract["rho_a"])
        self.x.mine(contract["terms"]["refund_height"] - self.x.n.info()["height"])
        self.assertTrue(adapter.observe()["refund_eligible"])
        wire, txid = adapter.prepare("xds-refund", contract["rho_a"])
        with self.assertRaises(_Unavailable):
            adapter.send("xds-refund", wire, txid)
        self.x.alice.stop()
        self.x.alice.start()
        restored = self.adapter(contract, refund=True, daemon=transport)
        self.assertEqual(restored.send("xds-refund", wire, txid), txid)
        self.assertEqual(calls, [wire.hex()])
        self.x.mine(11)
        self.assertTrue(restored.receipt("xds-refund", wire, txid)["final"])

    def test_03_real_claim_reorg_drops_receipt_finality_and_resends_same_signed_wire(self):
        contract = self.x.fund(delay=80)
        self.x.mine(10)
        adapter = self.adapter(contract)
        self.ready(adapter)
        wire, txid = adapter.prepare("xds-claim", contract["rho_b"], contract["secret"])
        self.x.net.partition([[0, 1], [2, 3]])
        right = None
        try:
            adapter.send("xds-claim", wire, txid)
            left = self.x.n.mine(1, self.x.treasury)[-1]
            self.x.net.same_tip([0, 1], left)
            self.assertEqual(adapter.receipt("xds-claim", wire, txid)["status"], "confirmed")
            right = self.x.net.nodes[2].mine(2, bytes.fromhex("96" * 32))[-1]
            self.x.net.same_tip([2, 3], right)
        finally:
            self.x.net.reconnect()
        self.x.net.same_tip(expected=right)
        receipt = adapter.receipt("xds-claim", wire, txid)
        self.assertIn(receipt["status"], ("unknown", "pending"))
        self.assertFalse(receipt["final"])
        # Native reorg may requeue the spend; known exact wire avoids another send.
        self.assertEqual(adapter.send("xds-claim", wire, txid), txid)
        self.x.mine(11)
        self.assertTrue(adapter.receipt("xds-claim", wire, txid)["final"])

    def test_04_session_journal_child_process_recovers_lost_ack_real_xds_mock_foreign(self):
        from swap_runtime.session import Session
        contract = self.x.fund(delay=80)
        self.x.mine(10)
        adapter = self.adapter(contract)
        self.ready(adapter)
        terms = {key: value.hex() if isinstance(value, bytes) else value
                 for key, value in vars(adapter.contract).items()}
        config = dict(version=1, swap_id="native-session-reopen", role="foreign-owner",
            foreign_chain="bitcoin", xds=terms,
            foreign={"hashlock": terms["hashlock"], "refund_height": 1000},
            policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2,
                foreign_claim_budget_units=2, max_observation_seconds=15, solana_fee_attempt_reserve=2))
        path, key = self.directory / "native-session.sqlite", os.urandom(32)
        sends = []
        holder = []
        def transport(method, params):
            if method == "sendrawtransaction":
                session = holder[0]
                intent = session.journal.intent(session.id, "xds-claim")
                self.assertEqual(intent["stage"], "attempt-started")
                self.assertTrue(session.journal.exposed(session.id))
                self.assertEqual(params["tx_as_hex"], intent["payload"].hex())
                result = self.rpc(method, params)
                sends.append(params["tx_as_hex"])
                raise TimeoutError("accepted native transaction; acknowledgment deliberately dropped")
            return self.rpc(method, params)
        with patch("swap_runtime.session._adapters", session_adapters):
            with Session(path, key, config["swap_id"], transport, None,
                         wallet=lambda method, params: self.x.bob.call(method, params), config=config) as session:
                holder.append(session)
                session.prepare("xds-claim", contract["rho_b"], contract["secret"])
                intent = session.journal.intent(session.id, "xds-claim")
                wire, txid = intent["payload"], intent["txid"]
                with self.assertRaises(_Unavailable):
                    session.broadcast("xds-claim")
                self.assertEqual(sends, [wire.hex()])
        # The original Session process state is gone; a fresh interpreter has no
        # wallet RPC transport and may only prove the native pending receipt.
        env = dict(os.environ)
        runtime = Path(__file__).resolve().parents[1]
        env["PYTHONPATH"] = str(runtime) + os.pathsep + env.get("PYTHONPATH", "")
        request = dict(path=str(path), journal_key=key.hex(), swap_id=config["swap_id"],
                       daemon_port=self.x.n.rpc, payload_sha256=hashlib.sha256(wire).hexdigest())
        child = subprocess.run([sys.executable, "-B", __file__, "--session-reopen-child"],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=runtime, env=env, timeout=45, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))
        restored = json.loads(child.stdout)
        self.assertEqual(restored["payload_sha256"], hashlib.sha256(wire).hexdigest())
        self.assertEqual(restored["stage"], "attempt-started")
        self.assertTrue(restored["exposed"])
        self.x.mine(11)
        with patch("swap_runtime.session._adapters", session_adapters):
            with Session(path, key, config["swap_id"], self.rpc, None) as session:
                receipt = session.reconcile("xds-claim")
                self.assertEqual(receipt["status"], "confirmed")
                self.assertTrue(receipt["final"])
                self.assertEqual(session.journal.intent(session.id, "xds-claim")["payload"], wire)
                self.assertEqual(session.journal.intent(session.id, "xds-claim")["txid"], txid)
        self.assertEqual(sends, [wire.hex()])


if __name__ == "__main__":
    if sys.argv[1:] == ["--session-reopen-child"]:
        reopen_session_child()
    else:
        unittest.main()
