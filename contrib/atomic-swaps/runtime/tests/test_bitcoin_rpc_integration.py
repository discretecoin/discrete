"""Opt-in real Core regtest: BITCOIND=/path/to/bitcoind; never public networks.

BITCOIN_TEST_DATA optionally retains owned node data/logs outside the source tree.
Tests require no public peers, real assets, provider credentials or installation.
"""
import base64
from decimal import Decimal
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ec

from swap_runtime.bitcoin import BitcoinAdapter, Contract, pubkey, sha


BITCOIND = os.environ.get("BITCOIND")


class RegtestNode:
    def __init__(self):
        parent = os.environ.get("BITCOIN_TEST_DATA")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        self.path = Path(tempfile.mkdtemp(prefix="bitcoin-regtest-", dir=parent))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.start()

    def start(self):
        self.log = (self.path / "process.log").open("ab")
        self.process = subprocess.Popen(
            [BITCOIND, "-regtest", "-datadir=" + str(self.path), "-server=1", "-txindex=1",
             "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0", "-rpcbind=127.0.0.1",
             "-rpcallowip=127.0.0.1", "-rpcport=" + str(self.port), "-fallbackfee=0.0002"],
            stdout=self.log, stderr=self.log,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("owned regtest process exited")
                try:
                    self.auth = (self.path / "regtest" / ".cookie").read_text().strip()
                    self.rpc("getblockchaininfo", [])
                    return
                except (OSError, RuntimeError):
                    time.sleep(0.05)
            raise RuntimeError("owned regtest startup timed out")
        except BaseException:
            self.stop()
            raise

    def rpc(self, method, params, wallet=False):
        path = "/wallet/swaps-runtime" if wallet else "/"
        request = urllib.request.Request("http://127.0.0.1:" + str(self.port) + path,
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Basic " +
                     base64.b64encode(self.auth.encode()).decode()})
        try:
            raw = self.opener.open(request, timeout=15).read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
        result = json.loads(raw, parse_float=Decimal)
        if result.get("error"):
            raise RuntimeError(str(result["error"]))
        return result["result"]

    def stop(self):
        try:
            if self.process.poll() is None:
                try:
                    self.rpc("stop", [])
                except (OSError, RuntimeError, AttributeError):
                    pass
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    self.process.wait(timeout=5)
        finally:
            self.log.close()

    def mine(self, count=1):
        address = self.rpc("getnewaddress", [], wallet=True)
        blocks = self.rpc("generatetoaddress", [count, address])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            info = self.rpc("getindexinfo", [])
            if info.get("txindex", {}).get("synced") is True:
                return blocks
            time.sleep(0.02)
        raise RuntimeError("owned txindex failed to synchronize")


@unittest.skipUnless(BITCOIND and Path(BITCOIND).is_file(), "set BITCOIND for owned Core regtest")
class BitcoinRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = RegtestNode()
        try:
            cls.node.rpc("createwallet", ["swaps-runtime"])
            cls.node.mine(110)
            cls.a = ec.derive_private_key(12345, ec.SECP256K1())
            cls.b = ec.derive_private_key(67890, ec.SECP256K1())
        except BaseException:
            cls.node.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def fund(self, delay=8):
        n = self.node
        secret = os.urandom(32)
        destinations = []
        for _ in range(2):
            address = n.rpc("getnewaddress", [], wallet=True)
            destinations.append(n.rpc("getaddressinfo", [address], wallet=True)["scriptPubKey"])
        terms = {"genesis_hash": n.rpc("getblockhash", [0]), "hashlock": sha(secret).hex(),
                 "claim_pubkey": pubkey(self.a).hex(), "refund_pubkey": pubkey(self.b).hex(),
                 "refund_height": n.rpc("getblockcount", []) + delay, "funding_txid": "00" * 32,
                 "funding_vout": 0, "funding_value_sats": 100_000,
                 "claim_script": destinations[0], "refund_script": destinations[1],
                 "fee_sats": 1000, "min_confirmations": 2}
        contract = Contract.parse(terms)
        decoded = n.rpc("decodescript", [contract.script().hex()])
        txid = n.rpc("sendtoaddress", [decoded["segwit"]["address"], "0.001"], wallet=True)
        n.mine(2)
        funding = n.rpc("getrawtransaction", [txid, True])
        output = next(o for o in funding["vout"] if o["scriptPubKey"]["hex"] == contract.output_script().hex())
        terms.update(funding_txid=txid, funding_vout=output["n"])
        return BitcoinAdapter(n.rpc, terms), secret, terms

    def test_claim_receipt_confirmations_and_wallet_ordinary_spend(self):
        adapter, secret, terms = self.fund()
        self.assertEqual(adapter.observe()["status"], "unspent")
        self.assertTrue(adapter.observe()["final"])
        raw, txid = adapter.prepare("foreign-claim", self.a, secret)
        self.assertTrue(self.node.rpc("testmempoolaccept", [[raw.hex()]])[0]["allowed"])
        self.assertEqual(adapter.send("foreign-claim", raw, txid), txid)
        self.assertEqual(adapter.receipt("foreign-claim", raw, txid)["status"], "pending")
        public = adapter.verify_public_spend(txid, "foreign-claim")
        self.assertEqual(public["secret"], secret.hex())
        self.assertEqual(public["raw"], raw.hex())
        self.node.mine()
        first = adapter.receipt("foreign-claim", raw, txid)
        self.assertEqual(first["status"], "confirmed")
        self.assertFalse(first["final"])
        self.node.mine()
        self.assertTrue(adapter.receipt("foreign-claim", raw, txid)["final"])
        destination = self.node.rpc("getnewaddress", [], wallet=True)
        unsigned = self.node.rpc("createrawtransaction", [[{"txid": txid, "vout": 0}], {destination: "0.00098"}])
        signed = self.node.rpc("signrawtransactionwithwallet", [unsigned], wallet=True)
        self.assertTrue(signed["complete"])
        next_id = self.node.rpc("sendrawtransaction", [signed["hex"]])
        self.node.mine()
        self.assertIsNotNone(self.node.rpc("gettxout", [next_id, 0]))
        self.assertTrue(adapter.receipt("foreign-claim", raw, txid)["final"])

    def test_refund_height_then_restart_reconciles_exact_bytes(self):
        adapter, _, terms = self.fund()
        raw, txid = adapter.prepare("foreign-refund", self.b)
        self.assertFalse(self.node.rpc("testmempoolaccept", [[raw.hex()]])[0]["allowed"])
        self.assertFalse(adapter.observe()["refund_eligible"])
        current = self.node.rpc("getblockcount", [])
        self.node.mine(terms["refund_height"] - 1 - current)
        self.assertFalse(self.node.rpc("testmempoolaccept", [[raw.hex()]])[0]["allowed"])
        self.node.mine()
        self.assertTrue(adapter.observe()["refund_eligible"])
        self.assertTrue(self.node.rpc("testmempoolaccept", [[raw.hex()]])[0]["allowed"])
        adapter.send("foreign-refund", raw, txid)
        self.node.mine(2)
        self.node.stop()
        self.node.start()
        # Wallet can be autoloaded by Core; loading is unnecessary for receipt.
        fresh = BitcoinAdapter(self.node.rpc, terms)
        self.assertTrue(fresh.receipt("foreign-refund", raw, txid)["final"])
        self.assertEqual(fresh.observe()["status"], "spent")

    def test_lost_ack_duplicate_and_reorg_reacceptance(self):
        adapter, secret, terms = self.fund()
        raw, txid = adapter.prepare("foreign-claim", self.a, secret)
        def lossy(method, params):
            result = self.node.rpc(method, params)
            if method == "sendrawtransaction":
                raise TimeoutError("lost acknowledgment after Core acceptance")
            return result
        with self.assertRaises(Exception):
            BitcoinAdapter(lossy, terms).send("foreign-claim", raw, txid)
        self.assertEqual(adapter.receipt("foreign-claim", raw, txid)["status"], "pending")
        self.assertEqual(adapter.send("foreign-claim", raw, txid), txid)
        block = self.node.mine()[0]
        self.assertEqual(adapter.receipt("foreign-claim", raw, txid)["status"], "confirmed")
        self.node.rpc("invalidateblock", [block])
        self.assertEqual(adapter.receipt("foreign-claim", raw, txid)["status"], "pending")
        self.node.mine(2)
        self.assertTrue(adapter.receipt("foreign-claim", raw, txid)["final"])

    def test_full_witness_mismatch_and_local_tamper_block(self):
        adapter, secret, _ = self.fund()
        raw, txid = adapter.prepare("foreign-claim", self.a, secret)
        second, second_id = adapter.prepare("foreign-claim", self.a, secret)
        self.assertEqual(second_id, txid)
        self.assertNotEqual(raw, second)
        adapter.send("foreign-claim", raw, txid)
        self.assertEqual(adapter.receipt("foreign-claim", second, txid)["status"], "conflict")
        damaged = raw.replace(secret, b"\0" * 32)
        with self.assertRaises(ValueError):
            adapter.send("foreign-claim", damaged, txid)
        self.node.mine(2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
