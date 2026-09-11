"""Owned loopback qualification for the bounded read-only outpoint RPC.

Run with SWAP_CORE_DIR/SWAP_BUILD_DIR set to an independently built candidate.
No public peers, tokens, production wallets, or mining outside swap-lab are used.
"""
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "contrib/atomic-swaps/lab/swap-vps-v05/linux-harness"
sys.path.insert(0, str(HARNESS))
import xds_localnet as lab


class SwapReadRpc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="xds-swap-read-rpc-")
        cls.previous_root = lab.ROOT
        lab.ROOT = Path(cls.directory.name)
        try:
            cls.network = lab.Network(1)
        except BaseException:
            lab.ROOT = cls.previous_root
            cls.directory.cleanup()
            raise
        cls.node = cls.network.nodes[0]
        cls.query = {"txid": "00" * 32, "index": 0, "spend_tag": ""}

    @classmethod
    def tearDownClass(cls):
        cls.network.close()
        lab.ROOT = cls.previous_root
        cls.directory.cleanup()

    def test_default_testnet_read_keeps_lab_mutation_disabled_in_restricted_mode(self):
        for restricted in (False, True):
            with self.subTest(restricted=restricted), tempfile.TemporaryDirectory(prefix="xds-read-default-testnet-") as directory:
                directory = Path(directory)
                rpc = lab.port()
                args = [str(lab.DAEMON), "--testnet", "--without-checkpoints", "--no-console",
                        "--data-dir", str(directory), "--p2p-bind-ip", "127.0.0.1",
                        "--p2p-bind-port", str(lab.port()), "--rpc-bind-ip", "127.0.0.1",
                        "--rpc-bind-port", str(rpc), "--allow-local-ip",
                        "--add-exclusive-node", f"127.0.0.1:{lab.port()}",
                        "--log-file", str(directory / "daemon.log")]
                if restricted:
                    args.append("--restricted-rpc")
                with (directory / "process.log").open("wb") as output:
                    process = subprocess.Popen(args, cwd=directory, stdin=subprocess.DEVNULL,
                                               stdout=output, stderr=output,
                                               creationflags=lab.CREATE_NO_WINDOW)
                    try:
                        before = lab.wait_for(lambda: lab.http(rpc, "/getinfo", {}), "default testnet startup")
                        result = lab.http(rpc, "/get_swap_outpoint", self.query)
                        self.assertEqual(result["status"], "OK")
                        self.assertFalse(result["found"])
                        self.assertEqual(result["height"], 1)
                        for path in ("/swap_lab_mine", "/swap_lab_outpoint"):
                            with self.assertRaisesRegex(RuntimeError, "HTTP 404"):
                                lab.http(rpc, path, self.query)
                        self.assertEqual(lab.http(rpc, "/getinfo", {})["top_block_hash"], before["top_block_hash"])
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        process.wait(timeout=10)

    def test_lab_alias_matches_and_reads_do_not_mine(self):
        before = self.node.info()["top_block_hash"]
        old = self.node.call("/swap_lab_outpoint", self.query)
        new = self.node.call("/get_swap_outpoint", self.query)
        self.assertEqual(old, new)
        self.assertEqual(new["status"], "OK")
        self.assertFalse(new["found"])
        self.assertEqual(new["tip_hash"], before)
        self.assertEqual(len(new["genesis_hash"]), 64)
        self.assertEqual(self.node.info()["top_block_hash"], before)

    def test_malformed_identifiers_reject_then_valid_retry_succeeds(self):
        for patch, status in (({"txid": "ab"}, "INVALID_TXID"),
                              ({"spend_tag": "gg" * 32}, "INVALID_SPEND_TAG")):
            self.assertEqual(self.node.call("/get_swap_outpoint", dict(self.query, **patch))["status"], status)
        self.assertEqual(self.node.call("/get_swap_outpoint", self.query)["status"], "OK")

    def test_request_limit_precedes_json_parse(self):
        with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
            self.node.call("/get_swap_outpoint", dict(self.query, padding="x" * 512))
        self.assertEqual(self.node.call("/get_swap_outpoint", self.query)["status"], "OK")

    def test_browser_origin_content_type_and_method_are_refused(self):
        for headers in ({"Origin": "https://browser.invalid"}, {"Content-Type": "text/plain"}):
            with self.assertRaisesRegex(RuntimeError, "HTTP 404"):
                self.node.call("/get_swap_outpoint", self.query, headers=headers)
        request = urllib.request.Request(f"http://127.0.0.1:{self.node.rpc}/get_swap_outpoint",
                                         headers={"Content-Type": "application/json"}, method="GET")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            lab.OPENER.open(request, timeout=5)
        self.assertEqual(caught.exception.code, 404)
        self.assertEqual(self.node.call("/get_swap_outpoint", self.query)["status"], "OK")


if __name__ == "__main__":
    unittest.main()
