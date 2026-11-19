"""Run in a Linux network namespace with loopback up and no other interfaces."""

import argparse
import fcntl
from pathlib import Path
import socket
import subprocess
import tempfile


def check_startup(binary, directory):
    data = directory / "chain"
    database = data / "blockchain.lmdb"
    database.mkdir(parents=True)
    wallet = directory / "test.wallet"
    args = [
        str(binary), "--local", "--testnet", "--data-dir", str(data),
        "--p2p-bind-ip", "127.0.0.1", "--p2p-bind-port", "0",
        "--generate-container", "--container-file", str(wallet),
        "--container-password", "fixture-only",
    ]

    def run(name):
        log = directory / (name + ".log")
        process = subprocess.run(args + ["--log-file", str(log)], cwd=directory,
                                 capture_output=True, text=True, timeout=60)
        return process, log.read_text()

    with (database / "db.lock").open("wb") as locked:
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        refused, log = run("locked")
        if refused.returncode != 1 or "Failed to initialize blockchain core" not in refused.stderr:
            raise RuntimeError(f"expected a Core startup error, got exit {refused.returncode}")
        if "already in use by another process" not in log or "Spawning p2p server" in log:
            raise RuntimeError("the database lock must stop startup before the P2P server runs")
        if wallet.exists() or (database / "data.mdb").exists():
            raise RuntimeError("refused startup created wallet or chain data")

    retry, log = run("retry")
    if retry.returncode != 0 or "Spawning p2p server" not in log:
        raise RuntimeError(f"unlocked retry did not start the embedded node (exit {retry.returncode})")
    if not wallet.is_file() or wallet.stat().st_size == 0 or not (database / "data.mdb").is_file():
        raise RuntimeError("unlocked retry did not create the disposable wallet and blockchain")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("walletd", type=Path)
    binary = parser.parse_args().walletd.resolve(strict=True)
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError(__doc__)
    with tempfile.TemporaryDirectory(prefix="walletd-local-") as temporary:
        check_startup(binary, Path(temporary))
    print("PASS: locked database refused; unlocked retry initialized Core and created the wallet")
