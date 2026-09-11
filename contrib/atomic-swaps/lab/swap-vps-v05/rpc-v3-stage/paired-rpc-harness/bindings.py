"""Read-only, hash-pinned reuse. Importing this module launches no process or RPC."""
from pathlib import Path
import hashlib
import importlib
import importlib.util
import sys

ROOT = Path(__file__).resolve().parent
V05 = ROOT.parent
PINS = {
    "solana-rpc-harness/driver.py": "1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3",
    "linux-harness/test_xds_wallet_network.py": "c85067f1ea0ea50e2e57de01845dc87a290f2b742cce85348b35720a3ce52330",
    "linux-harness/swap_journal.py": "8e935ecceaae034e1ae5ab0c8bccb4ed01ae4c78c799d9a0846eb084cf1c4792",
    "linux-harness/xds_localnet.py": "a44ea85438c46850937dc2af635bcacf86771e07bad5911838ffb387435079c5",
    "linux-harness/runtime_paths.py": "55d36a11c3346cd358789fb271910ee6d11167f8fa55a39bd9d59a66d0315210",
}


def verify_pins():
    for relative, digest in PINS.items():
        path = V05 / relative
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"frozen dependency hash mismatch: {relative}")
    return dict(PINS)


verify_pins()
spec = importlib.util.spec_from_file_location("paired_frozen_solana", V05 / "solana-rpc-harness/driver.py")
sol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sol)
sys.path.insert(0, str(V05 / "linux-harness"))
for name in ("runtime_paths", "swap_journal", "xds_localnet", "test_xds_wallet_network"):
    module = importlib.import_module(name)
    if Path(module.__file__).resolve() != (V05 / "linux-harness" / (name + ".py")).resolve():
        raise RuntimeError("unexpected preloaded XDS helper module")
xds = sys.modules["test_xds_wallet_network"]
localnet = sys.modules["xds_localnet"]
Admission = sys.modules["swap_journal"].Admission

