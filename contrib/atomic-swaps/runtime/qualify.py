"""Repeatable offline qualification; detailed receipts remain local."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parent


def hashes():
    paths = list((ROOT/'swap_runtime').glob('*.py')) + list((ROOT/'tests').glob('*.py'))
    paths += list((ROOT/'solana_fixture').glob('*.py'))
    paths += list((ROOT.parent/'solana').glob('*.py')) + list((ROOT.parent/'solana/tests').glob('*.py'))
    paths += list((ROOT.parent/'solana/src').glob('*.rs'))
    paths += [Path(__file__).resolve(), ROOT/'requirements.txt', ROOT.parent/'solana/Cargo.lock', ROOT.parent/'solana/Cargo.toml',
              ROOT.parent/'lab/swap-vps-v05/sbf-v3/test_solana_vm.py']
    paths += list((ROOT/'tests/fixtures/solana-v06').glob('*.json'))
    paths += list((ROOT/'tests/fixtures/solana-v06').glob('*.so'))
    return {p.relative_to(ROOT.parent).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new local output directory')
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    # This command qualifies the committed fixture, irrespective of inherited
    # test environment overrides. Standalone VM tests still accept other builds.
    os.environ['XDS_SOLANA_BUILD'] = str(ROOT/'tests/fixtures/solana-v06')
    sys.path[:0] = [str(ROOT), str(ROOT/'tests'), str(ROOT.parent/'solana/tests')]
    modules = ['test_bitcoin', 'test_journal', 'test_session', 'test_xds', 'test_solana',
               'test_transport_cli', 'test_profile', 'test_vm',
               'test_bitcoin_funding', 'test_xds_funding', 'test_xds_discovery',
               'test_solana_funding', 'test_lifecycle_store', 'test_lifecycle_settlement',
               'test_owner_protocol', 'test_owner', 'test_owner_cli', 'test_owner_recovery',
               'test_owner_solana', 'test_anchor', 'test_xds_preparation',
               'test_anchored_owner', 'test_owner_hardening_cli', 'test_solana_fixture']
    before = hashes()
    started = time.time()
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    with (output/'tests.log').open('w', encoding='utf8') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    after = hashes()
    receipt = {'schema': 1, 'scope': 'offline unit, crypto, abrupt process exit, loopback HTTP/TLS, CLI processes and compiled-ELF LiteSVM',
               'python': sys.version, 'tests_run': result.testsRun, 'skipped': len(result.skipped),
               'failures': len(result.failures), 'errors': len(result.errors),
               'seconds': round(time.time()-started, 3), 'source_unchanged': before == after,
               'source_sha256': after,
               'log_sha256': hashlib.sha256((output/'tests.log').read_bytes()).hexdigest(),
               'pass': result.wasSuccessful() and not result.skipped and before == after}
    (output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf8')
    # Only aggregate counters are printed. Detailed logs/receipts are neither
    # printed nor uploaded by the workflow, including on failure.
    print(json.dumps({k: receipt[k] for k in ('tests_run', 'skipped', 'failures', 'errors', 'seconds', 'source_unchanged', 'pass')}))
    return 0 if receipt['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
