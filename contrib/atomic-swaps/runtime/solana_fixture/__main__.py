"""Explicit test-fixture commands; no mainnet/devnet endpoints are accepted."""
import argparse
from pathlib import Path
import sys

from swap_runtime.common import canonical, strict_json
from .bridge import create_bridge, init_client, serve
from .runner import run_validator
from .support import isolated_network, regular


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    run = commands.add_parser('run', help='Foreground private validator; Ctrl-C retains ledger and stops owned process')
    run.add_argument('--run-dir', type=Path, required=True)
    run.add_argument('--validator', type=Path, required=True)
    run.add_argument('--validator-sha256', required=True)
    run.add_argument('--max-seconds', type=int, default=1800)
    run.add_argument('--resume', action='store_true')
    server = commands.add_parser('serve', help='Framed stdio bridge inside the same loopback namespace')
    server.add_argument('--run-dir', type=Path, required=True)
    client = commands.add_parser('client', help='Create private local client identities for explicit transport argv')
    client.add_argument('--run-dir', type=Path, required=True)
    client.add_argument('--command-json', type=Path, required=True)
    info = commands.add_parser('info', help='Verify and print only the public fixture identity')
    info.add_argument('--run-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'run':
            run_validator(args.run_dir, args.validator, args.validator_sha256, args.max_seconds,
                args.resume, on_ready=lambda value: print(canonical(value).decode(), flush=True))
        elif args.action == 'serve':
            isolated_network()
            serve(args.run_dir, sys.stdin.buffer, sys.stdout.buffer)
        elif args.action == 'client':
            path = regular(args.command_json)
            if path.stat().st_size > 65536:
                raise ValueError('Bounded transport command file required')
            value = init_client(args.run_dir, strict_json(path.read_bytes()))
            print(canonical(value).decode())
        else:
            bridge = create_bridge(args.run_dir)
            try:
                print(canonical(bridge.ready).decode())
            finally:
                bridge.close()
    except Exception:
        # No command argv, key material, secret-bearing transaction or RPC body.
        print('Synthetic fixture operation failed; inspect private run evidence locally.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
