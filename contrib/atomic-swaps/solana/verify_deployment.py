"""Read-only deployment verification. No signing, writes, secrets or retries."""
import argparse
import json
from pathlib import Path
import urllib.request
from urllib.parse import urlsplit

from profile import verify_rpc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--rpc-url', required=True)
    parser.add_argument('--expected-upgrade-authority', help='Pre-freeze inspection ONLY; default requires immutability')
    args = parser.parse_args()
    endpoint = urlsplit(args.rpc_url)
    if endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username or endpoint.password:
        parser.error('Use an HTTP(S) RPC URL without embedded credentials')
    def rpc(method, params):
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        request = urllib.request.Request(args.rpc_url, data=payload, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError('RPC response exceeds the bounded account observation limit')
        body = json.loads(raw)
        if body.get('id') != 1 or body.get('jsonrpc') != '2.0' or 'error' in body or 'result' not in body:
            raise ValueError('RPC failed or returned a mismatched response')
        return body['result']
    receipt = verify_rpc(json.loads(args.manifest.read_text()), rpc,
                         expected_upgrade_authority=args.expected_upgrade_authority)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
