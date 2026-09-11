"""Actual loopback HTTP and separate-process command/lock behavior."""
import base64
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from swap_runtime import __main__ as cli
from swap_runtime.common import SessionLock, new_private_file
from swap_runtime.rpc import LocalRpc, RpcError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        request = json.loads(body)
        self.server.requests.append((self.path, self.headers, request))
        status, data = self.server.reply(request)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.requests = []
        self.server.reply = lambda req: (200, json.dumps({'id': req.get('id'), 'result': {'ok': True}}).encode())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_decimal_amount_auth_and_no_environment_proxy(self):
        self.server.reply = lambda req: (200, ('{"id":"'+req['id']+'","result":{"value":0.00000001}}').encode())
        with patch.dict(os.environ, {'HTTP_PROXY': 'http://127.0.0.1:1', 'http_proxy': 'http://127.0.0.1:1'}):
            result = LocalRpc(self.endpoint, 'operator:private-cookie')('gettxout', ['a', 0, True])
        self.assertEqual(result['value'], Decimal('0.00000001'))
        path, headers, request = self.server.requests[0]
        self.assertEqual(path, '/')
        self.assertEqual(headers['Authorization'], 'Basic '+base64.b64encode(b'operator:private-cookie').decode())
        self.assertNotIn('Origin', headers)
        self.assertEqual(request['method'], 'gettxout')

    def test_native_wallet_and_read_paths(self):
        rpc = LocalRpc(self.endpoint)
        rpc.wallet('swap_role', {'rho': '11'*32})
        self.assertEqual(self.server.requests[0][0], '/json_rpc')
        self.server.reply = lambda req: (200, b'{"status":"OK","height":4}')
        self.assertEqual(rpc.daemon('get_swap_outpoint', {'txid': '22'*32, 'index': 0})['height'], 4)
        self.assertEqual(self.server.requests[1][0], '/get_swap_outpoint')

    def test_wrong_id_and_remote_error_are_redacted(self):
        for data in (b'{"id":"wrong","result":true}',
                     b'{"id":"1","error":{"code":-1,"message":"PRIVATE_SECRET_WIRE"}}'):
            self.server.reply = lambda req, data=data: (500, data)
            with self.assertRaises(RpcError) as error:
                LocalRpc(self.endpoint)('sendrawtransaction', ['PRIVATE_SECRET_WIRE'])
            self.assertNotIn('PRIVATE_SECRET_WIRE', str(error.exception))

    def test_duplicate_nonfinite_nonobject_redirect_and_oversize_rejected(self):
        for status, data in ((200, b'{"id":"1","id":"1","result":true}'),
                             (200, b'{"id":"1","result":NaN}'), (200, b'[]'),
                             (302, b'{}'), (200, b'x'*(8*1024*1024+1))):
            self.server.reply = lambda req, status=status, data=data: (status, data)
            with self.assertRaises(RpcError):
                LocalRpc(self.endpoint)('test', [])

    def test_only_explicit_loopback_and_safe_method_are_accepted(self):
        for endpoint in ('http://localhost:1', 'https://127.0.0.1:1', 'http://127.0.0.1',
                         'http://127.0.0.1:1/wallet/a', 'http://u:p@127.0.0.1:1',
                         'http://127.0.0.1:1?q=a', 'http://127.0.0.1:1#f'):
            with self.assertRaises(ValueError):
                LocalRpc(endpoint)
        with self.assertRaises(RpcError):
            LocalRpc(self.endpoint).daemon('../json_rpc', {})
        self.assertEqual(len(self.server.requests), 0)


class CliAndFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHONDONTWRITEBYTECODE='1')

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-B', '-m', 'swap_runtime', *args],
                              env=self.env, capture_output=True, text=True, timeout=15)

    def test_keygen_never_overwrites_or_displays_key(self):
        path = self.root/'key'
        first = self.run_cli('keygen', '--journal-key', str(path))
        self.assertEqual(first.returncode, 0, first.stderr)
        key = path.read_text().strip()
        self.assertEqual(len(bytes.fromhex(key)), 32)
        self.assertNotIn(key, first.stdout+first.stderr)
        second = self.run_cli('keygen', '--journal-key', str(path))
        self.assertEqual(second.returncode, 1)
        self.assertEqual(path.read_text().strip(), key)
        self.assertNotIn(key, second.stdout+second.stderr)

    def test_configuration_duplicate_fields_and_nan_rejected(self):
        for n, data in enumerate((b'{"role":"xds-owner","role":"foreign-owner"}', b'{"amount":NaN}')):
            path = self.root/str(n)
            new_private_file(path, data)
            with self.assertRaises(ValueError):
                cli._json(path)

    def test_actual_child_lock_conflict_then_release(self):
        path = self.root/'session.db'
        lock = SessionLock(path)
        script = 'from swap_runtime.common import SessionLock; import sys; x=SessionLock(sys.argv[1]); x.close()'
        child = subprocess.run([sys.executable, '-B', '-c', script, str(path)], env=self.env,
                               capture_output=True, text=True, timeout=15)
        self.assertNotEqual(child.returncode, 0)
        lock.close()
        child = subprocess.run([sys.executable, '-B', '-c', script, str(path)], env=self.env,
                               capture_output=True, text=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_unknown_outcome_cli_does_not_print_credentials(self):
        key = self.root/'key'
        new_private_file(key, b'aa'*32)
        invalid = self.root/'rpc'
        new_private_file(invalid, b'{"credential":"PRIVATE_COOKIE_VALUE"}')
        result = self.run_cli('observe', '--journal-key', str(key), '--journal', str(self.root/'absent.db'),
                              '--rpc-config', str(invalid), '--swap-id', 'case')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('PRIVATE_COOKIE_VALUE', result.stdout+result.stderr)
        self.assertNotIn('Traceback', result.stdout+result.stderr)
        self.assertFalse((self.root/'absent.db').exists())


if __name__ == '__main__':
    unittest.main()
