"""Explicit loopback HTTP RPC, without environment proxies or redirects.

Use authenticated local tunnels for remote owned nodes. Credentials are passed
in memory, never included in URLs, exceptions, evidence or command arguments.
"""
import base64
from decimal import Decimal
import http.client
from urllib.parse import urlsplit

from .common import canonical, strict_json


class RpcError(ValueError):
    pass


class LocalRpc:
    def __init__(self, endpoint, credentials=None, timeout=15):
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except (ValueError, TypeError):
            raise ValueError('Invalid RPC endpoint') from None
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in ('', '/')
                or port is None or not 1 <= port <= 65535
                or endpoint not in (f'http://127.0.0.1:{port}', f'http://127.0.0.1:{port}/')):
            raise ValueError('Literal loopback RPC endpoint with explicit port required')
        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise ValueError('Bounded RPC timeout required')
        if credentials is not None and (type(credentials) is not str or ':' not in credentials
                                         or any(c in credentials for c in '\r\n')):
            raise ValueError('Invalid RPC credentials')
        self.port, self.timeout, self.sequence = port, timeout, 0
        self.authorization = None if credentials is None else 'Basic ' + base64.b64encode(credentials.encode()).decode()

    def _post(self, path, body):
        wire = canonical(body)
        if len(wire) > 1024 * 1024:
            raise RpcError('RPC request exceeds size bound')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        try:
            headers = {'Content-Type': 'application/json', 'Connection': 'close'}
            if self.authorization:
                headers['Authorization'] = self.authorization
            connection.request('POST', path, wire, headers)
            response = connection.getresponse()
            data = response.read(8 * 1024 * 1024 + 1)
            if response.status not in (200, 500) or len(data) > 8 * 1024 * 1024:
                raise RpcError('RPC response status or size rejected')
            result = strict_json(data, parse_float=Decimal)
            if type(result) is not dict:
                raise RpcError('RPC object response required')
            return result
        except Exception:
            raise RpcError('Local RPC request failed or returned invalid data') from None
        finally:
            connection.close()

    def _json_rpc(self, path, method, params):
        self.sequence += 1
        request_id = str(self.sequence)
        result = self._post(path, {'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        if result.get('id') != request_id or result.get('error') is not None or 'result' not in result:
            raise RpcError('RPC identity mismatch or remote operation failed')
        return result['result']

    def __call__(self, method, params):
        return self._json_rpc('/', method, params)

    def wallet(self, method, params):
        return self._json_rpc('/json_rpc', method, params)

    def daemon(self, method, params):
        if type(method) is not str or not method.replace('_', '').isalnum():
            raise RpcError('Invalid daemon method')
        return self._post('/' + method, params)
