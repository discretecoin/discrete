"""Independent monotonic checkpoint service; no wallet material is accepted.

The external database and pinned endpoint/profile must remain outside the owner
backup domain. Rolling back BOTH owner and anchor is not detectable here. TLS
authenticates fresh reads; owner Ed25519 signatures authorize append-only CAS.
There are no retries, force updates, resets or unauthenticated local fallbacks.
"""
import argparse
import datetime
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import sqlite3
import ssl
import threading
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .common import SessionLock, canonical, hex_bytes, integer, new_private_file, private_read, strict_json


MAX_WIRE = 4096
MAX_CHECKPOINTS = 100000
MAX_DATABASE = 128 * 1024 * 1024
ZERO = '00' * 32
CHECKPOINT_DOMAIN = b'xds-external-checkpoint-v1\0'
REQUEST_DOMAIN = b'xds-external-checkpoint-request-v1\0'
HEAD_FIELDS = {'version', 'service_id', 'stream_id', 'sequence', 'record_hash', 'commitment', 'recovery'}
CHECKPOINT_FIELDS = {'version', 'service_id', 'stream_id', 'sequence', 'previous', 'commitment', 'recovery'}


class AnchorError(ValueError):
    pass


class AnchorUncertain(AnchorError):
    """An operation may have committed. Retain Pending and explicitly reconcile."""


class AnchorConflict(AnchorError):
    pass


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _bounded(value):
    try:
        raw = canonical(value)
        if len(raw) > MAX_WIRE:
            raise ValueError('Bound exceeded')
        return strict_json(raw)
    except Exception:
        raise AnchorError('Bounded canonical checkpoint JSON required') from None


def _identity(service_id, stream_id):
    hex_bytes(service_id, 32, 'anchor service identity')
    hex_bytes(stream_id, 32, 'anchor stream identity')


def _checkpoint(value, service_id, stream_id):
    value = _bounded(value)
    if (type(value) is not dict or set(value) != CHECKPOINT_FIELDS
            or type(value['version']) is not int or value['version'] != 1
            or value['service_id'] != service_id or value['stream_id'] != stream_id
            or type(value['recovery']) is not bool):
        raise AnchorError('Checkpoint schema or pinned identity differs')
    integer(value['sequence'], 'checkpoint sequence', 1, MAX_CHECKPOINTS)
    hex_bytes(value['previous'], 32, 'previous checkpoint')
    hex_bytes(value['commitment'], 32, 'opaque state commitment')
    return value


def _pending(value, service_id, stream_id, public_key):
    if type(value) is not dict or set(value) != {'checkpoint', 'signature'}:
        raise AnchorError('Exact signed Pending required')
    checkpoint = _checkpoint(value['checkpoint'], service_id, stream_id)
    try:
        public_key.verify(hex_bytes(value['signature'], 64, 'checkpoint signature'),
                          CHECKPOINT_DOMAIN + canonical(checkpoint))
    except Exception:
        raise AnchorError('Checkpoint writer authentication failed') from None
    return dict(checkpoint=checkpoint, signature=value['signature'])


def _from_checkpoint(checkpoint):
    return {k: v for k, v in checkpoint.items() if k != 'previous'} | {'record_hash': _hash(canonical(checkpoint))}


def _genesis(service_id, stream_id, public_key):
    encoded = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    digest = _hash(canonical(['xds-anchor-genesis-v1', service_id, stream_id, encoded]))
    return dict(version=1, service_id=service_id, stream_id=stream_id, sequence=0,
                record_hash=digest, commitment=ZERO, recovery=False)


def _head(value, service_id, stream_id, public_key):
    value = _bounded(value)
    if (type(value) is not dict or set(value) != HEAD_FIELDS
            or type(value['version']) is not int or value['version'] != 1
            or value['service_id'] != service_id or value['stream_id'] != stream_id
            or type(value['recovery']) is not bool):
        raise AnchorError('Checkpoint head schema or pinned identity differs')
    integer(value['sequence'], 'checkpoint sequence', 0, MAX_CHECKPOINTS)
    hex_bytes(value['record_hash'], 32, 'checkpoint identity')
    hex_bytes(value['commitment'], 32, 'opaque state commitment')
    if value['sequence'] == 0 and value != _genesis(service_id, stream_id, public_key):
        raise AnchorError('Checkpoint genesis differs from pinned writer')
    return value


class AnchorClient:
    """One call per operation. Remote use requires PinnedHTTPS or equivalent trust.

    Persist the exact result of prepare before submit. A transport exception is
    uncertain, never evidence of absence. reconcile returns committed only when
    the CURRENT authenticated head equals that exact Pending, not an old entry.
    """
    def __init__(self, transport, *, service_id, stream_id, writer_key):
        _identity(service_id, stream_id)
        if not callable(transport) or not isinstance(writer_key, Ed25519PrivateKey):
            raise AnchorError('Explicit transport and checkpoint signing key required')
        self.transport, self.service_id, self.stream_id = transport, service_id, stream_id
        self.writer_key, self.public_key = writer_key, writer_key.public_key()

    def _call(self, operation, pending=None):
        nonce = os.urandom(32).hex()
        request = dict(version=1, operation=operation, service_id=self.service_id,
                       stream_id=self.stream_id, nonce=nonce)
        if pending is not None:
            request['pending'] = pending
        request['signature'] = self.writer_key.sign(REQUEST_DOMAIN + canonical(request)).hex()
        try:
            response = _bounded(self.transport(request))
        except Exception:
            raise AnchorUncertain('Anchor response unavailable; retain the exact pending checkpoint') from None
        if (type(response) is not dict or set(response) != {'version', 'service_id', 'stream_id', 'nonce', 'status', 'head'}
                or type(response['version']) is not int or response['version'] != 1
                or response['service_id'] != self.service_id or response['stream_id'] != self.stream_id
                or response['nonce'] != nonce or response['status'] not in ('head', 'advanced', 'existing', 'conflict')):
            raise AnchorUncertain('Anchor response binding rejected; retain the exact pending checkpoint')
        try:
            response['head'] = _head(response['head'], self.service_id, self.stream_id, self.public_key)
        except Exception:
            raise AnchorUncertain('Anchor head rejected; retain the exact pending checkpoint') from None
        return response

    def read(self):
        result = self._call('read')
        if result['status'] != 'head':
            raise AnchorError('Anchor did not provide a fresh head')
        return result['head']

    def prepare(self, previous, commitment, recovery):
        previous = _head(previous, self.service_id, self.stream_id, self.public_key)
        hex_bytes(commitment, 32, 'opaque state commitment')
        if type(recovery) is not bool or (previous['recovery'] and not recovery):
            raise AnchorError('Anchor recovery is irreversible')
        checkpoint = dict(version=1, service_id=self.service_id, stream_id=self.stream_id,
            sequence=previous['sequence'] + 1, previous=previous['record_hash'], commitment=commitment, recovery=recovery)
        _checkpoint(checkpoint, self.service_id, self.stream_id)
        return dict(checkpoint=checkpoint, signature=self.writer_key.sign(CHECKPOINT_DOMAIN + canonical(checkpoint)).hex())

    def submit(self, pending):
        pending = _pending(pending, self.service_id, self.stream_id, self.public_key)
        result = self._call('append', pending)
        if (result['status'] not in ('advanced', 'existing')
                or result['head'] != _from_checkpoint(pending['checkpoint'])):
            raise AnchorConflict('External checkpoint differs; normal local publication refused')
        return result['head']

    def reconcile(self, pending):
        pending = _pending(pending, self.service_id, self.stream_id, self.public_key)
        current, checkpoint = self.read(), pending['checkpoint']
        if current == _from_checkpoint(checkpoint):
            status = 'committed'
        elif current['sequence'] == checkpoint['sequence'] - 1 and current['record_hash'] == checkpoint['previous']:
            status = 'not-committed'
        else:
            status = 'conflict'
        return dict(status=status, head=current)


class AnchorStore:
    """One externally provisioned stream, verified against immutable public pins.

    Private TLS keys belong to the transport. This database holds only public
    configuration, owner signatures and opaque commitments. Whole-anchor rollback
    requires an independent provider/storage guarantee and is not claimed here.
    """
    def __init__(self, path, *, service_id, stream_id, writer_public_key, create=False):
        _identity(service_id, stream_id)
        self.public_key = Ed25519PublicKey.from_public_bytes(hex_bytes(writer_public_key, 32, 'checkpoint writer'))
        self.profile = dict(version=1, service_id=service_id, stream_id=stream_id, writer_public_key=writer_public_key)
        self.service_id, self.stream_id = service_id, stream_id
        self.path, self.lock, self.db = Path(path).absolute(), None, None
        self.mutex = threading.RLock()
        if type(create) is not bool or self.path.is_symlink():
            raise AnchorError('Regular external checkpoint database required')
        try:
            self.lock = SessionLock(self.path)
            if create:
                new_private_file(self.path, b'')
            elif not self.path.is_file():
                raise AnchorError('External checkpoint absent; no automatic initialization')
            self.db = sqlite3.connect(self.path, isolation_level=None, timeout=5, check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            if create:
                self.db.executescript('''BEGIN IMMEDIATE;
                    CREATE TABLE profile(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
                    CREATE TABLE head(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
                    CREATE TABLE checkpoints(seq INTEGER PRIMARY KEY, record_hash TEXT UNIQUE NOT NULL, pending BLOB NOT NULL);
                    CREATE TRIGGER no_checkpoint_update BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT,'append only'); END;
                    CREATE TRIGGER no_checkpoint_delete BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT,'append only'); END;
                    CREATE TRIGGER no_profile_update BEFORE UPDATE ON profile BEGIN SELECT RAISE(ABORT,'pinned identity'); END;
                    CREATE TRIGGER no_profile_delete BEFORE DELETE ON profile BEGIN SELECT RAISE(ABORT,'pinned identity'); END;
                    CREATE TRIGGER no_head_delete BEFORE DELETE ON head BEGIN SELECT RAISE(ABORT,'retained head'); END;
                    PRAGMA user_version=1; COMMIT;''')
                with self.db:
                    self.db.execute('BEGIN IMMEDIATE')
                    self.db.execute('INSERT INTO profile VALUES(1,?)', (canonical(self.profile),))
                    self.db.execute('INSERT INTO head VALUES(1,?)', (canonical(_genesis(service_id, stream_id, self.public_key)),))
            self._audit()
        except BaseException:
            self.close()
            raise

    def _audit(self):
        if (self.db.execute('PRAGMA user_version').fetchone()[0] != 1
                or self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok'
                or self.db.execute('PRAGMA page_count').fetchone()[0] * self.db.execute('PRAGMA page_size').fetchone()[0] > MAX_DATABASE
                or self.db.execute('SELECT id,value FROM profile').fetchall() != [(1, canonical(self.profile))]):
            raise AnchorError('External checkpoint schema, identity or integrity differs')
        current = _genesis(self.service_id, self.stream_id, self.public_key)
        for sequence, digest, encoded in self.db.execute('SELECT seq,record_hash,pending FROM checkpoints ORDER BY seq'):
            if not isinstance(encoded, bytes) or len(encoded) > MAX_WIRE:
                raise AnchorError('Stored checkpoint size rejected')
            pending = _pending(strict_json(encoded), self.service_id, self.stream_id, self.public_key)
            cp = pending['checkpoint']
            following = _from_checkpoint(cp)
            if (canonical(pending) != encoded or sequence != current['sequence'] + 1 or cp['sequence'] != sequence
                    or cp['previous'] != current['record_hash'] or following['record_hash'] != digest
                    or (current['recovery'] and not cp['recovery'])):
                raise AnchorError('External checkpoint chain differs')
            current = following
        if self.db.execute('SELECT id,value FROM head').fetchall() != [(1, canonical(current))]:
            raise AnchorError('External checkpoint head differs from retained history')
        self.current = current

    def _check(self):
        count, last = self.db.execute('SELECT COUNT(*),COALESCE(MAX(seq),0) FROM checkpoints').fetchone()
        if (count != self.current['sequence'] or count != last
                or self.db.execute('SELECT id,value FROM head').fetchall() != [(1, canonical(self.current))]):
            raise AnchorError('External checkpoint changed outside its active writer')

    def handle(self, request):
        request = _bounded(request)
        fields = {'version', 'operation', 'service_id', 'stream_id', 'nonce', 'signature'}
        if type(request) is dict and request.get('operation') == 'append':
            fields.add('pending')
        if (type(request) is not dict or set(request) != fields or type(request['version']) is not int
                or request['version'] != 1 or request['operation'] not in ('read', 'append')
                or request['service_id'] != self.service_id or request['stream_id'] != self.stream_id):
            raise AnchorError('Checkpoint request schema or identity rejected')
        hex_bytes(request['nonce'], 32, 'fresh checkpoint nonce')
        try:
            unsigned = {k: v for k, v in request.items() if k != 'signature'}
            self.public_key.verify(hex_bytes(request['signature'], 64, 'request signature'), REQUEST_DOMAIN + canonical(unsigned))
        except Exception:
            raise AnchorError('Checkpoint request authentication failed') from None
        with self.mutex:
            self._check()
            status = 'head'
            if request['operation'] == 'append':
                pending = _pending(request['pending'], self.service_id, self.stream_id, self.public_key)
                cp, encoded = pending['checkpoint'], canonical(pending)
                following = _from_checkpoint(cp)
                self.db.execute('BEGIN IMMEDIATE')
                try:
                    self._check()
                    old = self.db.execute('SELECT pending FROM checkpoints WHERE record_hash=?', (following['record_hash'],)).fetchone()
                    if old is not None:
                        status = 'existing' if old[0] == encoded else 'conflict'
                    elif (cp['sequence'] != self.current['sequence'] + 1 or cp['previous'] != self.current['record_hash']
                          or (self.current['recovery'] and not cp['recovery'])):
                        status = 'conflict'
                    else:
                        self.db.execute('INSERT INTO checkpoints VALUES(?,?,?)', (cp['sequence'], following['record_hash'], encoded))
                        self.db.execute('UPDATE head SET value=? WHERE id=1', (canonical(following),))
                        if self.db.execute('PRAGMA page_count').fetchone()[0] * self.db.execute('PRAGMA page_size').fetchone()[0] > MAX_DATABASE:
                            raise AnchorError('External checkpoint storage bound reached')
                        status = 'advanced'
                    self.db.execute('COMMIT')
                    if status == 'advanced':
                        self.current = following
                except BaseException:
                    if self.db.in_transaction:
                        self.db.execute('ROLLBACK')
                    raise
            return dict(version=1, service_id=self.service_id, stream_id=self.stream_id,
                        nonce=request['nonce'], status=status, head=dict(self.current))

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class PinnedHTTPS:
    """A fresh TLS connection per call; exact certificate pin replaces CA lookup.

    The pin, endpoint and anchor identity must be provisioned independently from
    the wallet backup. No request is sent until TLS possession and the DER pin
    and validity dates have been checked. No proxies, redirects or retries.
    """
    def __init__(self, endpoint, certificate_sha256, timeout=5):
        hex_bytes(certificate_sha256, 32, 'anchor TLS certificate fingerprint')
        integer(timeout, 'anchor timeout', 1, 60)
        try:
            parsed = urlsplit(endpoint)
            if (type(endpoint) is not str or not 1 <= len(endpoint) <= 2048 or not endpoint.isascii()
                    or any(ord(c) <= 32 or ord(c) == 127 for c in endpoint)
                    or parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/')
                    or parsed.port is None or not 1 <= parsed.port <= 65535):
                raise ValueError('Endpoint')
        except Exception:
            raise AnchorError('Explicit HTTPS endpoint and port required') from None
        self.host, self.port, self.pin, self.timeout = parsed.hostname, parsed.port, certificate_sha256, timeout

    def __call__(self, request):
        wire = canonical(_bounded(request))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=context)
        try:
            connection.connect()
            certificate = connection.sock.getpeercert(binary_form=True)
            parsed = x509.load_der_x509_certificate(certificate)
            now = datetime.datetime.now(datetime.timezone.utc)
            if (not hmac.compare_digest(_hash(certificate), self.pin)
                    or not parsed.not_valid_before_utc <= now <= parsed.not_valid_after_utc):
                raise AnchorError('Pinned TLS identity rejected')
            connection.request('POST', '/v1/checkpoint', wire,
                {'Content-Type': 'application/json', 'Connection': 'close', 'Cache-Control': 'no-store'})
            response = connection.getresponse()
            data = response.read(MAX_WIRE + 1)
            if response.status != 200 or len(data) > MAX_WIRE:
                raise AnchorError('Checkpoint HTTP response rejected')
            return _bounded(strict_json(data))
        except Exception:
            raise AnchorUncertain('Pinned checkpoint transport failed; retain pending state') from None
        finally:
            connection.close()


def client_from_profile(path):
    """Load independent pins and a separate private Ed25519 seed; no network I/O.

    Relative writer_key_file paths resolve beside the profile. The caller must
    retain both profile and provider identity outside the owner backup domain.
    Endpoint/profile replacement is an explicit operator trust decision.
    """
    try:
        path = Path(path).absolute()
        profile = strict_json(private_read(path, MAX_WIRE))
        fields = {'version', 'service_id', 'stream_id', 'endpoint', 'certificate_sha256', 'writer_key_file'}
        if (type(profile) is not dict or set(profile) not in (fields, fields | {'timeout'})
                or type(profile['version']) is not int or profile['version'] != 1
                or type(profile['writer_key_file']) is not str
                or not 1 <= len(profile['writer_key_file']) <= 2048 or '\0' in profile['writer_key_file']):
            raise AnchorError('Exact independent checkpoint client profile required')
        _identity(profile['service_id'], profile['stream_id'])
        transport = PinnedHTTPS(profile['endpoint'], profile['certificate_sha256'], profile.get('timeout', 5))
        key_path = Path(profile['writer_key_file'])
        if not key_path.is_absolute(): key_path = path.parent / key_path
        seed = hex_bytes(private_read(key_path, 128).decode('ascii').strip(), 32, 'checkpoint writer seed')
        return AnchorClient(transport, service_id=profile['service_id'], stream_id=profile['stream_id'],
                            writer_key=Ed25519PrivateKey.from_private_bytes(seed))
    except Exception:
        raise AnchorError('Independent checkpoint client profile or key rejected') from None


class AnchorServer(HTTPServer):
    """Serial, bounded loopback TLS endpoint for an independently operated store."""
    def __init__(self, store, context, *, port=0):
        if not isinstance(store, AnchorStore) or not isinstance(context, ssl.SSLContext):
            raise AnchorError('Checkpoint store and TLS server context required')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.store, self.context = store, context
        super().__init__(('127.0.0.1', integer(port, 'checkpoint listen port', 0, 65535)), _Handler)

    def get_request(self):
        stream, address = super().get_request()
        stream.settimeout(5)
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except BaseException:
            stream.close()
            raise


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if (self.path != '/v1/checkpoint' or self.headers.get('Transfer-Encoding') is not None
                    or self.headers.get('Content-Type') != 'application/json' or len(lengths) != 1
                    or not lengths[0].isascii() or not lengths[0].isdigit()):
                raise AnchorError('HTTP framing')
            length = integer(int(lengths[0]), 'checkpoint request bytes', 1, MAX_WIRE)
            raw = self.rfile.read(length)
            if len(raw) != length: raise AnchorError('Truncated checkpoint request')
            result = self.server.store.handle(strict_json(raw))
            self._reply(200, result)
        except Exception:
            self._reply(400, {'error': 'checkpoint-request-rejected'})

    def _reply(self, status, result):
        data = canonical(result)
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
        except (OSError, ValueError):
            pass
        self.close_connection = True


class _Parser(argparse.ArgumentParser):
    def error(self, _):
        raise AnchorError('Checkpoint service arguments rejected')


def main(argv=None):
    parser = _Parser(description='Independent owned checkpoint service; public profile, no wallet keys')
    parser.add_argument('action', choices=('init', 'serve'))
    parser.add_argument('--database', required=True)
    parser.add_argument('--profile', required=True, help='public service_id/stream_id/writer_public_key JSON')
    parser.add_argument('--certificate')
    parser.add_argument('--tls-key')
    parser.add_argument('--port', type=int, default=9443)
    try:
        args = parser.parse_args(argv)
        profile = strict_json(private_read(args.profile, MAX_WIRE))
        if (type(profile) is not dict or set(profile) != {'version', 'service_id', 'stream_id', 'writer_public_key'}
                or type(profile['version']) is not int or profile['version'] != 1):
            raise AnchorError('Exact public checkpoint profile required')
        if args.action == 'init' and (args.certificate or args.tls_key):
            raise AnchorError('Initialization does not use TLS credentials')
        if args.action == 'serve':
            integer(args.port, 'checkpoint port', 1, 65535)
            private_read(args.certificate, 65536)
            private_read(args.tls_key, 65536)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.certificate, args.tls_key)
        with AnchorStore(args.database, **{k: v for k, v in profile.items() if k != 'version'}, create=args.action == 'init') as store:
            if args.action == 'init':
                print(canonical({'initialized': True, 'head': store.current}).decode(), flush=True)
                return 0
            with AnchorServer(store, context, port=args.port) as server:
                print(canonical({'listening': True, 'port': server.server_port}).decode(), flush=True)
                server.serve_forever()
        return 0
    except (Exception, KeyboardInterrupt):
        print(canonical({'error': 'checkpoint-service-refused-or-stopped'}).decode(), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
