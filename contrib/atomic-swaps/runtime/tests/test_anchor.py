"""External checkpoint CAS, abrupt exit and loopback pinned TLS qualification.

Every identity and signing key here is a synthetic public test fixture. Child
processes and HTTPS listeners use temporary local files and loopback only.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout
import copy
import datetime
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from swap_runtime.anchor import (AnchorClient, AnchorConflict, AnchorError, AnchorServer,
    AnchorStore, AnchorUncertain, CHECKPOINT_DOMAIN, MAX_WIRE, PinnedHTTPS, REQUEST_DOMAIN,
    ZERO, client_from_profile, main)
from swap_runtime.common import canonical, new_private_file
import swap_runtime.anchor as anchor_module


KEY = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
SERVICE = '11' * 32
STREAM = '22' * 32
PROFILE = dict(service_id=SERVICE, stream_id=STREAM, writer_public_key=PUBLIC)


def request(operation='read', pending=None, key=KEY, **changes):
    value = dict(version=1, operation=operation, service_id=SERVICE, stream_id=STREAM, nonce='ab' * 32)
    if pending is not None: value['pending'] = pending
    value.update(changes)
    value['signature'] = key.sign(REQUEST_DOMAIN + canonical(value)).hex()
    return value


def resign(pending):
    result = copy.deepcopy(pending)
    result['signature'] = KEY.sign(CHECKPOINT_DOMAIN + canonical(result['checkpoint'])).hex()
    return result


class Fixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-anchor-test-')
        self.root = Path(self.temp.name)
        self.path = self.root / 'external.db'
        self.store = AnchorStore(self.path, **PROFILE, create=True)
        self.opened = [self.store]
        self.client = self.client_for(self.store.handle)

    def tearDown(self):
        for store in reversed(self.opened): store.close()
        self.temp.cleanup()

    def client_for(self, transport):
        return AnchorClient(transport, service_id=SERVICE, stream_id=STREAM, writer_key=KEY)

    def reopen(self):
        self.store.close()
        self.store = AnchorStore(self.path, **PROFILE)
        self.opened.append(self.store)
        self.client = self.client_for(self.store.handle)
        return self.store

    def pending(self, commitment='33' * 32, recovery=False):
        return self.client.prepare(self.client.read(), commitment, recovery)

    def count(self):
        return self.store.db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0]

    def child(self, stage, pending=None):
        args = [sys.executable, '-B', __file__, '--child', stage, str(self.path)]
        result = subprocess.run(args, input=canonical(request('append', pending)) if pending else b'',
            capture_output=True, timeout=20, cwd=ROOT,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout, b'')


class AnchorTests(Fixture, unittest.TestCase):
    def test_genesis_binds_service_stream_and_writer(self):
        head = self.client.read()
        self.assertEqual(set(head), {'version', 'service_id', 'stream_id', 'sequence', 'record_hash', 'commitment', 'recovery'})
        self.assertEqual(head['record_hash'], hashlib.sha256(canonical([
            'xds-anchor-genesis-v1', SERVICE, STREAM, PUBLIC])).hexdigest())
        self.assertEqual((head['sequence'], head['commitment'], head['recovery']), (0, ZERO, False))

    def test_exact_pending_current_retry_and_restart(self):
        pending = self.pending()
        head = self.client.submit(pending)
        self.assertEqual(head['record_hash'], hashlib.sha256(canonical(pending['checkpoint'])).hexdigest())
        self.assertEqual(self.client.submit(copy.deepcopy(pending)), head)
        self.assertEqual(self.count(), 1)
        self.reopen()
        self.assertEqual(self.client.read(), head)
        self.assertEqual(self.client.reconcile(pending), dict(status='committed', head=head))

    def test_old_exact_request_is_not_current_publication_authority(self):
        first = self.pending()
        self.client.submit(first)
        second = self.pending('44' * 32)
        second_head = self.client.submit(second)
        with self.assertRaises(AnchorConflict): self.client.submit(first)
        self.assertEqual(self.client.reconcile(first), dict(status='conflict', head=second_head))
        self.assertEqual(self.count(), 2)

    def test_competing_stale_compare_and_swap_refused(self):
        previous = self.client.read()
        first = self.client.prepare(previous, '33' * 32, False)
        alternative = self.client.prepare(previous, '44' * 32, False)
        self.client.submit(first)
        with self.assertRaises(AnchorConflict): self.client.submit(alternative)
        self.assertEqual(self.client.reconcile(alternative)['status'], 'conflict')
        self.assertEqual(self.count(), 1)

    def test_signed_wrong_predecessor_and_skipped_sequence_refused(self):
        for field, value in [('previous', ZERO), ('sequence', 2)]:
            with self.subTest(field=field):
                altered = self.pending()
                altered['checkpoint'][field] = value
                with self.assertRaises(AnchorConflict): self.client.submit(resign(altered))
        self.assertEqual(self.count(), 0)

    def test_recovery_is_irreversible_even_for_correct_writer_after_restart(self):
        self.client.submit(self.pending(recovery=True))
        self.reopen()
        with self.assertRaises(AnchorError): self.pending(recovery=False)
        invalid = self.pending(recovery=True)
        invalid['checkpoint']['recovery'] = False
        with self.assertRaises(AnchorConflict): self.client.submit(resign(invalid))
        self.assertTrue(self.client.read()['recovery'])
        self.client.submit(self.pending('44' * 32, True))
        self.assertEqual(self.count(), 2)

    def test_prepare_is_deterministic_and_does_not_mutate_previous(self):
        previous = self.client.read()
        retained = copy.deepcopy(previous)
        one = self.client.prepare(previous, '33' * 32, False)
        self.assertEqual(one, self.client.prepare(previous, '33' * 32, False))
        one['checkpoint']['commitment'] = '44' * 32
        self.assertEqual(previous, retained)
        self.assertEqual(self.client.read(), retained)
        self.assertEqual(self.count(), 0)

    def test_result_copies_cannot_mutate_server_head(self):
        head = self.client.submit(self.pending())
        head['sequence'] = 999
        self.assertEqual(self.client.read()['sequence'], 1)

    def test_wrong_request_writer_rejected_before_append(self):
        stranger = Ed25519PrivateKey.from_private_bytes(bytes([8]) * 32)
        with self.assertRaises(AnchorError):
            self.store.handle(request('append', self.pending(), key=stranger))
        self.assertEqual(self.count(), 0)

    def test_checkpoint_signature_is_verified_independently_of_request(self):
        pending = self.pending()
        pending['checkpoint']['commitment'] = '44' * 32
        with self.assertRaises(AnchorError): self.store.handle(request('append', pending))
        self.assertEqual(self.count(), 0)

    def test_request_binding_and_exact_fields(self):
        for changes in [dict(version=True), dict(service_id='55' * 32), dict(stream_id='66' * 32),
                        dict(nonce='ab'), dict(operation='reset'), dict(secret='forbidden')]:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError): self.store.handle(request(**changes))
        self.assertEqual(self.count(), 0)

    def test_pending_exact_schema_and_scalar_bounds(self):
        for field, value in [('version', True), ('sequence', True), ('sequence', 0),
                             ('sequence', 100001), ('recovery', 1), ('commitment', 'AB' * 32),
                             ('commitment', '00 ' * 32), ('previous', '00' * 31), ('secret', ZERO)]:
            with self.subTest(field=field, value=value):
                pending = self.pending()
                pending['checkpoint'][field] = value
                with self.assertRaises(ValueError): self.store.handle(request('append', resign(pending)))
        self.assertEqual(self.count(), 0)

    def test_size_bound_and_nonfinite_payload_refused(self):
        for value in [dict(extra='x' * MAX_WIRE), dict(extra=float('nan'))]:
            with self.subTest(value_type=type(value['extra']).__name__):
                with self.assertRaises(AnchorError): self.store.handle(value)
        self.assertEqual(self.count(), 0)

    def test_unknown_reply_never_retries_or_means_absent(self):
        pending = self.pending()
        calls = []
        def lose_ack(value):
            calls.append(copy.deepcopy(value))
            self.store.handle(value)
            raise TimeoutError('private transport diagnostic must not escape')
        client = self.client_for(lose_ack)
        with self.assertRaises(AnchorUncertain) as error: client.submit(pending)
        self.assertNotIn('private transport', str(error.exception))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.client.reconcile(pending)['status'], 'committed')
        self.assertEqual(self.client.submit(pending)['sequence'], 1)
        self.assertEqual(self.count(), 1)

    def test_failure_before_request_requires_explicit_fresh_readback(self):
        pending = self.pending()
        calls = []
        def unavailable(value):
            calls.append(value)
            raise ConnectionError('not connected')
        with self.assertRaises(AnchorUncertain): self.client_for(unavailable).submit(pending)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.client.reconcile(pending)['status'], 'not-committed')
        self.assertEqual(self.count(), 0)

    def test_nonce_replay_rejected_even_if_head_did_not_change(self):
        retained = []
        def replay(value):
            if not retained: retained.append(self.store.handle(value))
            return retained[0]
        client = self.client_for(replay)
        client.read()
        with self.assertRaises(AnchorUncertain): client.read()

    def test_nonce_changes_on_explicit_readback_and_exact_submit_retry(self):
        seen = []
        def transport(value):
            seen.append(value['nonce'])
            return self.store.handle(value)
        client = self.client_for(transport)
        pending = client.prepare(client.read(), '33' * 32, False)
        client.submit(pending)
        client.reconcile(pending)
        client.submit(pending)
        self.assertEqual(len(set(seen)), 4)

    def test_malformed_or_wrong_identity_reply_stays_uncertain(self):
        for changes in [dict(service_id='55' * 32), dict(version=True), dict(status='ok'),
                        dict(head={}), dict(extra='forbidden')]:
            with self.subTest(changes=changes):
                def transport(value):
                    return self.store.handle(value) | changes
                with self.assertRaises(AnchorUncertain): self.client_for(transport).read()

    def test_fake_success_wrong_current_head_is_not_publishable(self):
        pending = self.pending()
        def fake(value):
            read = request(nonce=value['nonce'])
            return self.store.handle(read) | dict(status='advanced')
        with self.assertRaises(AnchorConflict): self.client_for(fake).submit(pending)
        self.assertEqual(self.count(), 0)

    def test_two_concurrent_clients_only_one_checkpoint_wins(self):
        previous = self.client.read()
        candidates = [self.client.prepare(previous, byte * 64, False) for byte in ('3', '4')]
        barrier = threading.Barrier(2)
        def submit(pending):
            client = self.client_for(self.store.handle)
            barrier.wait(timeout=5)
            try: return client.submit(pending)['commitment']
            except AnchorConflict: return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, candidates))
        self.assertEqual(results.count('conflict'), 1)
        self.assertEqual(self.count(), 1)
        self.reopen()
        self.assertIn(self.client.read()['commitment'], results)

    def test_second_process_cannot_open_active_external_writer(self):
        self.child('locked')
        self.assertEqual(self.count(), 0)

    def test_real_exit_before_commit_rolls_back_and_retains_exact_retry(self):
        pending = self.pending()
        self.store.close()
        self.child('before-commit', pending)
        self.reopen()
        self.assertEqual(self.client.reconcile(pending)['status'], 'not-committed')
        self.assertEqual(self.count(), 0)
        self.client.submit(pending)
        self.assertEqual(self.count(), 1)

    def test_real_exit_after_commit_before_ack_recovers_exact_current_head(self):
        pending = self.pending()
        self.store.close()
        self.child('after-commit', pending)
        self.reopen()
        self.assertEqual(self.client.reconcile(pending)['status'], 'committed')
        self.assertEqual(self.count(), 1)
        self.client.submit(pending)
        self.assertEqual(self.count(), 1)

    def test_durable_database_contains_public_profile_not_writer_private_key(self):
        self.client.submit(self.pending())
        self.store.close()
        raw = self.path.read_bytes()
        self.assertIn(PUBLIC.encode(), raw)
        self.assertIn(b'checkpoint', raw)
        self.assertNotIn(bytes([7]) * 32, raw)
        self.assertNotIn((bytes([7]) * 32).hex().encode(), raw)

    def test_open_requires_existing_pinned_profile_and_never_reinitializes(self):
        self.store.close()
        retained = self.path.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            AnchorStore(self.path, **PROFILE, create=True)
        with self.assertRaises(AnchorError):
            AnchorStore(self.path, **(PROFILE | dict(service_id='55' * 32)))
        with self.assertRaises(AnchorError):
            AnchorStore(self.root / 'absent.db', **PROFILE)
        self.assertEqual(self.path.read_bytes(), retained)
        self.assertFalse((self.root / 'absent.db').exists())

    def test_signed_history_tamper_rejected_on_restart(self):
        self.client.submit(self.pending())
        self.store.close()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('DROP TRIGGER no_checkpoint_update')
            encoded = json.loads(db.execute('SELECT pending FROM checkpoints').fetchone()[0])
            encoded['checkpoint']['commitment'] = '44' * 32
            db.execute('UPDATE checkpoints SET pending=?', (canonical(encoded),))
        with self.assertRaises(AnchorError): AnchorStore(self.path, **PROFILE)

    def test_history_truncation_with_retained_head_rejected_on_restart(self):
        self.client.submit(self.pending())
        self.store.close()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('DROP TRIGGER no_checkpoint_delete')
            db.execute('DELETE FROM checkpoints')
        with self.assertRaises(AnchorError): AnchorStore(self.path, **PROFILE)

    def test_append_only_schema_prevents_accidental_history_mutation(self):
        self.client.submit(self.pending())
        for statement in ['DELETE FROM checkpoints', 'UPDATE checkpoints SET seq=2',
                          'DELETE FROM profile', 'UPDATE profile SET value=value', 'DELETE FROM head']:
            with self.subTest(statement=statement):
                with self.assertRaises(sqlite3.DatabaseError): self.store.db.execute(statement)
        self.assertEqual(self.client.read()['sequence'], 1)

    def test_whole_anchor_rollback_is_an_explicit_external_trust_boundary(self):
        genesis_copy = self.root / 'genesis.db'
        with closing(sqlite3.connect(genesis_copy)) as destination: self.store.db.backup(destination)
        pending = self.pending()
        retained_head = self.client.submit(pending)
        with AnchorStore(genesis_copy, **PROFILE) as rolled_back_provider:
            rollback_client = self.client_for(rolled_back_provider.handle)
            current = rollback_client.read()
            self.assertLess(current['sequence'], retained_head['sequence'])
            # The caller MUST compare its retained head and stop; the service
            # cannot discover a simultaneous rollback of all trusted domains.
            self.assertEqual(rollback_client.reconcile(pending)['status'], 'not-committed')


def certificate(root, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'owned-loopback-test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=-1 if expired else 1))
        .sign(key, hashes.SHA256()))
    certificate_path, key_path = root / 'tls.pem', root / 'tls.key'
    new_private_file(certificate_path, cert.public_bytes(Encoding.PEM))
    new_private_file(key_path, key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    return context, hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


class HTTPSAnchorTests(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        context, self.fingerprint = certificate(self.root)
        self.server = AnchorServer(self.store, context, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs=dict(poll_interval=.02), daemon=True)
        self.thread.start()
        self.endpoint = 'https://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        super().tearDown()

    def wire(self, body, headers=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, timeout=5, context=context)
        try:
            connection.request('POST', '/v1/checkpoint', body,
                headers=headers or {'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, response.read(MAX_WIRE + 1)
        finally: connection.close()

    def test_real_pinned_tls_current_cas_fresh_readback_and_no_proxy(self):
        transport = PinnedHTTPS(self.endpoint, self.fingerprint)
        client = self.client_for(transport)
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:1', 'ALL_PROXY': 'http://127.0.0.1:1'}):
            pending = client.prepare(client.read(), '33' * 32, False)
            head = client.submit(pending)
            self.assertEqual(client.reconcile(pending), dict(status='committed', head=head))
        self.assertEqual(self.count(), 1)

    def test_wrong_certificate_pin_sends_no_checkpoint_request(self):
        with patch.object(self.store, 'handle', wraps=self.store.handle) as handle:
            with self.assertRaises(AnchorUncertain):
                self.client_for(PinnedHTTPS(self.endpoint, ZERO)).read()
            self.assertEqual(handle.call_count, 0)

    def test_expired_pinned_certificate_sends_no_checkpoint_request(self):
        expired_root = self.root / 'expired'
        expired_root.mkdir()
        context, fingerprint = certificate(expired_root, expired=True)
        with AnchorServer(self.store, context) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=.02), daemon=True)
            thread.start()
            try:
                transport = PinnedHTTPS('https://127.0.0.1:' + str(server.server_port), fingerprint)
                with patch.object(self.store, 'handle', wraps=self.store.handle) as handle:
                    with self.assertRaises(AnchorUncertain): self.client_for(transport).read()
                    self.assertEqual(handle.call_count, 0)
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_duplicate_json_and_oversized_wire_return_fixed_error(self):
        for body in [b'{"version":1,"version":1}', b'x' * (MAX_WIRE + 1), b'not-json']:
            with self.subTest(length=len(body)):
                status, raw = self.wire(body)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(raw), dict(error='checkpoint-request-rejected'))
        self.assertEqual(self.count(), 0)

    def test_http_framing_and_authenticated_request_required(self):
        for body, headers in [(canonical(request()), {'Content-Type': 'text/plain'}),
                             (b'{}', {'Content-Type': 'application/json'}),
                             (b'', {'Content-Type': 'application/json', 'Content-Length': '0'})]:
            with self.subTest(body=body[:2], headers=headers):
                status, raw = self.wire(body, headers)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(raw), dict(error='checkpoint-request-rejected'))

    def test_redirect_response_is_not_followed(self):
        def redirect(handler):
            handler.send_response(307)
            handler.send_header('Location', 'https://127.0.0.1:1/')
            handler.send_header('Content-Length', '0')
            handler.end_headers()
        with patch.object(anchor_module._Handler, 'do_POST', redirect):
            with patch.object(self.store, 'handle', wraps=self.store.handle) as handle:
                with self.assertRaises(AnchorUncertain):
                    self.client_for(PinnedHTTPS(self.endpoint, self.fingerprint)).read()
                self.assertEqual(handle.call_count, 0)

    def test_network_nonce_replay_refused(self):
        retained = []
        original = self.store.handle
        def replay(value):
            if not retained: retained.append(original(value))
            return retained[0]
        with patch.object(self.store, 'handle', replay):
            client = self.client_for(PinnedHTTPS(self.endpoint, self.fingerprint))
            client.read()
            with self.assertRaises(AnchorUncertain): client.read()

    def test_https_network_lost_ack_has_no_automatic_second_append(self):
        pending = self.pending()
        original = anchor_module._Handler._reply
        def drop_reply(handler, status, value):
            if status == 200:
                handler.close_connection = True
                return
            return original(handler, status, value)
        client = self.client_for(PinnedHTTPS(self.endpoint, self.fingerprint))
        with patch.object(anchor_module._Handler, '_reply', drop_reply):
            with self.assertRaises(AnchorUncertain): client.submit(pending)
        self.assertEqual(self.count(), 1)
        self.assertEqual(client.reconcile(pending)['status'], 'committed')

    def test_endpoint_fingerprint_timeout_bounds(self):
        for endpoint in ['http://127.0.0.1:1', 'https://127.0.0.1', 'https://a:b@localhost:1',
                         'https://localhost:1/path', 'https://localhost:1/?query', 'https://localhost:1/#fragment',
                         'https://localhost:0', 'https://localhost:65536', 'https://localhost:9443\n',
                         ' https://localhost:9443', 'https://local\thost:9443']:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError): PinnedHTTPS(endpoint, self.fingerprint)
        for timeout in [0, 61, True, 1.5]:
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError): PinnedHTTPS(self.endpoint, self.fingerprint, timeout)
        with self.assertRaises(ValueError): PinnedHTTPS(self.endpoint, self.fingerprint.upper())


class AnchorCLITests(unittest.TestCase):
    def profile(self, root, changes=None, seed=None):
        path, key = root / 'client.json', root / 'writer.seed'
        new_private_file(key, seed if seed is not None else (bytes([7]) * 32).hex().encode() + b'\n')
        values = dict(version=1, service_id=SERVICE, stream_id=STREAM, endpoint='https://127.0.0.1:9443',
                      certificate_sha256='aa' * 32, writer_key_file='writer.seed')
        values.update(changes or {})
        new_private_file(path, canonical(values))
        return path

    def test_private_client_profile_uses_separate_key_and_does_no_network_io(self):
        with tempfile.TemporaryDirectory(prefix='anchor-profile-test-') as directory:
            path = self.profile(Path(directory))
            with patch.object(PinnedHTTPS, '__call__', side_effect=AssertionError('no connection')):
                client = client_from_profile(path)
            self.assertEqual(client.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), PUBLIC)
            self.assertEqual(client.transport.timeout, 5)
            self.assertEqual((client.service_id, client.stream_id), (SERVICE, STREAM))
            self.assertNotIn((bytes([7]) * 32).hex().encode(), path.read_bytes())

    def test_client_profile_rejects_ambiguous_or_untrusted_fields(self):
        for changes in [dict(version=True), dict(timeout=True), dict(timeout=0), dict(secret=ZERO),
                        dict(writer_key_file=''), dict(endpoint='http://127.0.0.1:9443'),
                        dict(service_id='11'), dict(certificate_sha256='aa')]:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory(prefix='anchor-profile-test-') as directory:
                path = self.profile(Path(directory), changes)
                with self.assertRaises(AnchorError): client_from_profile(path)

    def test_client_profile_rejects_wrong_key_encoding_and_size(self):
        for seed in [b'private-do-not-echo', b'AA' * 32, b'00' * 33, b'00' * 65, b'[1,2,3]']:
            with self.subTest(length=len(seed)), tempfile.TemporaryDirectory(prefix='anchor-profile-test-') as directory:
                path = self.profile(Path(directory), seed=seed)
                with self.assertRaises(AnchorError) as error: client_from_profile(path)
                self.assertNotIn('private-do-not-echo', str(error.exception))

    def test_client_profile_duplicate_fields_and_world_readable_key_refused(self):
        with tempfile.TemporaryDirectory(prefix='anchor-profile-test-') as directory:
            root = Path(directory)
            path = self.profile(root)
            if os.name != 'nt':
                (root / 'writer.seed').chmod(0o644)
                with self.assertRaises(AnchorError): client_from_profile(path)
                (root / 'writer.seed').chmod(0o600)
            path.write_bytes(path.read_bytes()[:-1] + b',"version":1}')
            with self.assertRaises(AnchorError): client_from_profile(path)

    def test_init_once_public_profile_and_existing_service_restart(self):
        with tempfile.TemporaryDirectory(prefix='anchor-cli-test-') as directory:
            root = Path(directory)
            profile, database = root / 'profile.json', root / 'external.db'
            new_private_file(profile, canonical(dict(version=1, **PROFILE)))
            arguments = ['init', '--database', str(database), '--profile', str(profile)]
            output = io.StringIO()
            with redirect_stdout(output): self.assertEqual(main(arguments), 0)
            self.assertTrue(json.loads(output.getvalue())['initialized'])
            output = io.StringIO()
            with redirect_stdout(output): self.assertEqual(main(arguments), 1)
            self.assertEqual(json.loads(output.getvalue()), dict(error='checkpoint-service-refused-or-stopped'))
            with AnchorStore(database, **PROFILE) as store: self.assertEqual(store.current['sequence'], 0)

    def test_bad_cli_does_not_echo_untrusted_arguments(self):
        output = io.StringIO()
        with redirect_stdout(output): self.assertEqual(main(['secret-example-do-not-echo']), 1)
        self.assertNotIn('secret-example', output.getvalue())

    def test_invalid_init_credentials_do_not_create_database(self):
        with tempfile.TemporaryDirectory(prefix='anchor-cli-test-') as directory:
            root = Path(directory)
            profile, database = root / 'profile.json', root / 'external.db'
            new_private_file(profile, canonical(dict(version=1, **PROFILE)))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(['init', '--database', str(database), '--profile', str(profile),
                    '--tls-key', 'unexpected']), 1)
            self.assertFalse(database.exists())


def child_main(stage, path):
    if stage == 'locked':
        try: AnchorStore(path, **PROFILE)
        except ValueError: os._exit(73)
        os._exit(74)
    pending_request = json.loads(sys.stdin.buffer.read(MAX_WIRE + 1))
    store = AnchorStore(path, **PROFILE)
    if stage == 'before-commit':
        def terminate_at_commit(sql):
            if sql.strip().upper() == 'COMMIT': os._exit(73)
        store.db.set_trace_callback(terminate_at_commit)
        store.handle(pending_request)
        os._exit(74)
    if stage == 'after-commit':
        store.handle(pending_request)
        os._exit(73)
    os._exit(74)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child': child_main(*sys.argv[2:])
    unittest.main()
