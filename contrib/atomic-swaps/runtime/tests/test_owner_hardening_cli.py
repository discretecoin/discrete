"""Actual CLI child processes with encrypted storage and temporary pinned TLS.

No wallet/chain operations: initialization, backup, status and restoration only.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from swap_runtime.anchor import AnchorServer, AnchorStore, client_from_profile
from swap_runtime.common import canonical, new_private_file
from swap_runtime.lifecycle_store import OwnerStore
from test_anchor import KEY, PROFILE, SERVICE, STREAM, certificate
from test_owner_protocol import configuration

ROOT = Path(__file__).resolve().parents[1]
OWNER_KEY = bytes([57]) * 32  # Synthetic fixture, never a wallet key.


class HardenedOwnerCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-checkpoint-cli-')
        self.root = Path(self.temp.name)
        self.owner = self.root / 'owner'
        (self.root / 'exchange').mkdir(mode=0o700)
        self.external = self.root / 'separate-profile'
        self.external.mkdir(mode=0o700)
        self.store = AnchorStore(self.external / 'history.db', **PROFILE, create=True)
        context, pin = certificate(self.external)
        self.server = AnchorServer(self.store, context, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs=dict(poll_interval=.02), daemon=True)
        self.thread.start()
        self.profile = self.external / 'client.json'
        new_private_file(self.external / 'checkpoint.seed', (bytes([7]) * 32).hex().encode())
        new_private_file(self.profile, canonical(dict(version=1, service_id=SERVICE, stream_id=STREAM,
            endpoint='https://127.0.0.1:' + str(self.server.server_port), certificate_sha256=pin,
            writer_key_file='checkpoint.seed', timeout=2)))
        self.client = client_from_profile(self.profile)
        new_private_file(self.root / 'owner.key', OWNER_KEY.hex().encode())
        new_private_file(self.root / 'rpc.json', canonical(dict(
            xds_daemon=dict(url='http://127.0.0.1:1'), foreign=dict(url='http://127.0.0.1:1'))))
        offer, keys = configuration()
        secret = bytes([61]) * 32
        offer['xds']['hashlock'] = offer['foreign']['contract']['hashlock'] = hashlib.sha256(secret).hexdigest()
        new_private_file(self.root / 'offer.json', canonical(offer))
        self.credentials = dict(xds_rho='31' * 32, secret=secret.hex(),
            foreign_key=keys['foreign-owner'].private_numbers().private_value.to_bytes(32, 'big').hex())
        new_private_file(self.root / 'credentials.json', canonical(self.credentials))

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.store.close()
        self.temp.cleanup()

    def command(self, action, *, directory=None, anchored=True, extra=(), success=True):
        args = [sys.executable, '-B', '-m', 'swap_runtime.owner_cli', action,
            '--directory', str(directory or self.owner), '--owner-key', str(self.root / 'owner.key')]
        if anchored: args += ['--anchor-profile', str(self.profile)]
        if action != 'restore': args += ['--rpc-config', str(self.root / 'rpc.json')]
        if action == 'init':
            args += ['--offer', str(self.root / 'offer.json'), '--credentials', str(self.root / 'credentials.json'),
                '--role', 'foreign-owner', '--exchange-dir', str(self.root / 'exchange'),
                '--backup-dir', str(self.root / 'backups')]
        args += [str(x) for x in extra]
        result = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=30,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 0 if success else 1, result.stdout.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        for value in [*self.credentials.values(), OWNER_KEY.hex(), (bytes([7]) * 32).hex()]:
            self.assertNotIn(value.encode(), result.stdout)
        return json.loads(result.stdout)

    def snapshot(self):
        path = self.root / 'manual.backup'
        self.command('backup', extra=('--snapshot', path))
        return path

    def test_init_restart_status_backup_uses_complete_anchored_v2_state(self):
        first = self.command('init')
        self.assertTrue(first['externally_anchored'])
        self.assertFalse(first['recovery_required'])
        head = self.client.read()
        self.assertEqual(self.command('status')['checkpoint_sequence'], head['sequence'])
        self.assertEqual(self.snapshot().read_bytes(),
            (self.owner / 'snapshots' / (head['commitment'] + '.backup')).read_bytes())
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw, _ = OwnerStore._decode_backup((self.root / 'manual.backup').read_bytes(), AESGCM(OWNER_KEY))
        path = self.root / 'inspect.db'
        new_private_file(path, raw)
        with OwnerStore(path, OWNER_KEY) as state:
            self.assertEqual(state.get('config')['version'], 2)
            self.assertTrue(state.get('config')['durable_funding'])
        self.assertFalse((self.owner / 'owner.db').exists())
        self.assertEqual(self.client.read(), head)  # Metadata does not advance work.

    def test_missing_profile_cannot_downgrade_existing_anchored_owner(self):
        self.command('init')
        head = self.client.read()
        self.command('status', anchored=False, success=False)
        self.assertEqual(self.client.read(), head)

    def test_historical_online_restore_advances_sticky_recovery_and_fences_old_copy(self):
        self.command('init')
        snapshot = self.snapshot()
        old = self.client.read()
        target = self.root / 'recovered'
        result = self.command('restore', directory=target, extra=('--snapshot', snapshot))
        self.assertTrue(result['recovery_required'])
        self.assertGreater(result['checkpoint_sequence'], old['sequence'])
        self.assertTrue(self.command('status', directory=target)['recovery_required'])
        self.command('status', success=False)

    def test_explicit_offline_restore_requires_no_profile_or_live_service(self):
        self.command('init')
        snapshot = self.snapshot()
        head = self.client.read()
        target = self.root / 'offline-recovered'
        result = self.command('restore', directory=target, anchored=False,
            extra=('--snapshot', snapshot, '--offline-protective'))
        self.assertTrue(result['offline_protective'])
        self.assertFalse(result['externally_anchored'])
        self.assertTrue(self.command('status', directory=target, anchored=False)['recovery_required'])
        self.assertEqual(self.client.read(), head)

    def test_plain_restore_of_anchored_backup_has_no_implicit_normal_fallback(self):
        self.command('init')
        target = self.root / 'plain-restored'
        self.command('restore', directory=target, anchored=False, extra=('--snapshot', self.snapshot()))
        self.command('status', directory=target, anchored=False, success=False)

    def test_profile_inside_owner_directory_refused(self):
        self.command('init')
        copied = self.owner / 'client.json'
        new_private_file(copied, self.profile.read_bytes())
        self.profile = copied
        self.command('status', success=False)

    def test_incompatible_offline_flags_refused_without_history_change(self):
        self.command('init')
        snapshot = self.snapshot()
        head = self.client.read()
        self.command('status', extra=('--offline-protective',), success=False)
        self.command('restore', directory=self.root / 'invalid',
            extra=('--snapshot', snapshot, '--offline-protective'), success=False)
        self.assertEqual(self.client.read(), head)

    def test_unanchored_new_cli_owner_still_pins_durable_native_preparation(self):
        self.command('init', anchored=False)
        self.command('status', anchored=False)
        with OwnerStore(self.owner / 'owner.db', OWNER_KEY) as state:
            self.assertEqual(state.get('config')['version'], 2)
            self.assertTrue(state.get('config')['durable_funding'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
