"""Owner CLI routing/redaction with mocked Owner and RPC boundaries.

No test here asserts chain truth or actual funding. Paired integration tests own
that qualification; these tests ensure command dispatch cannot secretly advance
status/restore and keep signing material out of arguments/results/error logs.
"""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from swap_runtime.common import canonical, new_private_file
from swap_runtime import owner_cli as cli


PRIVATE = '33' * 32


class FakeRpc:
    instances = []
    calls = []

    def __init__(self, url, credentials=None, timeout=15):
        self.url, self.credentials, self.timeout = url, credentials, timeout
        self.instances.append(self)

    def __call__(self, method, params):
        self.calls.append((self.url, '/', method, params))
        return True

    def daemon(self, method, params):
        self.calls.append((self.url, '/'+method, method, params))
        return True

    def wallet(self, method, params):
        self.calls.append((self.url, '/json_rpc', method, params))
        return True

    def _json_rpc(self, path, method, params):
        self.calls.append((self.url, path, method, params))
        return True


class FakeOwner:
    instances = []
    restored = []
    events = []
    raises = {}
    status_result = None
    step_result = None

    def __init__(self, directory, key, daemon, foreign, **kwargs):
        self.directory, self.key = directory, key
        self.daemon, self.foreign, self.kwargs = daemon, foreign, kwargs
        self.instances.append(self)

    def __enter__(self):
        self.events.append('enter')
        return self

    def __exit__(self, *_):
        self.events.append('close')

    def action(self, name, default):
        self.events.append(name)
        if name in self.raises:
            raise self.raises[name]
        return copy.deepcopy(default)

    def status(self):
        return self.action('status', self.status_result or {'phase': 'ready', 'recovery_required': False})

    def step(self):
        return self.action('step', self.step_result or {'action': 'waiting', 'phase': 'funding-pending'})

    def backup(self, destination):
        return self.action('backup', Path(destination))

    def cancel(self):
        return self.action('cancel', {'cancel_requested': True})

    @classmethod
    def restore(cls, snapshot, directory, key):
        cls.restored.append((snapshot, directory, key))
        return {'restored': True, 'recovery_required': True, 'directory': str(directory)}


class OwnerCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-cli-test-')
        self.root = Path(self.temp.name)
        self.key = self.root / 'owner.key'
        self.rpc = self.root / 'rpc.json'
        self.offer = self.root / 'offer.json'
        self.credentials = self.root / 'credentials.json'
        self.cookie = self.root / 'cookie'
        new_private_file(self.key, b'aa' * 32)
        new_private_file(self.cookie, b'operator:PRIVATE_COOKIE_VALUE')
        self.rpc_config = {'xds_daemon': {'url': 'http://127.0.0.1:28081'},
            'xds_wallet': {'url': 'http://127.0.0.1:28082'},
            'foreign': {'url': 'http://127.0.0.1:18443', 'credential_file': str(self.cookie)},
            'foreign_wallet': {'url': 'http://127.0.0.1:18443', 'wallet_name': 'swaps-runtime',
                               'credential_file': str(self.cookie), 'timeout': 12}}
        new_private_file(self.rpc, canonical(self.rpc_config))
        new_private_file(self.offer, canonical({'foreign_chain': 'bitcoin', 'swap_id': 'fixture'}))
        new_private_file(self.credentials, canonical({'xds_rho': '11'*32, 'foreign_key': '22'*32, 'secret': PRIVATE}))
        FakeOwner.instances, FakeOwner.restored, FakeOwner.events, FakeOwner.raises = [], [], [], {}
        FakeOwner.status_result, FakeOwner.step_result = None, None
        FakeRpc.instances, FakeRpc.calls = [], []
        self.owner_patch = patch.object(cli, '_owner', return_value=FakeOwner)
        self.rpc_patch = patch.object(cli, 'LocalRpc', FakeRpc)
        self.owner_patch.start()
        self.rpc_patch.start()

    def tearDown(self):
        self.rpc_patch.stop()
        self.owner_patch.stop()
        self.temp.cleanup()

    def args(self, action, rpc=True):
        args = [action, '--directory', str(self.root/'owner'), '--owner-key', str(self.key)]
        if rpc:
            args += ['--rpc-config', str(self.rpc)]
        return args

    def init_args(self, role='foreign-owner'):
        return self.args('init') + ['--offer', str(self.offer), '--role', role,
            '--credentials', str(self.credentials), '--exchange-dir', str(self.root/'exchange'),
            '--backup-dir', str(self.root/'backups')]

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(args)
        text = stdout.getvalue()+stderr.getvalue()
        for secret in (PRIVATE, '11'*32, '22'*32, 'aa'*32, 'PRIVATE_COOKIE_VALUE'):
            self.assertNotIn(secret, text)
        self.assertNotIn('Traceback', text)
        return code, [json.loads(line) for line in stdout.getvalue().splitlines()], stderr.getvalue()

    def test_init_reads_private_files_and_creates_owner_without_step(self):
        code, result, stderr = self.invoke(self.init_args())
        self.assertEqual(code, 0)
        self.assertEqual(stderr, '')
        owner = FakeOwner.instances[0]
        self.assertEqual(owner.kwargs['credentials']['secret'], PRIVATE)
        self.assertEqual(owner.kwargs['role'], 'foreign-owner')
        self.assertEqual(owner.key, bytes.fromhex('aa'*32))
        self.assertEqual(FakeOwner.events, ['enter', 'status', 'close'])
        self.assertEqual(FakeRpc.calls, [])
        self.assertEqual(result[0]['phase'], 'ready')

    def test_status_cannot_advance_funding_and_does_not_reread_signing_credentials(self):
        self.credentials.unlink()
        code, _, _ = self.invoke(self.args('status'))
        self.assertEqual(code, 0)
        self.assertEqual(FakeOwner.events, ['enter', 'status', 'close'])
        self.assertEqual(FakeRpc.calls, [])
        self.assertNotIn('credentials', FakeOwner.instances[0].kwargs)
        self.assertNotIn('offer', FakeOwner.instances[0].kwargs)
        self.assertNotIn('exchange_dir', FakeOwner.instances[0].kwargs)

    def test_restore_uses_no_owner_instance_rpc_or_step(self):
        self.rpc.unlink()
        self.credentials.unlink()
        args = self.args('restore', rpc=False) + ['--snapshot', str(self.root/'snapshot.bin')]
        code, results, _ = self.invoke(args)
        self.assertEqual(code, 0)
        self.assertTrue(results[0]['recovery_required'])
        self.assertEqual(FakeOwner.instances, [])
        self.assertEqual(FakeRpc.instances, [])
        self.assertEqual(FakeOwner.events, [])
        self.assertEqual(len(FakeOwner.restored), 1)

    def test_step_dispatches_once_and_cancel_only_requests_cancel(self):
        self.assertEqual(self.invoke(self.args('step'))[0], 0)
        self.assertEqual(FakeOwner.events, ['enter', 'step', 'close'])
        FakeOwner.events.clear()
        self.assertEqual(self.invoke(self.args('cancel'))[0], 0)
        self.assertEqual(FakeOwner.events, ['enter', 'cancel', 'close'])

    def test_backup_calls_only_backup_and_emits_safe_path(self):
        target = self.root/'snapshot.bin'
        code, results, _ = self.invoke(self.args('backup') + ['--snapshot', str(target)])
        self.assertEqual(code, 0)
        self.assertEqual(FakeOwner.events, ['enter', 'backup', 'close'])
        self.assertEqual(results, [{'snapshot_created': True, 'snapshot': str(target)}])

    def test_run_has_explicit_finite_step_and_sleep_bounds(self):
        with patch.object(cli.time, 'sleep') as sleep:
            code, results, _ = self.invoke(self.args('run') + ['--max-steps', '3', '--poll-seconds', '0.1'])
        self.assertEqual(code, 0)
        self.assertEqual(len(results), 3)
        self.assertEqual(FakeOwner.events, ['enter', 'step', 'step', 'step', 'close'])
        self.assertEqual([call.args for call in sleep.call_args_list], [(0.1,), (0.1,)])
        for extra in (['--max-steps', '0'], ['--max-steps', '10001'], ['--poll-seconds', 'nan'],
                      ['--poll-seconds', 'inf'], ['--poll-seconds', '0.01'], ['--poll-seconds', '61']):
            before = len(FakeOwner.instances)
            with self.subTest(extra=extra):
                self.assertEqual(self.invoke(self.args('run')+extra)[0], 1)
                self.assertEqual(len(FakeOwner.instances), before)

    def test_run_stops_after_unknown_exception_and_redacts_remote_body(self):
        FakeOwner.raises['step'] = RuntimeError('RPC_BODY '+PRIVATE+' PRIVATE_COOKIE_VALUE')
        with patch.object(cli.time, 'sleep') as sleep:
            code, result, _ = self.invoke(self.args('run')+['--max-steps', '4'])
        self.assertEqual(code, 1)
        self.assertEqual(result, [cli.ERROR])
        self.assertEqual(FakeOwner.events, ['enter', 'step', 'close'])
        sleep.assert_not_called()

    def test_keyboard_interrupt_closes_owner_and_reports_only_safe_unknown(self):
        FakeOwner.raises['step'] = KeyboardInterrupt(PRIVATE)
        code, results, _ = self.invoke(self.args('run'))
        self.assertEqual(code, 1)
        self.assertEqual(results, [cli.ERROR])
        self.assertEqual(FakeOwner.events, ['enter', 'step', 'close'])

    def test_unsupported_secret_preimage_and_proof_arguments_never_echo_values(self):
        for option in ('--secret', '--preimage', '--public-xds-txid', '--key-file', '--secret-file'):
            with self.subTest(option=option):
                code, result, _ = self.invoke(self.args('step')+[option, PRIVATE])
                self.assertEqual(code, 1)
                self.assertEqual(result, [cli.ERROR])
        self.assertEqual(FakeOwner.instances, [])

    def test_invalid_typed_argument_and_role_do_not_echo_argument_contents(self):
        for extra in (['--max-steps', PRIVATE], ['--poll-seconds', 'PRIVATE_COOKIE_VALUE'], ['--role', PRIVATE]):
            self.assertEqual(self.invoke(self.args('run')+extra)[0], 1)
        self.assertEqual(FakeOwner.instances, [])

    def test_existing_owner_rejects_replacement_private_initialization_options(self):
        for extra in (['--credentials', str(self.credentials)], ['--offer', str(self.offer)], ['--role', 'foreign-owner']):
            self.assertEqual(self.invoke(self.args('step')+extra)[0], 1)
        self.assertEqual(FakeOwner.instances, [])

    def test_non_foreign_owner_cannot_supply_private_secret(self):
        self.assertEqual(self.invoke(self.init_args('xds-owner'))[0], 1)
        self.assertEqual(FakeOwner.instances, [])
        self.credentials.write_bytes(canonical({'xds_rho': '11'*32, 'foreign_key': '22'*32}))
        self.assertEqual(self.invoke(self.init_args('xds-owner'))[0], 0)
        self.assertNotIn('secret', FakeOwner.instances[-1].kwargs['credentials'])

    def test_foreign_owner_requires_secret_and_exact_canonical_credential_fields(self):
        for values in ({'xds_rho': '11'*32, 'foreign_key': '22'*32},
                       {'xds_rho': '11'*32, 'foreign_key': '22'*32, 'secret': PRIVATE, 'extra': 1},
                       {'xds_rho': '11'*32, 'foreign_key': '22'*31, 'secret': PRIVATE},
                       {'xds_rho': 'AB'*32, 'foreign_key': '22'*32, 'secret': PRIVATE}):
            self.credentials.write_bytes(canonical(values))
            self.assertEqual(self.invoke(self.init_args())[0], 1)
        self.assertEqual(FakeOwner.instances, [])

    def test_solana_private_account_bundle_is_optional_but_exact_when_present(self):
        self.offer.write_bytes(canonical({'foreign_chain': 'solana'}))
        values = {'xds_rho': '11'*32, 'foreign_key': '22'*64, 'secret': PRIVATE}
        self.credentials.write_bytes(canonical(values))
        self.assertEqual(self.invoke(self.init_args())[0], 0)
        values['solana_accounts'] = {name: '44'*64 for name in ('state', 'vault', 'refund')}
        self.credentials.write_bytes(canonical(values))
        self.assertEqual(self.invoke(self.init_args())[0], 0)
        values['solana_accounts'].pop('refund')
        self.credentials.write_bytes(canonical(values))
        self.assertEqual(self.invoke(self.init_args())[0], 1)

    def test_native_and_named_bitcoin_wallet_callables_route_without_url_override(self):
        self.assertEqual(self.invoke(self.args('status'))[0], 0)
        owner = FakeOwner.instances[0]
        owner.daemon('get_info', {})
        owner.kwargs['wallet']('swap_role', {'rho': 'fixture'})
        owner.foreign('getblockchaininfo', [])
        owner.kwargs['foreign_wallet']('listunspent', [])
        self.assertEqual([call[1] for call in FakeRpc.calls], ['/get_info', '/json_rpc', '/', '/wallet/swaps-runtime'])
        self.assertEqual(FakeRpc.instances[-1].credentials, 'operator:PRIVATE_COOKIE_VALUE')
        self.assertEqual(FakeRpc.instances[-1].timeout, 12)
        for name in ('../other', '/wallet/other', '..', '', 'x'*81, 'wallet name', 'bad?wallet'):
            self.rpc_config['foreign_wallet']['wallet_name'] = name
            self.rpc.write_bytes(canonical(self.rpc_config))
            self.assertEqual(self.invoke(self.args('status'))[0], 1)

    def test_rpc_record_unknown_fields_and_duplicate_json_fail_before_owner(self):
        self.rpc.write_bytes(b'{"foreign":{},"foreign":{},"xds_daemon":{}}')
        self.assertEqual(self.invoke(self.args('status'))[0], 1)
        self.rpc_config['foreign_wallet']['path'] = '/wallet/other'
        self.rpc.write_bytes(canonical(self.rpc_config))
        self.assertEqual(self.invoke(self.args('status'))[0], 1)
        self.assertEqual(FakeOwner.instances, [])

    def test_real_transport_constructor_still_rejects_public_url_before_owner(self):
        self.rpc_patch.stop()
        self.rpc_config['foreign']['url'] = 'https://example.com'
        self.rpc.write_bytes(canonical(self.rpc_config))
        self.assertEqual(self.invoke(self.args('status'))[0], 1)
        self.assertEqual(FakeOwner.instances, [])

    def test_private_fields_raw_payload_nonfinite_or_oversized_owner_results_refuse_output(self):
        for result in ({'secret': PRIVATE}, {'receipt': {'raw': PRIVATE}}, {'PrivateKey': PRIVATE},
                       {'authorization': 'PRIVATE_COOKIE_VALUE'},
                       {'value': float('nan')}, {'message': 'x'*140000}):
            FakeOwner.status_result = result
            code, emitted, _ = self.invoke(self.args('status'))
            self.assertEqual(code, 1)
            self.assertEqual(emitted, [cli.ERROR])

    def test_restore_rejects_rpc_and_init_paths_before_transport(self):
        code, _, _ = self.invoke(self.args('restore')+['--snapshot', str(self.root/'snapshot')])
        self.assertEqual(code, 1)
        self.assertEqual(FakeRpc.instances, [])
        self.assertEqual(FakeOwner.restored, [])

    def test_help_is_available_as_separate_module_without_initializing_owner(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, '-B', '-m', 'swap_runtime.owner_cli', '--help'],
                                env=env, capture_output=True, text=True, timeout=15,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Examples', result.stdout)
        self.assertIn('--credentials', result.stdout)
        self.assertIn('max-steps', result.stdout)
        self.assertNotIn('--secret-file', result.stdout)
        self.assertEqual(FakeOwner.instances, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
