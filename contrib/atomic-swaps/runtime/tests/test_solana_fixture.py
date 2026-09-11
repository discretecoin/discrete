"""Public fixture guards/transport and genuine System/SPL/escrow VM execution.

The VM has controlled RPC contexts; these tests do not claim Agave finality.
The echo subprocess below tests framing/reconnect only and cannot execute swaps.
"""
import base64
import copy
from decimal import Decimal
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

# Direct signer/transport child execution must not depend on the parent test
# runner's in-process sys.path mutation or a pre-existing PYTHONPATH variable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solders.account import Account
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from swap_runtime.solana import SolanaAdapter, profile
from swap_runtime.solana_funding import SolanaFundingAdapter
from solana_fixture.bridge import (LocalBridge, StdioTransport, create_bridge,
    init_client, setup, serve, command_argv, reply_wire)
from solana_fixture.runner import mint_account, program_accounts, validator_command, validate_validator
from solana_fixture.support import (AGAVE_VERSION, ARTIFACT, ELF_SHA256, VALIDATOR_SHA256,
    artifact_manifest, isolated_network, local_manifest, private_directory,
    public_ready, read_json, read_key, validate_manifest, write_json, write_keys)
import test_solana_funding as funding_fixture


def ready_record():
    return dict(version=1, kind='synthetic-agave-fixture', manifest=local_manifest(str(Hash.default())),
        validator_sha256=VALIDATOR_SHA256, validator_version=AGAVE_VERSION, genesis_loading=True)


def echo_server():
    for raw in sys.stdin.buffer:
        request = json.loads(raw)
        result = ready_record() if request['action'] == 'info' else request
        print(json.dumps({'result': result}), flush=True)


class PublicFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_committed_exact_artifact_only_genesis_can_change(self):
        original = artifact_manifest()
        changed = local_manifest(str(Hash.new_unique()))
        self.assertNotEqual(original['profile']['genesis_hash'], changed['profile']['genesis_hash'])
        self.assertEqual(changed['artifact']['sha256'], ELF_SHA256)
        self.assertEqual(validate_manifest(changed), changed)
        for field, value in [('program_id', str(Keypair().pubkey())), ('mint', str(Keypair().pubkey())),
                             ('network', 'mainnet-usdc')]:
            bad = copy.deepcopy(changed); bad['profile'][field] = value
            with self.assertRaises(ValueError): validate_manifest(bad)
        bad = copy.deepcopy(changed); bad['artifact']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): validate_manifest(bad)

    def test_mint_dump_exact_legacy_layout_and_fresh_authority(self):
        minter = Keypair().pubkey()
        value = mint_account(artifact_manifest()['profile']['mint'], minter)
        data = base64.b64decode(value['account']['data'][0], validate=True)
        self.assertEqual(len(data), 82)
        self.assertEqual(data[4:36], bytes(minter))
        self.assertEqual(data[36:44], bytes(8))
        self.assertEqual(data[44:46], b'\x06\x01')
        self.assertEqual(data[50:82], bytes(minter))
        self.assertEqual(value['account']['owner'], profile.TOKEN)

    def test_genesis_programdata_has_actual_none_authority_and_exact_elf_offset(self):
        program, programdata = program_accounts()
        mint = mint_account(artifact_manifest()['profile']['mint'], Keypair().pubkey())
        manifest = artifact_manifest()
        observed = profile.verify_accounts(manifest, program['account'], programdata['account'], mint['account'])
        self.assertTrue(observed['immutable'])
        self.assertIsNone(observed['upgrade_authority'])
        self.assertEqual(observed['artifact_sha256'], ELF_SHA256)
        self.assertEqual(observed['last_deployed_slot'], 0)
        data = bytearray(base64.b64decode(programdata['account']['data'][0]))
        self.assertEqual(data[12], 0)
        self.assertEqual(data[45:49], b'\x7fELF')
        data[12] = 1  # Agave CLI 'none' actually creates Some(default-pubkey).
        programdata['account']['data'][0] = base64.b64encode(data).decode()
        with self.assertRaises(ValueError):
            profile.verify_accounts(manifest, program['account'], programdata['account'], mint['account'])

    def test_private_run_rejects_reuse_partial_and_nonregular_files(self):
        run = private_directory(self.root / 'run', create=True)
        with self.assertRaises(FileExistsError): private_directory(run, create=True)
        with self.assertRaises(Exception): create_bridge(run)
        (run / 'key.json').mkdir()
        with self.assertRaises(ValueError): read_json(run / 'key.json')
        write_json(run / 'bad.json', {'a': 1})
        (run / 'duplicate.json').write_text('{"a":1,"a":2}')
        (run / 'duplicate.json').chmod(0o600)
        with self.assertRaises(ValueError): read_json(run / 'duplicate.json')

    def test_keys_survive_reconnect_without_regeneration(self):
        run = private_directory(self.root / 'run', create=True)
        keys = write_keys(run, ('owner', 'claim'))
        self.assertNotEqual(keys['owner'].pubkey(), keys['claim'].pubkey())
        self.assertEqual(bytes(read_key(run, 'owner')), bytes(keys['owner']))
        self.assertEqual(bytes(read_key(run, 'claim')), bytes(keys['claim']))
        with self.assertRaises(FileExistsError): write_keys(run, ('owner',))

    def test_public_stdio_client_retains_independent_identities_in_new_processes(self):
        command = [sys.executable, '-B', str(Path(__file__).resolve()), 'echo-server']
        run = self.root / 'client'
        result = init_client(run, command)
        self.assertEqual(result, ready_record())
        snapshots = []
        for _ in range(2):
            child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), 'client-info', str(run)],
                capture_output=True, check=True, timeout=20)
            snapshots.append(json.loads(child.stdout))
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertNotEqual(snapshots[0]['owner'], snapshots[0]['claim'])
        self.assertEqual(set(snapshots[0]), {'owner', 'claim', 'manifest'})
        with self.assertRaises(FileExistsError): init_client(run, command)

    def test_stdio_is_shell_free_bounded_and_readiness_pinned(self):
        for value in ('echo something', [], ['x\ny'], ['x', 1]):
            with self.assertRaises(ValueError): command_argv(value)
        bad = ready_record(); bad['genesis_loading'] = False
        with self.assertRaises(ValueError): public_ready(bad)
        bad = ready_record(); bad['validator_version'] = 'different'
        with self.assertRaises(ValueError): public_ready(bad)
        bad = ready_record(); bad['unrecognized'] = True
        with self.assertRaises(ValueError): public_ready(bad)

    def test_explicit_local_endpoint_cannot_select_public_network_or_credentials(self):
        for endpoint in ('https://api.mainnet-beta.solana.com', 'http://localhost:18899',
                         'http://user:password@127.0.0.1:18899', 'http://127.0.0.1:18899/?a=b'):
            run = private_directory(self.root / str(len(list(self.root.iterdir()))), create=True)
            write_json(run / 'local.json', {'version': 1, 'endpoint': endpoint})
            with self.assertRaises(ValueError): LocalBridge(run)

    def test_network_namespace_without_external_interface_required(self):
        with patch('solana_fixture.support.socket.if_nameindex', return_value=[(1, 'lo'), (2, 'eth0')]):
            with self.assertRaises(ValueError): isolated_network()

    def test_fixed_start_command_has_no_reset_clone_or_public_rpc_option(self):
        run = self.root / 'fresh'
        command = validator_command(Path('/owned/bin/solana-test-validator'), run, Keypair().pubkey(), True)
        self.assertEqual(command.count('--account'), 3)
        self.assertIn(artifact_manifest()['profile']['program_id'], command)
        self.assertNotIn('--upgradeable-program', command)
        self.assertEqual(command[command.index('--bind-address') + 1], '127.0.0.1')
        self.assertFalse(set(command) & {'--reset', '--clone', '--url', '--warp-slot'})
        resumed = validator_command(Path('/owned/bin/solana-test-validator'), run, Keypair().pubkey(), False)
        self.assertFalse(set(resumed) & {'--account', '--upgradeable-program', '--reset', '--mint'})

    def test_wrong_binary_hash_rejected_before_execution(self):
        binary = self.root / 'untrusted-binary'; binary.write_bytes(b'not executable')
        with patch('solana_fixture.runner.subprocess.run') as execute:
            with self.assertRaises(ValueError): validate_validator(binary, '0' * 64)
            execute.assert_not_called()

    def test_server_rejects_unknown_method_and_partial_frame_without_echoing_payload(self):
        class FakeLocal:
            def __init__(self, _): self.ready = ready_record()
            def rpc(self, method, params): raise ValueError('private payload must never be echoed')
            def close(self): pass
        output = io.BytesIO()
        incoming = io.BytesIO(b'{"action":"rpc","method":"arbitrary","params":[]}\n{"action":"info"}')
        with patch('solana_fixture.bridge.LocalBridge', FakeLocal): serve(self.root, incoming, output)
        self.assertEqual(output.getvalue(), b'{"error":"fixture request failed"}\n' * 2)

    def test_rpc_token_decimal_fields_forward_without_rounding_or_receipt_loss(self):
        value = {'meta': {'postTokenBalances': [{'uiTokenAmount': {'uiAmount': Decimal('1.234567890123456789')}}]},
                 'integer_balance': 12345678901234567890}
        encoded = reply_wire({'result': value})
        self.assertEqual(json.loads(encoded, parse_float=Decimal), {'result': value})
        self.assertIn(b'1.234567890123456789', encoded)
        for invalid in (Decimal('NaN'), Decimal('Infinity')):
            with self.assertRaises(ValueError): reply_wire({'result': invalid})
        class FakeLocal:
            def __init__(self, _): pass
            def rpc(self, method, params): return value
            def close(self): pass
        output = io.BytesIO()
        with patch('solana_fixture.bridge.LocalBridge', FakeLocal):
            serve(self.root, io.BytesIO(b'{"action":"rpc","method":"getTransaction","params":[]}\n'), output)
        self.assertEqual(json.loads(output.getvalue(), parse_float=Decimal), {'result': value})

    def test_real_vm_public_provisioning_then_atomic_funding_and_claim(self):
        f = funding_fixture.Fixture()
        f.vm.airdrop(f.owner.pubkey(), 10_000_000_000)
        owner, claimant = Keypair(), Keypair()
        def rpc(method, params):
            if method == 'getBalance': return f.result(f.vm.get_balance(Pubkey.from_string(params[0])))
            if method == 'getTokenAccountBalance': return f.result({'amount': str(f.balance(params[0]))})
            return f.rpc(method, params)
        result = setup(rpc, f.manifest, f.owner, str(owner.pubkey()), str(claimant.pubkey()),
            f.terms['hashlock'], 500)
        self.assertEqual(result['source_balance'], 10_000_000)
        self.assertEqual(result['owner_balance_lamports'], 1_000_000_000)
        self.assertEqual(result['claim_balance_lamports'], 1_000_000_000)
        self.assertNotIn('state', result['terms'])
        provisioning = Transaction.from_bytes(f.sent[-1][0])
        self.assertEqual(len(provisioning.message.instructions), 5)
        self.assertEqual(provisioning.message.header.num_required_signatures, 2)
        self.assertNotIn(f.program, provisioning.message.account_keys)
        funding = SolanaFundingAdapter(rpc, result['terms'])
        keys = dict(owner=owner, state=Keypair(), vault=Keypair(), refund=Keypair())
        plan = funding.plan(keys); raw, txid = funding.prepare(plan, keys)
        funding.send(plan, raw, txid)
        self.assertEqual(funding.receipt(plan, raw, txid)['status'], 'confirmed')
        settlement = SolanaAdapter(rpc, funding.settlement_terms(plan, str(claimant.pubkey())))
        raw, txid = settlement.prepare('foreign-claim', claimant, f.secret)
        settlement.send('foreign-claim', raw, txid)
        self.assertEqual(settlement.receipt('foreign-claim', raw, txid)['status'], 'confirmed')
        self.assertEqual(f.balance(plan['accounts']['claim']), result['terms']['amount'])
        self.assertEqual(f.balance(plan['accounts']['vault']), 0)
        self.assertTrue(all(not isinstance(item[1], FailedTransactionMetadata) for item in f.sent))

    def test_setup_rejects_invalid_roles_or_secret_shape_before_chain_calls(self):
        owner = Keypair(); rpc_calls = []
        def rpc(method, params): rpc_calls.append(method); raise AssertionError('unexpected RPC')
        with self.assertRaises(ValueError): setup(rpc, {}, owner, str(owner.pubkey()), str(owner.pubkey()), '00' * 32, 500)
        with self.assertRaises(ValueError): setup(rpc, {}, owner, str(owner.pubkey()), str(Keypair().pubkey()), 'secret', 500)
        with self.assertRaises(ValueError): setup(rpc, {}, owner, str(owner.pubkey()), str(Keypair().pubkey()), '00' * 32, 2)
        self.assertEqual(rpc_calls, [])


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'echo-server':
        echo_server()
    elif len(sys.argv) > 1 and sys.argv[1] == 'client-info':
        with patch('solana_fixture.bridge.profile.verify_rpc'):
            bridge = create_bridge(sys.argv[2])
            try:
                print(json.dumps(dict(owner=str(bridge.owner_key.pubkey()), claim=str(bridge.claim_key.pubkey()), manifest=bridge.manifest)))
            finally: bridge.close()
    else:
        unittest.main()
