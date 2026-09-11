"""Opt-in real native/remote-private-Solana Session qualification.

PAIR_SOLANA_RPC_INTEGRATION=1 and PAIR_SOLANA_BRIDGE_FACTORY select an explicitly
authorized test-only bridge. The factory exports create_bridge(); its instance
has rpc(method,params), fund(hashlock,delay_slots), key and close(). It must target
only the owned isolated synthetic ledger. No credentials belong in this file.
The normal XDS fixture owns four isolated nodes and two wallet RPC processes.
Deadline budgets are controlled private-test policy, not public-network timing
guidance. The fresh-process case reconciles an already finalized receipt; it does
not claim a lost-acknowledgment scenario for this pair.
"""
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

from swap_runtime.rpc import LocalRpc
from swap_runtime.session import Session
from swap_runtime.xds import _Unavailable


def bridge():
    path = Path(os.environ['PAIR_SOLANA_BRIDGE_FACTORY']).resolve()
    spec = importlib.util.spec_from_file_location('owned_private_solana_bridge', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.create_bridge()


def wait_final(session, kind, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = session.reconcile(kind)
        if receipt.get('status') == 'confirmed' and receipt.get('final'):
            return receipt
        if receipt.get('status') in ('failed', 'conflict'):
            raise AssertionError('Exact settlement failed or conflicted')
        time.sleep(1)
    raise TimeoutError('Finalized settlement receipt deadline expired')


def reopen_child():
    request = json.loads(sys.stdin.buffer.read())
    remote = bridge()
    try:
        daemon = LocalRpc(request['native_endpoint']).daemon
        def read_native(method, params):
            if method == 'sendrawtransaction':
                raise AssertionError('Receipt-only child must not transmit native bytes')
            return daemon(method, params)
        def read_foreign(method, params):
            if method == 'sendTransaction':
                raise AssertionError('Receipt-only child must not transmit foreign bytes')
            return remote.rpc(method, params)
        with Session(request['path'], bytes.fromhex(request['key']), request['swap_id'], read_native, read_foreign) as session:
            result = session.broadcast(request['kind'])
            intent = session.journal.intent(session.id, request['kind'])
            if result['action'] != 'reconciled':
                raise AssertionError('Fresh process attempted a second broadcast')
            print(json.dumps({'action': result['action'], 'txid': intent['txid'],
                              'wire_sha256': hashlib.sha256(intent['payload']).hexdigest(),
                              'exposed': session.journal.exposed(session.id), 'receipt': result['receipt'], 'sends': 0}))
    finally:
        remote.close()


def renew_child():
    """Fresh process: reload authenticated acquisition, renew, settle exactly once."""
    from solders.keypair import Keypair
    request = json.loads(sys.stdin.buffer.read())
    remote = bridge()
    sends = []
    try:
        daemon = LocalRpc(request['native_endpoint']).daemon
        def read_native(method, params):
            if method == 'sendrawtransaction':
                raise AssertionError('Renewal child must not transmit native bytes')
            return daemon(method, params)
        def counted_foreign(method, params):
            if method == 'sendTransaction':
                sends.append(method)
            return remote.rpc(method, params)
        with Session(request['path'], bytes.fromhex(request['key']), request['swap_id'],
                     read_native, counted_foreign) as session:
            old = session.journal.intent(session.id, 'foreign-claim', 0)
            if (old['txid'] != request['old_txid'] or hashlib.sha256(old['payload']).hexdigest() != request['old_sha256']
                    or old['evidence']['_aad_version'] != 1):
                raise AssertionError('Authenticated original attempt did not survive restart')
            adapter = session.adapters['foreign']
            original = adapter.validate('foreign-claim', old['payload'], old['txid'])
            description = session.renew_solana('foreign-claim', Keypair.from_bytes(bytes.fromhex(request['payer_key'])))
            renewed = session.journal.intent(session.id, 'foreign-claim')
            replacement = adapter.validate('foreign-claim', renewed['payload'], renewed['txid'])
            proof = renewed['evidence']
            if (description['attempt'] != 1 or session.journal.intent(session.id, 'foreign-claim', 0) != old
                    or original['semantic_hash'] != replacement['semantic_hash']
                    or original['recent_blockhash'] == replacement['recent_blockhash']
                    or old['txid'] == renewed['txid']
                    or proof['expiry_context_slot'] <= old['evidence']['context_slot']
                    or proof['unspent_context_slot'] < proof['expiry_context_slot']):
                raise AssertionError('Rooted renewal did not preserve its exact economic intent and prior artifact')
            session.broadcast('foreign-claim')
            receipt = wait_final(session, 'foreign-claim')
            retry = session.broadcast('foreign-claim')
            if retry['action'] != 'reconciled' or len(sends) != 1:
                raise AssertionError('Finalized renewal retransmitted or settled more than once')
            print(json.dumps({'status': 'PASS', 'old_txid': old['txid'], 'new_txid': renewed['txid'],
                'old_sha256': request['old_sha256'], 'new_sha256': hashlib.sha256(renewed['payload']).hexdigest(),
                'semantic_hash': original['semantic_hash'], 'prior_attempt_unchanged': True,
                'authenticated_acquisition_loaded': True, 'acquisition_context_slot': old['evidence']['context_slot'],
                'expiry_context_slot': proof['expiry_context_slot'], 'unspent_context_slot': proof['unspent_context_slot'],
                'previous_history_status': proof['previous_history_status'], 'history_may_be_pruned': proof['history_may_be_pruned'],
                'basis': proof['basis'], 'receipt': receipt, 'sends': len(sends), 'retry_action': retry['action']}))
    finally:
        remote.close()


@unittest.skipUnless(os.environ.get('PAIR_SOLANA_RPC_INTEGRATION') == '1',
                     'Set PAIR_SOLANA_RPC_INTEGRATION=1 and the explicitly owned bridge/native fixture settings')
class PairSolanaRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.xf = importlib.import_module('test_xds_rpc_integration')
        cls.xf.XdsRpcIntegration.setUpClass()
        cls.native = cls.xf.XdsRpcIntegration('runTest')
        cls.directory = cls.native.directory
        try:
            cls.remote = bridge()
        except BaseException:
            cls.xf.XdsRpcIntegration.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.remote.close()
        finally:
            cls.xf.XdsRpcIntegration.tearDownClass()

    def transports(self):
        x = self.native.x
        return (LocalRpc('http://127.0.0.1:' + str(x.n.rpc)).daemon,
                LocalRpc('http://127.0.0.1:' + str(x.alice.rpc), x.alice.auth).wallet,
                LocalRpc('http://127.0.0.1:' + str(x.bob.rpc), x.bob.auth).wallet)

    def fund_pair(self, name, abandon=False):
        secret = os.urandom(32)
        foreign = self.remote.fund(hashlib.sha256(secret).hexdigest(), 100 if abandon else 1000)
        contract = self.native.x.fund(secret=secret, delay=24 if abandon else 80)
        self.native.x.mine(10)
        adapter = self.native.adapter(contract); self.native.ready(adapter)
        terms = {name: value.hex() if isinstance(value, bytes) else value for name, value in vars(adapter.contract).items()}
        config = dict(version=1, swap_id=name, role='foreign-owner', foreign_chain='solana', xds=terms, foreign=foreign,
            policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2, foreign_claim_budget_units=2,
                        max_observation_seconds=15, solana_fee_attempt_reserve=2))
        return contract, config

    def save(self, name, report):
        path = self.directory / (name + '-public-receipt.json')
        with path.open('xb') as stream:
            stream.write((json.dumps(report, indent=2) + '\n').encode())

    def test_01_public_native_witness_real_solana_claim_and_fresh_journal_process(self):
        x = self.native.x; x.bob.synced(); before = x.bob.balance()
        contract, config = self.fund_pair('pair-solana-success')
        daemon, alice, bob = self.transports()
        bob_path, bob_key = self.directory / 'pair-solana-bob.sqlite', os.urandom(32)
        with Session(bob_path, bob_key, config['swap_id'], daemon, self.remote.rpc, wallet=bob, config=config) as owner:
            admission, observation = owner.observe()
            self.assertTrue(admission.allow_first_exposure(), observation)
            owner.prepare('xds-claim', contract['rho_b'], contract['secret'])
            intent = owner.journal.intent(owner.id, 'xds-claim'); xds_id = intent['txid']; xds_wire = intent['payload']
            self.assertEqual(owner.broadcast('xds-claim')['txid'], xds_id)
        alice_path, alice_key = self.directory / 'pair-solana-alice.sqlite', os.urandom(32)
        with Session(alice_path, alice_key, config['swap_id'], daemon, self.remote.rpc, wallet=alice,
                     config=dict(config, role='xds-owner')) as owner:
            with self.assertRaises(ValueError):
                owner.prepare('foreign-claim', self.remote.key, secret=contract['secret'])
            # No private preimage is passed: Session obtains the real public XDS wire.
            owner.prepare('foreign-claim', self.remote.key, public_xds_txid=xds_id)
            intent = owner.journal.intent(owner.id, 'foreign-claim'); sol_id = intent['txid']; sol_wire = intent['payload']
            self.assertEqual(owner.broadcast('foreign-claim')['txid'], sol_id)
            sol_receipt = wait_final(owner, 'foreign-claim')
            self.assertTrue(sol_receipt['publicly_observed'])
            self.assertTrue(owner.journal.exposed(owner.id))
        request = dict(path=str(alice_path), key=alice_key.hex(), swap_id=config['swap_id'], kind='foreign-claim',
                       native_endpoint='http://127.0.0.1:' + str(x.n.rpc))
        runtime = Path(__file__).resolve().parents[1]
        env = dict(os.environ); env['PYTHONPATH'] = str(runtime) + os.pathsep + env.get('PYTHONPATH', '')
        child = subprocess.run([sys.executable, '-B', __file__, '--reopen-child'], input=json.dumps(request).encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=runtime, timeout=60,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        recovered = json.loads(child.stdout)
        self.assertEqual(recovered['txid'], sol_id)
        self.assertEqual(recovered['wire_sha256'], hashlib.sha256(sol_wire).hexdigest())
        self.assertTrue(recovered['exposed'])
        self.assertEqual(recovered['sends'], 0)
        x.mine(11)
        with Session(bob_path, bob_key, config['swap_id'], daemon, self.remote.rpc) as owner:
            native_receipt = owner.reconcile('xds-claim')
            self.assertTrue(native_receipt['final'])
            self.assertEqual(owner.journal.intent(owner.id, 'xds-claim')['payload'], xds_wire)
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'paired Solana/native payout scanned', 60)
        balance = int(self.remote.rpc('getTokenAccountBalance', [config['foreign']['claim'], {'commitment': 'finalized'}])['value']['amount'])
        self.assertEqual(balance, config['foreign']['amount'])
        self.save('pair-solana-success', {'status': 'PASS', 'xds': native_receipt, 'solana': sol_receipt,
                  'journal_reopened_in_fresh_process': recovered, 'solana_destination_balance': balance,
                  'native_balance_delta': 1000, 'secret_source': 'validated public native transaction only'})

    def test_02_abandoned_real_pair_refunds_both_principals_without_exposure(self):
        x = self.native.x; x.alice.synced(); before = x.alice.balance()
        contract, config = self.fund_pair('pair-solana-refund', abandon=True)
        daemon, alice, bob = self.transports()
        with Session(self.directory / 'pair-solana-refund-a.sqlite', os.urandom(32), config['swap_id'],
                     daemon, self.remote.rpc, wallet=alice, config=dict(config, role='xds-owner')) as a:
            with Session(self.directory / 'pair-solana-refund-b.sqlite', os.urandom(32), config['swap_id'],
                         daemon, self.remote.rpc, wallet=bob, config=config) as b:
                with self.assertRaises(_Unavailable): a.prepare('xds-refund', contract['rho_a'])
                self.assertFalse(a.journal.exposed(a.id)); self.assertFalse(b.journal.exposed(b.id))
                x.mine(config['xds']['refund_height'] - x.n.info()['height'])
                deadline = time.monotonic() + 180
                while not b.adapters['foreign'].observe()['refund_eligible']:
                    if time.monotonic() >= deadline: raise TimeoutError('Private Solana refund slot not reached')
                    time.sleep(1)
                a.prepare('xds-refund', contract['rho_a']); b.prepare('foreign-refund', self.remote.key)
                a.broadcast('xds-refund'); b.broadcast('foreign-refund')
                sol_receipt = wait_final(b, 'foreign-refund'); x.mine(11)
                native_receipt = a.reconcile('xds-refund')
                self.assertTrue(native_receipt['final'])
                self.assertFalse(a.journal.exposed(a.id)); self.assertFalse(b.journal.exposed(b.id))
        self.native.lab.wait_for(lambda: x.alice.balance() == before - 2, 'paired refund net native fixed fees', 60)
        balance = int(self.remote.rpc('getTokenAccountBalance', [config['foreign']['refund'], {'commitment': 'finalized'}])['value']['amount'])
        self.assertEqual(balance, config['foreign']['amount'])
        self.save('pair-solana-refund', {'status': 'PASS', 'xds': native_receipt, 'solana': sol_receipt,
                  'native_balance_delta': -2, 'solana_destination_balance': balance, 'exposed': False})


    def test_03_rooted_expiry_renewal_after_fresh_process_restart(self):
        x = self.native.x; x.bob.synced(); before = x.bob.balance()
        contract, config = self.fund_pair('pair-solana-renewal')
        daemon, alice, bob = self.transports()
        with Session(self.directory / 'pair-solana-renewal-b.sqlite', os.urandom(32), config['swap_id'],
                     daemon, self.remote.rpc, wallet=bob, config=config) as owner:
            admission, observation = owner.observe()
            self.assertTrue(admission.allow_first_exposure(), observation)
            owner.prepare('xds-claim', contract['rho_b'], contract['secret'])
            xds_id = owner.journal.intent(owner.id, 'xds-claim')['txid']
            owner.broadcast('xds-claim'); x.mine(11)
            native_receipt = owner.reconcile('xds-claim')
            self.assertTrue(native_receipt['final'])
        path, key = self.directory / 'pair-solana-renewal-a.sqlite', os.urandom(32)
        with Session(path, key, config['swap_id'], daemon, self.remote.rpc, wallet=alice,
                     config=dict(config, role='xds-owner')) as owner:
            owner.prepare('foreign-claim', self.remote.key, public_xds_txid=xds_id)
            old = owner.journal.intent(owner.id, 'foreign-claim')
            self.assertEqual(old['evidence']['source'], 'solana-blockhash-acquisition-v1')
            self.assertEqual(old['evidence']['_aad_version'], 1)
            acquired = old['evidence']['context_slot']
            blockhash = old['evidence']['recent_blockhash']
            initial = self.remote.rpc('isBlockhashValid', [blockhash, {'commitment': 'finalized', 'minContextSlot': acquired}])
            self.assertIs(initial['value'], True)
        # Real banks advance: no forged expiry response, time-based expiry claim or old send.
        deadline = time.monotonic() + 240
        while True:
            finalized = self.remote.rpc('getSlot', [{'commitment': 'finalized'}])
            if finalized > acquired:
                expiry = self.remote.rpc('isBlockhashValid', [blockhash,
                    {'commitment': 'finalized', 'minContextSlot': acquired + 1}])
                if expiry['value'] is False and expiry['context']['slot'] > acquired:
                    break
            if time.monotonic() >= deadline:
                raise TimeoutError('Genuine finalized blockhash expiry deadline expired')
            time.sleep(1)
        request = dict(path=str(path), key=key.hex(), swap_id=config['swap_id'], payer_key=bytes(self.remote.key).hex(),
                       old_txid=old['txid'], old_sha256=hashlib.sha256(old['payload']).hexdigest(),
                       native_endpoint='http://127.0.0.1:' + str(x.n.rpc))
        runtime = Path(__file__).resolve().parents[1]
        env = dict(os.environ); env['PYTHONPATH'] = str(runtime) + os.pathsep + env.get('PYTHONPATH', '')
        child = subprocess.run([sys.executable, '-B', __file__, '--renew-child'], input=json.dumps(request).encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=runtime, timeout=180,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        renewed = json.loads(child.stdout)
        self.assertEqual(renewed['status'], 'PASS'); self.assertEqual(renewed['sends'], 1)
        self.assertTrue(renewed['receipt']['final']); self.assertTrue(renewed['prior_attempt_unchanged'])
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'renewed paired native payout scanned', 60)
        balance = int(self.remote.rpc('getTokenAccountBalance', [config['foreign']['claim'], {'commitment': 'finalized'}])['value']['amount'])
        vault = int(self.remote.rpc('getTokenAccountBalance', [config['foreign']['vault'], {'commitment': 'finalized'}])['value']['amount'])
        self.assertEqual(balance, config['foreign']['amount']); self.assertEqual(vault, 0)
        self.save('pair-solana-renewal', {'status': 'PASS', 'xds': native_receipt,
            'renewal_in_fresh_process': renewed, 'expiry_observation': expiry, 'initial_blockhash_valid': initial,
            'solana_destination_balance': balance, 'solana_vault_balance': vault, 'native_balance_delta': 1000,
            'old_transaction_sent': False, 'secret_source': 'validated public native transaction only'})


if __name__ == '__main__':
    if sys.argv[1:] == ['--reopen-child']:
        reopen_child()
    elif sys.argv[1:] == ['--renew-child']:
        renew_child()
    else:
        unittest.main(verbosity=2)
