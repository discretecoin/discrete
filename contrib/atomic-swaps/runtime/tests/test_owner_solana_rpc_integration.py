"""Owned, opt-in unfunded XDS/Solana Owner lifecycle against actual ledgers.

OWNER_SOLANA_RPC_INTEGRATION=1 and OWNER_SOLANA_RUN_DIR select the public
solana_fixture synthetic-ledger fixture. OWNER_SOLANA_BRIDGE_FACTORY retains an
explicit legacy operator override. Its create_bridge() instance provides rpc,
setup(hashlock_hex, delay_slots), local owner_key/claim_key and close(). setup
only provisions an ordinary token source and two independent System fee payers;
the unmodified Owner engine creates and funds all escrow accounts itself.
Timing bounds below describe controlled test scheduling, not public networks.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import unittest

from swap_runtime.lifecycle import Owner
from swap_runtime.owner_protocol import validate_offer
from swap_runtime.rpc import LocalRpc
from swap_runtime.solana import profile
import test_xds_rpc_integration as native_fixture


def bridge():
    if os.environ.get('OWNER_SOLANA_RUN_DIR'):
        from solana_fixture import create_bridge
        return create_bridge()
    path = Path(os.environ['OWNER_SOLANA_BRIDGE_FACTORY']).resolve()
    spec = importlib.util.spec_from_file_location('owned_solana_owner_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_bridge()


def owner_step_child():
    """Reload only authenticated owner credentials; no preimage/candidate input."""
    request = json.loads(sys.stdin.buffer.read())
    remote = bridge()
    sends = []
    try:
        daemon = LocalRpc(request['native_endpoint']).daemon
        def counted(method, params):
            if method == 'sendTransaction':
                sends.append(method)
            return remote.rpc(method, params)
        with Owner(request['directory'], bytes.fromhex(request['owner_key']), daemon, counted) as owner:
            result = owner.step()
            packet = owner._attempt('funding')
            print(json.dumps(dict(result=result, recovery_required=owner.store.recovery_required(),
                funding_txid=packet['txid'], funding_sha256=hashlib.sha256(bytes.fromhex(packet['raw'])).hexdigest(),
                native_funding_present=owner.store.get('terms.xds') is not None,
                public_claim_present=owner.store.get('scanner.claim') is not None, sends=len(sends))))
    finally:
        remote.close()


@unittest.skipUnless(os.environ.get('OWNER_SOLANA_RPC_INTEGRATION') == '1',
                     'Set owned native/private Solana bridge fixture explicitly')
class OwnerSolanaRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_fixture.XdsRpcIntegration.setUpClass()
        try:
            cls.native = native_fixture.XdsRpcIntegration('runTest')
            cls.remote = bridge()
            cls.directory = cls.native.directory / 'solana-owners'
            cls.directory.mkdir()
        except BaseException:
            native_fixture.XdsRpcIntegration.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.remote.close()
        finally:
            native_fixture.XdsRpcIntegration.tearDownClass()

    def setUp(self):
        self.opened, self.actions, self.foreign_sends = [], [], []
        x = self.native.x
        self.daemon = LocalRpc('http://127.0.0.1:' + str(x.n.rpc)).daemon
        self.wallets = {
            'xds-owner': LocalRpc('http://127.0.0.1:' + str(x.alice.rpc), x.alice.auth).wallet,
            'foreign-owner': LocalRpc('http://127.0.0.1:' + str(x.bob.rpc), x.bob.auth).wallet}

    def tearDown(self):
        for owner in reversed(self.opened):
            owner.close()

    def foreign(self, method, params):
        if method == 'sendTransaction':
            self.foreign_sends.append(hashlib.sha256(base64.b64decode(params[0], validate=True)).hexdigest())
        return self.remote.rpc(method, params)

    def pair(self, name, delay_slots=1600):
        native = self.native.x.contract(delay=80)
        setup = self.remote.setup(native['terms']['hashlock'], delay_slots)
        foreign = setup['terms']
        self.assertEqual(foreign['owner'], str(self.remote.owner_key.pubkey()))
        self.assertEqual(foreign['claim_payer'], str(self.remote.claim_key.pubkey()))
        self.assertNotEqual(foreign['owner'], foreign['claim_payer'])
        self.assertNotIn('state', foreign)
        self.assertNotIn('vault', foreign)
        self.assertGreaterEqual(setup['source_balance'], foreign['amount'])
        t = native['terms']
        terms = dict(genesis_hash=t['genesis_hash'], hashlock=t['hashlock'], nonce=t['nonce'],
            claim_commitment=native['b']['commitment'], refund_commitment=native['a']['commitment'],
            claim_address=native['b']['address'], refund_address=native['a']['address'],
            refund_height=t['refund_height'], funding_value_atoms=1001, net_amount_atoms=1000,
            fee_atoms=1, min_confirmations=11)
        offer = validate_offer(dict(version=1, swap_id=name, foreign_chain='solana', xds=terms, foreign=foreign,
            policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2, foreign_claim_budget_units=2,
                max_observation_seconds=15, solana_fee_attempt_reserve=2),
            schedule=dict(xds_min_funding_blocks=20, foreign_min_funding_units=160,
                foreign_min_before_xds_fund=220, foreign_min_before_xds_claim=30, max_observation_seconds=15,
                xds_block_upper_ms=1000, foreign_unit_lower_ms=400, safety_margin_ms=1000)))
        path = self.directory / name
        path.mkdir()
        exchange = path / 'exchange'
        exchange.mkdir()
        keys = {role: os.urandom(32) for role in ('xds-owner', 'foreign-owner')}
        owners = {}
        for role, payer, rho in (('xds-owner', self.remote.claim_key, native['rho_a']),
                                  ('foreign-owner', self.remote.owner_key, native['rho_b'])):
            credentials = dict(xds_rho=rho.hex(), foreign_key=bytes(payer).hex())
            if role == 'foreign-owner':
                credentials['secret'] = native['secret'].hex()
            owner = Owner(path / role, keys[role], self.daemon, self.foreign,
                wallet=self.wallets[role], exchange_dir=exchange, backup_dir=path / (role + '-backups'),
                offer=offer, role=role, credentials=credentials)
            self.opened.append(owner)
            owners[role] = owner
            self.assertIsNone(owner.store.get('funding.attempt'))
            self.assertIsNone(owner.store.get('solana.accounts'))
        self.assertNotIn('secret', owners['xds-owner'].credentials)
        return path, offer, native, keys, owners

    def step(self, owner):
        result = owner.step()
        public = dict(swap=owner.offer['swap_id'], role=owner.role, action=result['action'])
        self.assertNotIn('"secret"', json.dumps(result))
        self.actions.append(public)
        print('owner-step=' + json.dumps(public), flush=True)
        return result

    def mine_pending(self):
        pool = self.daemon('getrawtransactionspool', {})
        self.assertEqual(pool['status'], 'OK')
        if pool['transactions']:
            self.native.x.mine(11)

    def drive(self, owners, done, timeout=360):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if done():
                return
            for owner in owners.values():
                self.step(owner)
            self.mine_pending()
            time.sleep(1)
        self.assertTrue(done(), 'Owner did not converge: ' + json.dumps(self.actions[-12:]))

    def settled(self, owners):
        return all((owner.store.get('settlement.status') or {}).get('final') is True
                   and owner.store.get('settlement.status')['status'] == 'confirmed' for owner in owners.values())

    def balance(self, address):
        return int(self.remote.rpc('getTokenAccountBalance', [address, {'commitment': 'finalized'}])['value']['amount'])

    def assert_mailbox_private(self, path, secret):
        for packet in (path / 'exchange').iterdir():
            self.assertNotIn(secret.hex().encode(), packet.read_bytes())

    def save(self, name, report):
        with (self.directory / (name + '-public-receipt.json')).open('xb') as stream:
            stream.write((json.dumps(report, indent=2) + '\n').encode())

    def ordinary_spend(self, source, destination, payer, amount):
        from solders.hash import Hash
        from solders.instruction import AccountMeta, Instruction
        from solders.message import Message
        from solders.pubkey import Pubkey
        from solders.transaction import Transaction
        before_source, before_destination = self.balance(source), self.balance(destination)
        block = self.remote.rpc('getLatestBlockhash', [{'commitment': 'finalized'}])
        instruction = Instruction(Pubkey.from_string(profile.TOKEN), bytes([3]) + struct.pack('<Q', amount), [
            AccountMeta(Pubkey.from_string(source), False, True),
            AccountMeta(Pubkey.from_string(destination), False, True), AccountMeta(payer.pubkey(), True, False)])
        recent = Hash.from_string(block['value']['blockhash'])
        transaction = Transaction([payer], Message.new_with_blockhash([instruction], payer.pubkey(), recent), recent)
        raw, txid = bytes(transaction), str(transaction.signatures[0])
        sent = self.remote.rpc('sendTransaction', [base64.b64encode(raw).decode(),
            {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0}])
        self.assertEqual(sent, txid)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            receipt = self.remote.rpc('getTransaction', [txid, {'encoding': 'base64', 'commitment': 'finalized',
                                                               'maxSupportedTransactionVersion': 0}])
            if receipt is not None:
                self.assertIsNone(receipt['meta']['err'])
                self.assertEqual(base64.b64decode(receipt['transaction'][0], validate=True), raw)
                self.assertEqual(self.balance(source), before_source - amount)
                self.assertEqual(self.balance(destination), before_destination + amount)
                return dict(txid=txid, slot=receipt['slot'], amount=amount,
                            wire_sha256=hashlib.sha256(raw).hexdigest(), final=True)
            time.sleep(1)
        raise TimeoutError('Ordinary token transfer did not finalize')

    def child_step(self, directory, key):
        request = dict(directory=str(directory), owner_key=key.hex(),
                       native_endpoint='http://127.0.0.1:' + str(self.native.x.n.rpc))
        self.assertNotIn('secret', request)
        self.assertNotIn('txid', request)
        child = subprocess.run([sys.executable, '-B', __file__, '--owner-step-child'],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        return json.loads(child.stdout)

    def test_01_unfunded_owner_pair_auto_discovery_and_ordinary_payout_spends(self):
        x = self.native.x
        x.alice.synced(); x.bob.synced()
        before = x.bob.balance()
        path, offer, native, keys, owners = self.pair('owner-solana-success')
        self.drive(owners, lambda: self.settled(owners))
        alice, bob = owners['xds-owner'], owners['foreign-owner']
        proof = alice.store.get('scanner.claim')
        native_claim = bob.session.journal.intent(offer['swap_id'], 'xds-claim')
        foreign_claim = alice.session.journal.intent(offer['swap_id'], 'foreign-claim')
        self.assertEqual(proof['txid'], native_claim['txid'])
        self.assertTrue(proof['acquisition']['full_wire_fetched'])
        self.assertTrue(alice.session._public_proof())
        self.assertNotIn('secret', alice.credentials)
        self.assertEqual(alice.store.get('funding.attempt')['raw'], alice.store.get('terms.xds')['funding_wire'])
        self.assertIsNotNone(bob.store.get('solana.accounts'))
        self.assertIsNotNone(bob.store.get('funding.acquisition'))
        self.assert_mailbox_private(path, native['secret'])
        self.assertTrue(any((path / 'xds-owner-backups').glob('*.backup')))
        self.assertTrue(any((path / 'foreign-owner-backups').glob('*.backup')))
        native_receipt = bob.session.reconcile('xds-claim')
        solana_receipt = alice.session.reconcile('foreign-claim')
        self.assertTrue(native_receipt['final']); self.assertTrue(solana_receipt['final'])
        sends = len(self.foreign_sends)
        self.assertEqual(self.step(alice)['action'], 'claim-observed')
        self.assertEqual(self.step(bob)['action'], 'claim-observed')
        self.assertEqual(len(self.foreign_sends), sends)
        terms = alice.store.get('terms.foreign')
        self.assertEqual(self.balance(terms['vault']), 0)
        self.assertGreaterEqual(self.balance(terms['claim']), offer['foreign']['amount'])
        ordinary_solana = self.ordinary_spend(terms['claim'], terms['source'], self.remote.claim_key, 100000)
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'Owner Solana native payout scanned', 60)
        ordinary = x.bob.call('transfer', dict(destinations=[dict(address=native['a']['address'], amount=900)],
                            fee=1, unlock_height=0, payment_id='', extra=''))
        self.mine_pending()
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 99, 'Owner ordinary native change scanned', 60)
        self.assertTrue(x.n.outpoint(ordinary['tx_hash'])['in_chain'])
        self.save('owner-solana-success', dict(status='PASS', xds=native_receipt, solana=solana_receipt,
            ordinary_solana=ordinary_solana, ordinary_xds_txid=ordinary['tx_hash'], native_payout_atoms=1000,
            foreign_claim_txid=foreign_claim['txid'], automatic_public_scanner=True, unchanged_retry_sends=True,
            funding_source='Owner created and signed both funding artifacts from unfunded offer'))

    def test_02_foreign_only_deposit_backup_fresh_process_refund_without_native_funding(self):
        path, offer, native, keys, owners = self.pair('owner-solana-no-counterparty', delay_slots=550)
        alice, bob = owners['xds-owner'], owners['foreign-owner']
        self.assertEqual(self.step(alice)['action'], 'wait-peer-acceptance')
        self.drive({'foreign-owner': bob}, lambda: bob.exchange.read('foreign-owner', 'funding') is not None)
        original = bob._attempt('funding')
        funding_receipt = bob.foreign_funding.receipt(*bob._funding_args(original))
        self.assertEqual(funding_receipt['status'], 'confirmed')
        self.assertTrue(funding_receipt['final'])
        self.assertIsNone(alice.store.get('funding.attempt'))
        self.assertIsNone(bob.store.get('terms.xds'))
        self.assertIsNone(bob.session)
        terms = bob.store.get('terms.foreign')
        snapshot = bob.backup(path / 'foreign-only-funded.backup')
        bob.close(); alice.close()
        restored = path / 'foreign-restored'
        Owner.restore(snapshot, restored, keys['foreign-owner'])
        self.assertLess(self.remote.rpc('getSlot', [{'commitment': 'finalized'}]), offer['foreign']['deadline_slot'])
        early = self.child_step(restored, keys['foreign-owner'])
        self.assertEqual(early['result']['action'], 'protective-await-refund')
        self.assertTrue(early['recovery_required'])
        self.assertEqual(early['sends'], 0)
        self.assertFalse(early['native_funding_present'])
        self.assertFalse(early['public_claim_present'])
        self.assertEqual(early['funding_txid'], original['txid'])
        self.assertEqual(early['funding_sha256'], hashlib.sha256(bytes.fromhex(original['raw'])).hexdigest())
        deadline = time.monotonic() + 420
        while self.remote.rpc('getSlot', [{'commitment': 'finalized'}]) < offer['foreign']['deadline_slot']:
            if time.monotonic() >= deadline:
                raise TimeoutError('Private finalized Solana refund deadline not reached')
            time.sleep(1)
        recovered = self.child_step(restored, keys['foreign-owner'])
        self.assertTrue(recovered['recovery_required'])
        self.assertFalse(recovered['native_funding_present'])
        self.assertFalse(recovered['public_claim_present'])
        self.assertEqual(recovered['result']['action'], 'refund-submitted')
        self.assertEqual(recovered['sends'], 1)
        self.assertEqual(recovered['funding_txid'], original['txid'])
        self.assertEqual(recovered['funding_sha256'], hashlib.sha256(bytes.fromhex(original['raw'])).hexdigest())
        owner = Owner(restored, keys['foreign-owner'], self.daemon, self.foreign)
        self.opened.append(owner)
        self.drive({'foreign-owner': owner}, lambda: self.settled({'foreign-owner': owner}))
        self.assertEqual(owner._attempt('funding'), original)
        refund = owner._attempt('refund')
        receipt = owner._foreign_adapter().receipt('foreign-refund', bytes.fromhex(refund['raw']), refund['txid'])
        self.assertTrue(receipt['final']); self.assertTrue(receipt['publicly_observed'])
        self.assertEqual(self.balance(terms['refund']), offer['foreign']['amount'])
        self.assertEqual(self.balance(terms['vault']), 0)
        self.assert_mailbox_private(path, native['secret'])
        owner.close()
        second = self.child_step(restored, keys['foreign-owner'])
        self.assertEqual(second['sends'], 0)
        self.assertEqual(second['result']['action'], 'refund-observed')
        self.assertTrue(second['result']['final'])
        ordinary = self.ordinary_spend(terms['refund'], terms['source'], self.remote.owner_key, 100000)
        self.save('owner-solana-refund', dict(status='PASS', funding=funding_receipt, refund=receipt,
            before_maturity_fresh_process=early, fresh_process=recovered,
            finalized_fresh_process_retry=second, ordinary_solana=ordinary,
            native_funding_absent=True, exact_funding_artifact_preserved=True))


if __name__ == '__main__':
    if '--owner-step-child' in sys.argv:
        owner_step_child()
    else:
        unittest.main(verbosity=2)
