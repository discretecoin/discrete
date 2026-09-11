"""Opt-in unfunded two-owner lifecycle against real native/Bitcoin processes.

OWNER_RPC_INTEGRATION=1, BITCOIND and SWAP_BUILD_DIR are required. Synthetic
funds, isolated nodes, separate native wallets, distinct Bitcoin role keys and
separate funding/receiving Bitcoin wallets only. Both owners run the actual
Owner engine and signed mailbox. No candidate txid or preimage is supplied to
the XDS owner's claim path. Block-time bounds below are artificial regtest
scheduling assumptions, not public-network estimates or guarantees.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from swap_runtime.lifecycle import Owner
from swap_runtime.owner_protocol import validate_offer
from swap_runtime.rpc import LocalRpc
from swap_runtime.bitcoin import pubkey
import test_xds_rpc_integration as native_fixture
import test_bitcoin_funding_rpc_integration as bitcoin_fixture


def owner_step_child():
    """Fresh process with only a restored owner's key and local daemon access."""
    request = json.loads(sys.stdin.buffer.read())
    native = LocalRpc(request['native_endpoint']).daemon
    cookie = (Path(request['bitcoin_directory']) / 'regtest/.cookie').read_text().strip()
    bitcoin = LocalRpc(request['bitcoin_endpoint'], cookie)
    # No signing wallet or new private/candidate witness is passed to the child.
    with Owner(request['directory'], bytes.fromhex(request['owner_key']), native, bitcoin) as owner:
        result = owner.step()
        proof = owner.store.get('scanner.claim')
        public = dict(result=result, recovery_required=owner.store.recovery_required(),
                      scanner_txid=proof['txid'] if proof else None)
        if owner.session is not None:
            kind = 'foreign-claim' if owner.role == 'xds-owner' else 'xds-claim'
            intent = owner.session.journal.intent(owner.offer['swap_id'], kind)
            public.update(session_recovery=owner.session.journal.recovery_required(),
                          public_exposure=owner.session._public_proof(),
                          intent_txid=intent['txid'] if intent else None,
                          payload_sha256=hashlib.sha256(intent['payload']).hexdigest() if intent else None)
        print(json.dumps(public))


@unittest.skipUnless(os.environ.get('OWNER_RPC_INTEGRATION') == '1' and
                     bitcoin_fixture.BITCOIND and Path(bitcoin_fixture.BITCOIND).is_file(),
                     'set OWNER_RPC_INTEGRATION=1, BITCOIND and SWAP_BUILD_DIR for owned lifecycle')
class OwnerRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_fixture.XdsRpcIntegration.setUpClass()
        try:
            bitcoin_fixture.BitcoinFundingRpcIntegration.setUpClass()
            cls.native = native_fixture.XdsRpcIntegration('runTest')
            cls.bitcoin = bitcoin_fixture.BitcoinFundingRpcIntegration('runTest')
            cls.btc = cls.bitcoin.node
            cls.btc.rpc('createwallet', ['xds-owner-receive'])
            cls.directory = cls.native.directory / 'owners'
            cls.directory.mkdir()
        except BaseException:
            if hasattr(bitcoin_fixture.BitcoinFundingRpcIntegration, 'node'):
                bitcoin_fixture.BitcoinFundingRpcIntegration.tearDownClass()
            native_fixture.XdsRpcIntegration.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            bitcoin_fixture.BitcoinFundingRpcIntegration.tearDownClass()
        finally:
            native_fixture.XdsRpcIntegration.tearDownClass()

    def setUp(self):
        self.opened, self.actions = [], []
        x = self.native.x
        self.native_rpc = LocalRpc('http://127.0.0.1:' + str(x.n.rpc)).daemon
        self.bitcoin_rpc = LocalRpc('http://127.0.0.1:' + str(self.btc.port), self.btc.auth)
        self.native_wallets = {
            'xds-owner': LocalRpc('http://127.0.0.1:' + str(x.alice.rpc), x.alice.auth).wallet,
            'foreign-owner': LocalRpc('http://127.0.0.1:' + str(x.bob.rpc), x.bob.auth).wallet}

    def tearDown(self):
        for owner in reversed(self.opened):
            owner.close()

    def bitcoin_wallet(self, name):
        if name not in ('swaps-runtime', 'xds-owner-receive'):
            raise ValueError('Owned fixture wallet required')
        return lambda method, params: self.bitcoin_rpc._json_rpc('/wallet/' + name, method, params)

    def offer(self, name, native_delay=80, bitcoin_delay=200):
        x, n = self.native.x, self.btc
        contract = x.contract(delay=native_delay)
        claim_key, refund_key = self.bitcoin.claim_key, self.bitcoin.refund_key
        funding_wallet, receiving_wallet = self.bitcoin_wallet('swaps-runtime'), self.bitcoin_wallet('xds-owner-receive')
        claim_address = receiving_wallet('getnewaddress', ['', 'bech32'])
        refund_address = funding_wallet('getnewaddress', ['', 'bech32'])
        change_address = funding_wallet('getrawchangeaddress', ['bech32'])
        terms = contract['terms']
        native = dict(genesis_hash=terms['genesis_hash'], hashlock=terms['hashlock'], nonce=terms['nonce'],
            claim_commitment=contract['b']['commitment'], refund_commitment=contract['a']['commitment'],
            claim_address=contract['b']['address'], refund_address=contract['a']['address'],
            refund_height=terms['refund_height'], funding_value_atoms=1001, net_amount_atoms=1000,
            fee_atoms=1, min_confirmations=11)
        foreign = dict(contract=dict(genesis_hash=n.rpc('getblockhash', [0]), hashlock=terms['hashlock'],
            claim_pubkey=pubkey(claim_key).hex(), refund_pubkey=pubkey(refund_key).hex(),
            refund_height=n.rpc('getblockcount', []) + bitcoin_delay, funding_value_sats=100000,
            claim_script=receiving_wallet('getaddressinfo', [claim_address])['scriptPubKey'],
            refund_script=funding_wallet('getaddressinfo', [refund_address])['scriptPubKey'],
            fee_sats=1000, min_confirmations=2), funding_fee_sats=1000,
            change_address=change_address, change_script=funding_wallet('getaddressinfo', [change_address])['scriptPubKey'],
            min_input_confirmations=2)
        offer = dict(version=1, swap_id=name, foreign_chain='bitcoin', xds=native, foreign=foreign,
            policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2, foreign_claim_budget_units=2,
                        max_observation_seconds=15, solana_fee_attempt_reserve=2),
            schedule=dict(xds_min_funding_blocks=20, foreign_min_funding_units=8,
                foreign_min_before_xds_fund=12, foreign_min_before_xds_claim=6, max_observation_seconds=15,
                xds_block_upper_ms=1000, foreign_unit_lower_ms=1000, safety_margin_ms=1000))
        return validate_offer(offer), contract

    def pair(self, name):
        offer, native = self.offer(name)
        path = self.directory / name
        path.mkdir()
        exchange = path / 'exchange'
        exchange.mkdir()
        keys = {role: os.urandom(32) for role in ('xds-owner', 'foreign-owner')}
        owners = {}
        for role, btc_key, rho in (('xds-owner', self.bitcoin.claim_key, native['rho_a']),
                                   ('foreign-owner', self.bitcoin.refund_key, native['rho_b'])):
            credentials = dict(xds_rho=rho.hex(), foreign_key=btc_key.private_numbers().private_value.to_bytes(32, 'big').hex())
            if role == 'foreign-owner':
                credentials['secret'] = native['secret'].hex()
            owner = Owner(path / role, keys[role], self.native_rpc, self.bitcoin_rpc,
                wallet=self.native_wallets[role],
                foreign_wallet=self.bitcoin_wallet('swaps-runtime') if role == 'foreign-owner' else None,
                exchange_dir=exchange, backup_dir=path / (role + '-backups'), offer=offer, role=role, credentials=credentials)
            self.opened.append(owner)
            owners[role] = owner
        self.assertNotIn('secret', owners['xds-owner'].credentials)
        self.assertIsNone(owners['xds-owner'].store.get('funding.attempt'))
        self.assertIsNone(owners['foreign-owner'].store.get('funding.attempt'))
        return path, offer, native, keys, owners

    def step(self, owner):
        result = owner.step()
        self.actions.append(dict(role=owner.role, action=result['action']))
        self.assertNotIn('"secret"', json.dumps(result))
        print('owner-step=' + json.dumps(dict(swap=owner.offer['swap_id'], role=owner.role, action=result['action'])), flush=True)
        return result

    def mine_pending(self):
        # No mining on a polling timer: only actual owned mempool entries cause
        # confirmation advancement. Abandonment explicitly advances its deadline.
        native_pool = self.native_rpc('getrawtransactionspool', {})
        self.assertEqual(native_pool['status'], 'OK')
        if native_pool['transactions']:
            self.native.x.mine(11)
        if self.btc.rpc('getrawmempool', []):
            self.btc.mine(2)

    def drive(self, owners, done, rounds=20):
        for _ in range(rounds):
            if done():
                return
            for owner in owners.values():
                self.step(owner)
            self.mine_pending()
        self.assertTrue(done(), 'Owner engine did not converge: ' + json.dumps(self.actions))

    def paired(self, owners):
        return all(owner.session is not None for owner in owners.values())

    def settled(self, owners):
        return all((owner.store.get('settlement.status') or {}).get('final') is True for owner in owners.values())

    def reopened(self, directory, key, role):
        owner = Owner(directory, key, self.native_rpc, self.bitcoin_rpc, wallet=self.native_wallets[role],
                      foreign_wallet=self.bitcoin_wallet('swaps-runtime') if role == 'foreign-owner' else None)
        self.opened.append(owner)
        return owner

    def child_step(self, directory, key):
        request = dict(directory=str(directory), owner_key=key.hex(),
            native_endpoint='http://127.0.0.1:' + str(self.native.x.n.rpc),
            bitcoin_endpoint='http://127.0.0.1:' + str(self.btc.port), bitcoin_directory=str(self.btc.path))
        self.assertNotIn('secret', request)
        self.assertNotIn('txid', request)
        child = subprocess.run([sys.executable, '-B', __file__, '--owner-step-child'],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        return json.loads(child.stdout)

    def assert_mailbox_private(self, path, secret):
        for packet in (path / 'exchange').iterdir():
            self.assertNotIn(secret.hex().encode(), packet.read_bytes(), 'Claim secret leaked into public mailbox')

    def test_01_unfunded_both_owners_automatic_public_claim_and_ordinary_wallet_outputs(self):
        x = self.native.x
        x.alice.synced(); x.bob.synced()
        before = x.bob.balance()
        path, offer, native, keys, owners = self.pair('owner-success')
        self.drive(owners, lambda: self.settled(owners))
        alice, bob = owners['xds-owner'], owners['foreign-owner']
        proof = alice.store.get('scanner.claim')
        native_claim = bob.session.journal.intent(offer['swap_id'], 'xds-claim')
        bitcoin_claim = alice.session.journal.intent(offer['swap_id'], 'foreign-claim')
        self.assertEqual(proof['txid'], native_claim['txid'])
        self.assertTrue(proof['acquisition']['full_wire_fetched'])
        self.assertNotIn('secret', alice.credentials)
        self.assertTrue(alice.session._public_proof())
        self.assertEqual(alice.store.get('funding.attempt')['raw'], alice.store.get('terms.xds')['funding_wire'])
        self.assert_mailbox_private(path, native['secret'])
        self.assertTrue(any((path / 'xds-owner-backups').glob('*.backup')))
        self.assertTrue(any((path / 'foreign-owner-backups').glob('*.backup')))
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'full owner native payout scanned', 60)
        ordinary = x.bob.call('transfer', dict(destinations=[dict(address=native['a']['address'], amount=900)],
                             fee=1, unlock_height=0, payment_id='', extra=''))
        self.mine_pending()
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 99, 'full owner native ordinary change scanned', 60)
        self.assertTrue(x.n.outpoint(ordinary['tx_hash'])['in_chain'])
        utxo = self.btc.rpc('gettxout', [bitcoin_claim['txid'], 0])
        self.assertEqual(utxo['scriptPubKey']['hex'], offer['foreign']['contract']['claim_script'])
        receiving = self.bitcoin_wallet('xds-owner-receive')
        target = receiving('getnewaddress', ['', 'bech32'])
        unsigned = self.btc.rpc('createrawtransaction', [[dict(txid=bitcoin_claim['txid'], vout=0)], {target: '0.00098'}])
        signed = receiving('signrawtransactionwithwallet', [unsigned])
        self.assertTrue(signed['complete'])
        ordinary_id = self.btc.rpc('sendrawtransaction', [signed['hex']])
        self.mine_pending()
        self.assertIsNotNone(self.btc.rpc('gettxout', [ordinary_id, 0]))

    def test_02_no_native_funding_foreign_owner_restores_and_refunds_own_bitcoin(self):
        path, offer, native, keys, owners = self.pair('owner-no-counterparty')
        alice, bob = owners['xds-owner'], owners['foreign-owner']
        self.assertEqual(self.step(alice)['action'], 'wait-peer-acceptance')
        self.step(bob)
        self.mine_pending()
        self.step(bob)
        self.assertIsNone(alice.store.get('funding.attempt'))
        self.assertIsNotNone(bob.store.get('funding.attempt'))
        self.assertIsNone(bob.session)
        original = bob.store.get('funding.attempt')
        snapshot = bob.backup(path / 'foreign-funded-without-native.backup')
        bob.close(); alice.close()
        target = path / 'foreign-restored'
        Owner.restore(snapshot, target, keys['foreign-owner'])
        self.btc.mine(offer['foreign']['contract']['refund_height'] - self.btc.rpc('getblockcount', []))
        recovered = self.child_step(target, keys['foreign-owner'])
        self.assertTrue(recovered['recovery_required'])
        self.assertEqual(recovered['result']['action'], 'refund-submitted')
        self.mine_pending()
        reopened = self.reopened(target, keys['foreign-owner'], 'foreign-owner')
        result = self.step(reopened)
        self.assertEqual(result['action'], 'refund-observed')
        self.assertTrue(result['final'])
        self.assertEqual(reopened.store.get('funding.attempt'), original)
        self.assertIsNone(reopened.store.get('terms.xds'))
        refund = reopened.store.get('refund.intent')
        output = self.btc.rpc('gettxout', [refund['txid'], 0])
        self.assertEqual(output['scriptPubKey']['hex'], offer['foreign']['contract']['refund_script'])
        self.assertEqual(str(output['value']), '0.00099000')
        self.assert_mailbox_private(path, native['secret'])

    def test_03_paired_preclaim_backup_blocks_first_exposure_then_protects_public_claim_in_fresh_process(self):
        path, offer, native, keys, owners = self.pair('owner-paired-recovery')
        self.drive(owners, lambda: self.paired(owners))
        alice, bob = owners['xds-owner'], owners['foreign-owner']
        funding_alice, funding_bob = alice.store.get('funding.attempt'), bob.store.get('funding.attempt')
        self.assertIsNone(bob.session.journal.intent(offer['swap_id'], 'xds-claim'))
        alice_backup = alice.backup(path / 'alice-before-claim.backup')
        bob_backup = bob.backup(path / 'bob-before-claim.backup')
        alice.close()
        restored_alice, restored_bob = path / 'alice-restored', path / 'bob-restored'
        Owner.restore(alice_backup, restored_alice, keys['xds-owner'])
        Owner.restore(bob_backup, restored_bob, keys['foreign-owner'])
        protected_bob = self.reopened(restored_bob, keys['foreign-owner'], 'foreign-owner')
        result = self.step(protected_bob)
        self.assertEqual(result['action'], 'protective-no-first-claim')
        self.assertIsNone(protected_bob.session.journal.intent(offer['swap_id'], 'xds-claim'))
        self.assertEqual(protected_bob.store.get('funding.attempt'), funding_bob)
        protected_bob.close()
        self.assertEqual(self.step(bob)['action'], 'claim-submitted')
        native_claim = bob.session.journal.intent(offer['swap_id'], 'xds-claim')
        recovered = self.child_step(restored_alice, keys['xds-owner'])
        self.assertTrue(recovered['recovery_required'])
        self.assertTrue(recovered['session_recovery'])
        self.assertTrue(recovered['public_exposure'])
        self.assertEqual(recovered['scanner_txid'], native_claim['txid'])
        self.assertEqual(recovered['result']['action'], 'claim-submitted')
        self.mine_pending()
        active_alice = self.reopened(restored_alice, keys['xds-owner'], 'xds-owner')
        self.drive({'xds-owner': active_alice, 'foreign-owner': bob}, lambda: self.settled({'a': active_alice, 'b': bob}))
        self.assertEqual(active_alice.store.get('funding.attempt'), funding_alice)
        self.assertEqual(active_alice.session.journal.intent(offer['swap_id'], 'foreign-claim')['txid'], recovered['intent_txid'])
        self.assertTrue(active_alice.store.recovery_required())
        self.assert_mailbox_private(path, native['secret'])


if __name__ == '__main__':
    if '--owner-step-child' in sys.argv:
        owner_step_child()
    else:
        unittest.main(verbosity=2)
