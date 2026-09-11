"""Opt-in real XDS/Bitcoin with durable preparation and paired external snapshots.

The chain processes are real; independent AnchorStore instances use their signed
protocol in process. Real pinned HTTPS/process faults have their own tests. No
public chain, real assets, or atomicity between checkpoint CAS and chains claimed.
"""
import hashlib
import os
from pathlib import Path
import unittest
import re
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from swap_runtime.anchor import AnchorStore, AnchorClient
from swap_runtime.anchored_owner import AnchoredOwner
from swap_runtime.xds import _Unavailable
import test_owner_rpc_integration as previous


class HardenedOwnerRpcIntegration(previous.OwnerRpcIntegration):
    def setUp(self):
        super().setUp()
        self.anchors = []
        self.parameters = {}

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            for anchor in reversed(self.anchors):
                anchor.close()

    def pair(self, name):
        offer, native = self.offer(name)
        path = self.directory / name
        path.mkdir()
        exchange = path / 'exchange'; exchange.mkdir()
        keys = {role: os.urandom(32) for role in ('xds-owner', 'foreign-owner')}
        owners = {}
        for role, btc_key, rho in (('xds-owner', self.bitcoin.claim_key, native['rho_a']),
                                   ('foreign-owner', self.bitcoin.refund_key, native['rho_b'])):
            signer = Ed25519PrivateKey.generate()
            profile = dict(service_id=os.urandom(32).hex(), stream_id=os.urandom(32).hex())
            store = AnchorStore(path / (role + '-external.db'), **profile,
                writer_public_key=signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), create=True)
            self.anchors.append(store)
            client = AnchorClient(store.handle, **profile, writer_key=signer)
            credentials = dict(xds_rho=rho.hex(), foreign_key=btc_key.private_numbers().private_value.to_bytes(32, 'big').hex())
            if role == 'foreign-owner':
                credentials['secret'] = native['secret'].hex()
            options = dict(wallet=self.native_wallets[role],
                foreign_wallet=self.bitcoin_wallet('swaps-runtime') if role == 'foreign-owner' else None,
                anchor_client=client)
            owner = AnchoredOwner(path / role, keys[role], self.native_rpc, self.bitcoin_rpc,
                exchange_dir=exchange, backup_dir=path / (role + '-backups'), offer=offer,
                role=role, credentials=credentials, durable_funding=True, **options)
            self.opened.append(owner)
            self.parameters[role] = dict(directory=path / role, key=keys[role], **options)
            owners[role] = owner
        return path, offer, native, keys, owners

    def step(self, outer):
        result = outer.step()
        self.actions.append(dict(role=outer.owner.role, action=result['action']))
        self.assertEqual(outer.head, outer.client.read())
        return result

    def paired(self, owners):
        return all(owner.owner.session is not None for owner in owners.values())

    def settled(self, owners):
        return all((owner.owner.store.get('settlement.status') or {}).get('final') is True for owner in owners.values())

    def reopen(self, role):
        outer = AnchoredOwner(daemon=self.native_rpc, foreign=self.bitcoin_rpc, **self.parameters[role])
        self.opened.append(outer)
        return outer

    def assert_explorer_transaction(self, txid, label, *, funding=None, refund_height=None):
        # Exercise the actual HTTP renderer on the owned validating daemon.
        # An omitted swap fee must not appear as a zero-fee block to users.
        def page(path):
            request = urllib.request.Request('http://127.0.0.1:' + str(self.native.x.n.rpc) + path)
            with self.native.lab.OPENER.open(request, timeout=15) as response:
                self.assertEqual(response.status, 200)
                return response.read().decode('utf-8')
        detail = page('/explorer/tx/' + txid)
        self.assertTrue('Type: ' + label + ' (v1)' in detail, 'Explorer transaction type is missing')
        self.assertTrue(re.search(r'Fee:\s+0\.01\s', detail), 'Explorer transaction fee is missing')
        state = self.native.x.n.outpoint(txid)
        self.assertTrue(state['in_chain'])
        block = page('/explorer/block/' + state['block_hash'])
        row = next((row for row in re.findall(r'<tr>.*?</tr>', block, re.S)
                    if '/explorer/tx/' + txid in row), '')
        self.assertTrue('<td>' + label + '</td>' in row, 'Explorer row type is missing')
        self.assertTrue('<td>0.01</td>' in row, 'Explorer row fee is missing')
        # These fixtures mine funding, claim and the ordinary payment separately.
        self.assertTrue(re.search(r'Fees:\s+0\.01\s', block), 'Explorer block fee is incorrect')
        if funding is not None:
            inputs = detail.split('<h3>Inputs</h3>', 1)[1].split('<h3>Outputs</h3>', 1)[0]
            self.assertTrue('/explorer/tx/' + funding in inputs, 'Explorer swap input link is missing')
            self.assertTrue('claim' in inputs, 'Explorer swap branch is missing')
            self.assertEqual(inputs.count('<td'), inputs.count('</td>'))
        if refund_height is not None:
            self.assertTrue('hashlock:' in detail, 'Explorer conditional output is missing')
            self.assertTrue('refund from height ' + str(refund_height) in detail,
                            'Explorer refund height is missing')

    def test_hardened_full_funding_claim_pair_and_ordinary_spends(self):
        path, offer, native, _, owners = self.pair('hardened-owner-success')
        before = self.native.x.bob.balance()
        self.drive(owners, lambda: self.settled(owners))
        alice, bob = owners['xds-owner'].owner, owners['foreign-owner'].owner
        self.assertTrue(alice.durable_funding)
        self.assertIsNotNone(alice.store.get('funding.operation'))
        self.assertEqual(alice.store.get('scanner.claim')['txid'],
                         bob.session.journal.intent(offer['swap_id'], 'xds-claim')['txid'])
        self.assertTrue(bob.session.journal.exposed(offer['swap_id']))
        foreign_claim = alice.session.journal.intent(offer['swap_id'], 'foreign-claim')
        self.assert_mailbox_private(path, native['secret'])
        for role in tuple(owners):
            old = owners[role].head
            owners[role].close()
            owners[role] = self.reopen(role)
            self.assertEqual(owners[role].head, old)
            self.assertFalse(owners[role].owner.store.recovery_required())
        self.assertTrue(owners['foreign-owner'].owner.session.journal.exposed(offer['swap_id']))
        x = self.native.x
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'anchored native payout', 60)
        ordinary = x.bob.call('transfer', dict(destinations=[dict(address=native['a']['address'], amount=900)],
                             fee=1, unlock_height=0, payment_id='', extra=''))
        self.mine_pending()
        self.assertTrue(x.n.outpoint(ordinary['tx_hash'])['in_chain'])
        receiving = self.bitcoin_wallet('xds-owner-receive')
        target = receiving('getnewaddress', ['', 'bech32'])
        unsigned = self.btc.rpc('createrawtransaction', [[dict(txid=foreign_claim['txid'], vout=0)], {target: '0.00098'}])
        signed = receiving('signrawtransactionwithwallet', [unsigned])
        self.assertTrue(signed['complete'])
        ordinary_id = self.btc.rpc('sendrawtransaction', [signed['hex']])
        self.mine_pending()
        self.assertIsNotNone(self.btc.rpc('gettxout', [ordinary_id, 0]))
        funding = owners['xds-owner'].owner.store.get('terms.xds')['funding_txid']
        claim = owners['foreign-owner'].owner.session.journal.intent(offer['swap_id'], 'xds-claim')['txid']
        self.assert_explorer_transaction(funding, 'swap funding', refund_height=offer['xds']['refund_height'])
        self.assert_explorer_transaction(claim, 'swap spend', funding=funding)
        self.assert_explorer_transaction(ordinary['tx_hash'], 'transfer')

    def test_hardened_lost_native_prepare_reply_reopens_exact_operation(self):
        _, offer, _, _, owners = self.pair('hardened-owner-lost-prepare')
        alice, bob = owners['xds-owner'], owners['foreign-owner']
        self.assertEqual(self.step(alice)['action'], 'wait-peer-acceptance')
        self.assertEqual(self.step(bob)['action'], 'funding-submitted')
        self.mine_pending()
        self.step(bob)
        # Prior test's ordinary payout advanced this shared real chain. Wait
        # for the actual wallet scan before testing a completed preparation
        # reply loss; a stale-wallet refusal is a separate fail-closed gate.
        self.native.x.alice.synced()
        original = self.native_wallets['xds-owner']
        calls, prepared = [], {}
        def lose_once(method, params):
            calls.append(method)
            result = original(method, params)
            if method == 'swap_prepare_funding_once':
                prepared.update(result)
                raise TimeoutError('fixture discarded completed preparation response')
            return result
        alice.owner.wallet = lose_once
        alice.owner.native_funding.wallet = lose_once
        with self.assertRaises(_Unavailable):
            self.step(alice)
        self.assertEqual(calls.count('swap_prepare_funding_once'), 1)
        operation = alice.owner.store.get('funding.operation')
        self.assertEqual(operation['operation_id'], prepared['operation_id'])
        self.assertIsNone(alice.owner.store.get('funding.attempt'))
        alice.close()
        # Kill the actual wallet process after its completed reply was dropped.
        # Keep its wallet file, sidecar and RPC identity: no new wallet/draft or
        # Python object memory can supply the operation after restart.
        native_wallet = self.native.x.alice
        wallet_path, old_pid = native_wallet.path, native_wallet.process.pid
        record = Path(str(wallet_path) + '.swap-funding-v1') / (operation['operation_id'] + '.prepared')
        stored_ciphertext_hash = hashlib.sha256(record.read_bytes()).hexdigest()
        native_wallet.stop(kill=True)
        self.assertIsNotNone(native_wallet.process.poll())
        native_wallet.start()
        native_wallet.synced()
        self.assertEqual(native_wallet.path, wallet_path)
        self.assertNotEqual(native_wallet.process.pid, old_pid)
        self.assertEqual(hashlib.sha256(record.read_bytes()).hexdigest(), stored_ciphertext_hash)
        owners['xds-owner'] = alice = self.reopen('xds-owner')
        def readback(method, params):
            calls.append(method)
            if method == 'swap_prepare_funding_once':
                raise AssertionError('Prepared operation must be fetched without preparation')
            return original(method, params)
        alice.owner.wallet = readback
        alice.owner.native_funding.wallet = readback
        self.assertEqual(self.step(alice)['action'], 'funding-submitted')
        packet = alice.owner.store.get('funding.attempt')
        self.assertEqual(packet['txid'], prepared['tx_hash'])
        self.assertEqual(packet['raw'], prepared['tx_as_hex'])
        self.assertEqual(alice.owner.store.get('funding.operation'), operation)
        self.assertEqual(calls.count('swap_prepare_funding_once'), 1)
        self.assertEqual(calls.count('swap_get_funding_preparation'), 1)
        self.mine_pending()
        self.drive(owners, lambda: self.settled(owners))
        self.assertTrue(alice.owner.session._public_proof())
        self.assertEqual(alice.owner.store.get('scanner.claim')['txid'],
            bob.owner.session.journal.intent(offer['swap_id'], 'xds-claim')['txid'])


def load_tests(loader, tests, pattern):
    # The original three scenarios run unchanged in their original module.
    return unittest.TestSuite(HardenedOwnerRpcIntegration(name) for name in (
        'test_hardened_full_funding_claim_pair_and_ordinary_spends',
        'test_hardened_lost_native_prepare_reply_reopens_exact_operation'))
