"""Opt-in actual XDS/Solana pair with durable funding and external snapshots.

Both chains are real private ledgers. Separate AnchorStore directories expose
their authenticated signed protocol in process; this case does not claim remote
HTTPS failure isolation. The public Solana fixture owns only synthetic assets.
"""
import json
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from swap_runtime.anchor import AnchorStore, AnchorClient
from swap_runtime.anchored_owner import AnchoredOwner
from swap_runtime.owner_protocol import validate_offer
import test_owner_solana_rpc_integration as previous


class HardenedSolanaOwnerRpcIntegration(previous.OwnerSolanaRpcIntegration):
    def setUp(self):
        super().setUp()
        self.anchors, self.parameters = [], {}

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            for anchor in reversed(self.anchors):
                anchor.close()

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
        exchange = path / 'exchange'; exchange.mkdir()
        keys = {role: os.urandom(32) for role in ('xds-owner', 'foreign-owner')}
        owners = {}
        for role, payer, rho in (('xds-owner', self.remote.claim_key, native['rho_a']),
                                  ('foreign-owner', self.remote.owner_key, native['rho_b'])):
            signer = Ed25519PrivateKey.generate()
            anchor_profile = dict(service_id=os.urandom(32).hex(), stream_id=os.urandom(32).hex())
            store = AnchorStore(path / (role + '-external.db'), **anchor_profile,
                writer_public_key=signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), create=True)
            self.anchors.append(store)
            client = AnchorClient(store.handle, **anchor_profile, writer_key=signer)
            credentials = dict(xds_rho=rho.hex(), foreign_key=bytes(payer).hex())
            if role == 'foreign-owner':
                credentials['secret'] = native['secret'].hex()
            options = dict(wallet=self.wallets[role], anchor_client=client)
            outer = AnchoredOwner(path / role, keys[role], self.daemon, self.foreign,
                exchange_dir=exchange, backup_dir=path / (role + '-backups'),
                offer=offer, role=role, credentials=credentials, durable_funding=True, **options)
            self.opened.append(outer)
            self.parameters[role] = dict(directory=path / role, key=keys[role], **options)
            owners[role] = outer
            self.assertIsNone(outer.owner.store.get('funding.attempt'))
            self.assertIsNone(outer.owner.store.get('solana.accounts'))
        self.assertNotIn('secret', owners['xds-owner'].owner.credentials)
        return path, offer, native, keys, owners

    def step(self, outer):
        result = outer.step()
        self.assertNotIn('"secret"', json.dumps(result))
        self.assertEqual(outer.head, outer.client.read())
        value = dict(role=outer.owner.role, action=result['action'])
        self.actions.append(value)
        print('anchored-owner-step=' + json.dumps(value), flush=True)
        return result

    def settled(self, owners):
        return all((outer.owner.store.get('settlement.status') or {}).get('final') is True
            and outer.owner.store.get('settlement.status')['status'] == 'confirmed' for outer in owners.values())

    def reopen(self, role):
        outer = AnchoredOwner(daemon=self.daemon, foreign=self.foreign, **self.parameters[role])
        self.opened.append(outer)
        return outer

    def test_hardened_solana_full_funding_claim_reopen_and_ordinary_spends(self):
        x = self.native.x
        x.alice.synced(); x.bob.synced()
        before = x.bob.balance()
        path, offer, native, _, owners = self.pair('hardened-owner-solana-success')
        self.drive(owners, lambda: self.settled(owners))
        alice, bob = owners['xds-owner'].owner, owners['foreign-owner'].owner
        self.assertTrue(alice.durable_funding)
        self.assertIsNotNone(alice.store.get('funding.operation'))
        self.assertEqual(alice.store.get('funding.attempt')['raw'], alice.store.get('terms.xds')['funding_wire'])
        self.assertIsNotNone(bob.store.get('solana.accounts'))
        self.assertIsNotNone(bob.store.get('funding.acquisition'))
        proof = alice.store.get('scanner.claim')
        native_claim = bob.session.journal.intent(offer['swap_id'], 'xds-claim')
        foreign_claim = alice.session.journal.intent(offer['swap_id'], 'foreign-claim')
        self.assertEqual(proof['txid'], native_claim['txid'])
        self.assertTrue(proof['acquisition']['full_wire_fetched'])
        self.assertTrue(alice.session._public_proof())
        self.assertTrue(bob.session.journal.exposed(offer['swap_id']))
        self.assertNotIn('secret', alice.credentials)
        self.assert_mailbox_private(path, native['secret'])
        self.assertTrue(any((path / 'xds-owner-backups').glob('*.backup')))
        self.assertTrue(any((path / 'foreign-owner-backups').glob('*.backup')))
        native_receipt = bob.session.reconcile('xds-claim')
        solana_receipt = alice.session.reconcile('foreign-claim')
        self.assertTrue(native_receipt['final']); self.assertTrue(solana_receipt['final'])
        heads = {}
        for role in tuple(owners):
            heads[role] = owners[role].head
            owners[role].close()
            owners[role] = self.reopen(role)
            self.assertEqual(owners[role].head, heads[role])
            self.assertFalse(owners[role].owner.store.recovery_required())
        sends = len(self.foreign_sends)
        for outer in owners.values():
            self.assertEqual(self.step(outer)['action'], 'claim-observed')
        self.assertEqual(len(self.foreign_sends), sends)
        alice, bob = owners['xds-owner'].owner, owners['foreign-owner'].owner
        self.assertTrue(bob.session.journal.exposed(offer['swap_id']))
        terms = alice.store.get('terms.foreign')
        self.assertEqual(self.balance(terms['vault']), 0)
        self.assertGreaterEqual(self.balance(terms['claim']), offer['foreign']['amount'])
        ordinary_solana = self.ordinary_spend(terms['claim'], terms['source'], self.remote.claim_key, 100000)
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 1000, 'Anchored Solana native payout scanned', 60)
        ordinary = x.bob.call('transfer', dict(destinations=[dict(address=native['a']['address'], amount=900)],
            fee=1, unlock_height=0, payment_id='', extra=''))
        self.mine_pending()
        self.native.lab.wait_for(lambda: x.bob.balance() == before + 99, 'Anchored ordinary native change scanned', 60)
        self.assertTrue(x.n.outpoint(ordinary['tx_hash'])['in_chain'])
        self.save('owner-hardened-solana-success', dict(status='PASS', xds=native_receipt, solana=solana_receipt,
            ordinary_solana=ordinary_solana, ordinary_xds_txid=ordinary['tx_hash'], native_payout_atoms=1000,
            foreign_claim_txid=foreign_claim['txid'], automatic_public_scanner=True, unchanged_retry_sends=True,
            durable_native_preparation=True, authenticated_anchor_heads=heads, reopened_both_owners=True,
            anchor_scope='Independent AnchorStore directories with authenticated protocol in process; no HTTPS fault simulation'))


def load_tests(loader, tests, pattern):
    # Existing two scenarios remain unchanged and are selected by their module.
    return unittest.TestSuite([HardenedSolanaOwnerRpcIntegration(
        'test_hardened_solana_full_funding_claim_reopen_and_ordinary_spends')])


if __name__ == '__main__':
    unittest.main()
