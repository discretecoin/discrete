"""Opt-in public fixture on actual owned Agave; synthetic principal only."""
import base64
import hashlib
import os
from pathlib import Path
import unittest

from solders.hash import Hash
from solders.instruction import AccountMeta as Meta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solana_fixture import create_bridge
from solana_fixture.bridge import TOKEN, finalized, wait_for
from solana_fixture.support import private_directory, write_json
from swap_runtime.solana import SolanaAdapter
from swap_runtime.solana_funding import SolanaFundingAdapter


@unittest.skipUnless(os.environ.get('SOLANA_FIXTURE_RPC_INTEGRATION') == '1',
                     'Explicit public fixture and synthetic private ledger required')
class PublicFixtureRpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = private_directory(os.environ['SOLANA_FIXTURE_EVIDENCE'], create=True)
        cls.bridge = create_bridge()
        cls.identity = (str(cls.bridge.owner_key.pubkey()), str(cls.bridge.claim_key.pubkey()), cls.bridge.ready)

    @classmethod
    def tearDownClass(cls):
        cls.bridge.close()

    def balance(self, address):
        return int(self.bridge.rpc('getTokenAccountBalance', [address, {'commitment': 'finalized'}])['value']['amount'])

    def settle(self, refund):
        remote = self.bridge
        secret = os.urandom(32)
        setup = remote.setup(hashlib.sha256(secret).hexdigest(), 220 if refund else 500)
        funding = SolanaFundingAdapter(remote.rpc, setup['terms'])
        keys = dict(owner=remote.owner_key, state=Keypair(), vault=Keypair(), refund=Keypair())
        plan = funding.plan(keys)
        name = 'refund' if refund else 'claim'
        write_json(self.evidence / (name + '-plan.json'), plan)
        raw, txid = funding.prepare(plan, keys)
        write_json(self.evidence / (name + '-funding-wire.json'), dict(raw=raw.hex(), txid=txid))
        funding.send(plan, raw, txid)
        funded = wait_for(lambda: (r if (r := funding.receipt(plan, raw, txid))['status'] == 'confirmed' else None))
        self.assertTrue(funded['publicly_observed'])
        payer = remote.owner_key if refund else remote.claim_key
        adapter = SolanaAdapter(remote.rpc, funding.settlement_terms(plan, str(payer.pubkey())))
        kind = 'foreign-refund' if refund else 'foreign-claim'
        if refund:
            with self.assertRaises(ValueError): adapter.prepare(kind, payer)
            wait_for(lambda: adapter.observe()['refund_eligible'], timeout=240)
        settlement_raw, settlement_id = adapter.prepare(kind, payer, None if refund else secret)
        write_json(self.evidence / (name + '-settlement-wire.json'), dict(raw=settlement_raw.hex(), txid=settlement_id))
        adapter.send(kind, settlement_raw, settlement_id)
        receipt = wait_for(lambda: (r if (r := adapter.receipt(kind, settlement_raw, settlement_id))['status'] == 'confirmed' else None))
        self.assertTrue(receipt['publicly_observed'])
        destination = plan['accounts']['refund' if refund else 'claim']
        self.assertEqual(self.balance(destination), setup['terms']['amount'])
        self.assertEqual(self.balance(plan['accounts']['vault']), 0)
        with self.assertRaises(ValueError): adapter.send(kind, settlement_raw, settlement_id)
        # Actual ordinary SPL transfer proves custody of the payout, using its
        # independent owner key after escrow settlement, not the synthetic minter.
        amount = 100_000
        instruction = Instruction(TOKEN, b'\x0c' + amount.to_bytes(8, 'little') + b'\x06',
            [Meta(Pubkey.from_string(destination), False, True),
             Meta(Pubkey.from_string(setup['terms']['manifest']['profile']['mint']), False, False),
             Meta(Pubkey.from_string(setup['terms']['source']), False, True), Meta(payer.pubkey(), True, False)])
        blockhash = Hash.from_string(remote.rpc('getLatestBlockhash', [{'commitment': 'finalized'}])['value']['blockhash'])
        spending = Transaction([payer], Message([instruction], payer.pubkey()), blockhash)
        spending_id = str(spending.signatures[0])
        self.assertEqual(remote.rpc('sendTransaction', [base64.b64encode(bytes(spending)).decode(),
            {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0}]), spending_id)
        wait_for(lambda: finalized(remote.rpc, spending_id))
        self.assertEqual(self.balance(destination), setup['terms']['amount'] - amount)
        self.assertEqual(self.balance(setup['terms']['source']), setup['source_balance'] - setup['terms']['amount'] + amount)
        write_json(self.evidence / (name + '-public-receipt.json'), dict(status='PASS', fixture=remote.ready,
            setup=setup, funding_receipt=funded, settlement_receipt=receipt, ordinary_spend_txid=spending_id,
            ordinary_spend_amount=amount, owner=str(remote.owner_key.pubkey()), claimant=str(remote.claim_key.pubkey()),
            vault_balance=0, destination_balance=self.balance(destination)))

    def test_01_actual_provisioning_funding_claim_and_owner_spend(self):
        self.settle(False)

    def test_02_reconnect_same_keys_then_natural_refund_and_owner_spend(self):
        self.bridge.close()
        type(self).bridge = create_bridge()
        self.assertEqual((str(self.bridge.owner_key.pubkey()), str(self.bridge.claim_key.pubkey()), self.bridge.ready), self.identity)
        self.settle(True)


if __name__ == '__main__':
    unittest.main()
