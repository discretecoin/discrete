"""Local owner-funding tests: real ELF/System/SPL/ATA execution in LiteSVM.

RPC contexts/profile metadata are controlled fixtures, not network finality.
The separate signer child receives only its owner's key and an ordinary SPL
message; no key is printed or written into test artifacts.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

from solders.account import Account
from solders.hash import Hash
from solders.instruction import Instruction, AccountMeta as Meta
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata

from swap_runtime.common import canonical
from swap_runtime.solana import SolanaAdapter, profile
from swap_runtime.solana_funding import SolanaFundingAdapter, ASSOCIATED, SYSTEM, TOKEN


BUILD = Path(os.environ.get('XDS_SOLANA_BUILD', Path(__file__).parent / 'fixtures/solana-v06'))


def account(owner, data, executable=False, lamports=1_000_000):
    return {'owner': str(owner), 'data': [base64.b64encode(data).decode(), 'base64'],
            'executable': executable, 'lamports': lamports}


class Fixture:
    def __init__(self):
        self.manifest = json.loads((BUILD / 'build-manifest.json').read_text())
        elf = (BUILD / 'solana_escrow.so').read_bytes()
        assert hashlib.sha256(elf).hexdigest() == self.manifest['artifact']['sha256']
        self.program, self.mint = [Pubkey.from_string(self.manifest['profile'][key]) for key in ('program_id', 'mint')]
        self.vm = LiteSVM(); self.vm.add_program_from_file(self.program, BUILD / 'solana_escrow.so')
        self.vm.warp_to_slot(100)
        self.keys = {name: Keypair() for name in ('owner', 'state', 'vault', 'refund')}
        self.owner, self.claimant, self.source = self.keys['owner'], Keypair(), Keypair().pubkey()
        self.vm.airdrop(self.owner.pubkey(), 100_000_000); self.vm.airdrop(self.claimant.pubkey(), 1_000_000)
        mint = bytearray(82); mint[:4] = struct.pack('<I', 1); mint[4:36] = bytes(self.owner.pubkey())
        mint[36:44] = struct.pack('<Q', 10_000_000); mint[44:46] = b'\x06\x01'
        mint[46:50] = struct.pack('<I', 1); mint[50:82] = bytes(self.owner.pubkey())
        self.vm.set_account(self.mint, Account(self.vm.minimum_balance_for_rent_exemption(82), bytes(mint), TOKEN))
        self.set_token(self.source, self.owner.pubkey(), 10_000_000)
        self.secret = os.urandom(32)
        self.terms = dict(manifest=self.manifest, owner=str(self.owner.pubkey()), source=str(self.source),
            claim_owner=str(self.claimant.pubkey()), claim_payer=str(self.claimant.pubkey()),
            refund_owner=str(self.owner.pubkey()), refund_payer=str(self.owner.pubkey()), amount=1_234_567,
            hashlock=hashlib.sha256(self.secret).hexdigest(), deadline_slot=1000, min_context_slot=0,
            max_finality_lag_slots=128, min_funding_window_slots=50, max_funding_fee_lamports=25000,
            max_rent_lamports=20_000_000, owner_reserve_lamports=10000)
        self.pd = Keypair().pubkey()
        self.metadata = {
            str(self.program): account(profile.LOADER, struct.pack('<I', 2) + bytes(self.pd), True),
            str(self.pd): account(profile.LOADER, struct.pack('<IQB', 3, 1, 0) + bytes(32) + elf),
        }
        self.calls, self.sent, self.history, self.transactions = [], [], {}, {}
        self.fee_per_signature, self.context_override = 5000, None
        self.genesis = self.manifest['profile']['genesis_hash']
        self.adapter = SolanaFundingAdapter(self.rpc, self.terms)

    @property
    def slot(self): return self.vm.get_clock().slot

    def set_token(self, address, owner, amount=0, frozen=False):
        data = bytearray(165); data[:32] = bytes(self.mint); data[32:64] = bytes(owner)
        data[64:72] = struct.pack('<Q', amount); data[108] = 2 if frozen else 1
        self.vm.set_account(address, Account(self.vm.minimum_balance_for_rent_exemption(165), bytes(data), TOKEN))

    def result(self, value):
        return {'context': {'slot': self.slot if self.context_override is None else self.context_override}, 'value': value}

    def get(self, address):
        if address in self.metadata: return self.metadata[address]
        value = self.vm.get_account(Pubkey.from_string(address))
        return None if value is None else account(value.owner, value.data, value.executable, value.lamports)

    def balance(self, address):
        return struct.unpack_from('<Q', self.vm.get_account(Pubkey.from_string(str(address))).data, 64)[0]

    def rpc(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if method == 'getGenesisHash': return self.genesis
        if method == 'getAccountInfo': return self.result(self.get(params[0]))
        if method == 'getMultipleAccounts': return self.result([self.get(k) for k in params[0]])
        if method == 'getSlot': return self.slot
        if method == 'getMinimumBalanceForRentExemption': return self.vm.minimum_balance_for_rent_exemption(params[0])
        if method == 'getLatestBlockhash': return self.result({'blockhash': str(self.vm.latest_blockhash()), 'lastValidBlockHeight': self.slot + 150})
        if method == 'getFeeForMessage':
            message = Message.from_bytes(base64.b64decode(params[0]))
            return self.result(message.header.num_required_signatures * self.fee_per_signature)
        if method == 'isBlockhashValid': return self.result(params[0] == str(self.vm.latest_blockhash()))
        if method == 'getSignatureStatuses': return self.result([self.history.get(params[0][0])])
        if method == 'getTransaction': return self.transactions.get(params[0])
        if method == 'sendTransaction':
            raw = base64.b64decode(params[0]); tx = Transaction.from_bytes(raw); txid = str(tx.signatures[0])
            pre = [self.vm.get_balance(k) or 0 for k in tx.message.account_keys]
            result = self.vm.send_transaction(tx)
            post = [self.vm.get_balance(k) or 0 for k in tx.message.account_keys]
            err = {'vm_error': str(result.err())} if isinstance(result, FailedTransactionMetadata) else None
            self.sent.append((raw, result))
            self.history[txid] = {'slot': self.slot, 'err': err, 'confirmationStatus': 'finalized', 'confirmations': None}
            self.transactions[txid] = {'slot': self.slot, 'transaction': [params[0], 'base64'],
                'meta': {'err': err, 'fee': tx.message.header.num_required_signatures * 5000, 'preBalances': pre, 'postBalances': post}}
            return txid
        raise AssertionError('Unexpected test RPC: ' + method)

    def prepare(self):
        plan = self.adapter.plan(self.keys); raw, txid = self.adapter.prepare(plan, self.keys)
        return plan, raw, txid

    def funded(self):
        plan, raw, txid = self.prepare(); self.adapter.send(plan, raw, txid)
        if isinstance(self.sent[-1][1], FailedTransactionMetadata): raise AssertionError(str(self.sent[-1][1]))
        return plan, raw, txid

    def expire(self):
        self.vm.expire_blockhash(); self.vm.warp_to_slot(self.slot + 1)

    def mutate_token(self, address, offset, data):
        old = self.vm.get_account(address); changed = bytearray(old.data); changed[offset:offset + len(data)] = data
        self.vm.set_account(address, Account(old.lamports, bytes(changed), old.owner, old.executable, old.rent_epoch))


def owner_signer_child():
    request = json.loads(sys.stdin.buffer.read())
    key = Keypair.from_bytes(bytes(request['key']))
    message = Message.from_bytes(base64.b64decode(request['message']))
    tx = Transaction([key], message, message.recent_blockhash)
    print(base64.b64encode(bytes(tx)).decode())


class SolanaFundingTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()

    def test_plan_is_readonly_and_one_atomic_bounded_signed_template(self):
        f = self.f; before = f.vm.get_balance(f.owner.pubkey()); plan, raw, txid = f.prepare()
        self.assertEqual(len(raw), 1061); tx = Transaction.from_bytes(raw)
        self.assertEqual(len(tx.signatures), 4); self.assertEqual(len(tx.message.instructions), 7)
        self.assertEqual(f.adapter.validate(plan, raw, txid)['plan_id'], plan['plan_id'])
        self.assertEqual(f.vm.get_balance(f.owner.pubkey()), before); self.assertEqual(f.balance(f.source), 10_000_000)
        self.assertFalse(f.sent); self.assertNotIn(f.secret, raw)
        for name in ('state', 'vault', 'refund'): self.assertIsNone(f.vm.get_account(Pubkey.from_string(plan['accounts'][name])))
        self.assertEqual(f.adapter.preparation_evidence(plan, raw, txid)['raw_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertFalse(any(method == 'simulateTransaction' for method, _ in f.calls))

    def test_real_atomic_funding_and_exact_fee_rent_receipt(self):
        f = self.f; plan, raw, txid = f.funded(); receipt = f.adapter.receipt(plan, raw, txid)
        self.assertEqual(receipt['status'], 'confirmed', receipt); self.assertTrue(receipt['final'])
        self.assertEqual(receipt['fee_lamports'], 20000)
        self.assertEqual(receipt['owner_debit_lamports'], sum(plan['rent'].values()) + 20000)
        self.assertEqual(f.balance(plan['accounts']['vault']), f.terms['amount'])
        self.assertEqual(f.balance(f.source), 10_000_000 - f.terms['amount'])
        self.assertEqual(f.get(plan['accounts']['claim'])['owner'], str(TOKEN))
        claim = f.vm.get_account(Pubkey.from_string(plan['accounts']['claim'])).data
        refund = f.vm.get_account(Pubkey.from_string(plan['accounts']['refund'])).data
        self.assertEqual(claim[32:64], bytes(f.claimant.pubkey())); self.assertEqual(refund[32:64], bytes(f.owner.pubkey()))
        resolved = f.adapter.resolve(plan, raw, txid)
        self.assertEqual(resolved['funded_terms']['claim']['payer'], str(f.claimant.pubkey()))
        self.assertEqual(resolved['funded_terms']['refund']['payer'], str(f.owner.pubkey()))

    def test_existing_correct_claim_ata_is_preserved_by_idempotent_creation(self):
        f = self.f; f.set_token(f.adapter.claim, f.claimant.pubkey(), 55)
        plan, raw, txid = f.funded(); receipt = f.adapter.receipt(plan, raw, txid)
        self.assertEqual(receipt['status'], 'confirmed', receipt); self.assertEqual(f.balance(f.adapter.claim), 55)
        self.assertEqual(receipt['owner_debit_lamports'], sum(plan['rent'].values()) - plan['rent']['claim_max'] + 20000)

    def test_atomic_failure_rolls_back_all_created_accounts_and_principal(self):
        f = self.f; plan, raw, txid = f.prepare(); before = f.vm.get_balance(f.owner.pubkey())
        f.vm.warp_to_slot(f.terms['deadline_slot'])
        f.rpc('sendTransaction', [base64.b64encode(raw).decode(), {}])
        self.assertIsInstance(f.sent[-1][1], FailedTransactionMetadata)
        for name in ('state', 'vault', 'refund', 'claim'): self.assertIsNone(f.vm.get_account(Pubkey.from_string(plan['accounts'][name])))
        self.assertEqual(f.balance(f.source), 10_000_000)
        self.assertEqual(before - f.vm.get_balance(f.owner.pubkey()), 20000)
        self.assertEqual(f.adapter.receipt(plan, raw, txid)['status'], 'failed')

    def test_signed_wire_extra_instruction_changed_principal_and_identity_rejected(self):
        f = self.f; plan, raw, txid = f.prepare(); tx = Transaction.from_bytes(raw)
        with self.assertRaises(ValueError): f.adapter.validate(plan, raw + b'\0', txid)
        changed = copy.deepcopy(plan); changed['accounts']['refund'] = str(Keypair().pubkey())
        with self.assertRaises(ValueError): f.adapter.prepare(changed, f.keys)
        changed = copy.deepcopy(plan); changed['terms']['claim_owner'] = str(f.owner.pubkey())
        with self.assertRaises(ValueError): f.adapter.validate(changed, raw, txid)
        instructions = f.adapter._instructions(plan)
        for bad in (instructions + [instructions[-1]], instructions[:-1] + [Instruction(f.program, b'\0' + bytes(48), instructions[-1].accounts)]):
            candidate = Transaction(list(f.keys.values()), Message(bad, f.owner.pubkey()), tx.message.recent_blockhash)
            with self.assertRaises(ValueError): f.adapter.validate(plan, bytes(candidate), str(candidate.signatures[0]))
        wrong = dict(f.keys, owner=f.claimant)
        with self.assertRaises(ValueError): f.adapter.prepare(plan, wrong)

    def test_fee_rent_reserve_and_owner_balance_caps_refuse_before_sign_or_send(self):
        for field, value in (('max_funding_fee_lamports', 19999), ('max_rent_lamports', 1), ('owner_reserve_lamports', 9999)):
            f = Fixture(); terms = dict(f.terms, **{field: value}); adapter = SolanaFundingAdapter(f.rpc, terms)
            with self.subTest(field=field), self.assertRaises(ValueError): adapter.plan(f.keys)
            self.assertFalse(f.sent)
        f = self.f; old = f.vm.get_account(f.owner.pubkey()); f.vm.set_account(f.owner.pubkey(), Account(10000, b'', old.owner))
        with self.assertRaises(ValueError): f.adapter.plan(f.keys)

    def test_source_owner_frozen_delegate_and_claim_owner_mismatch_fail_closed(self):
        for offset, value in ((32, bytes(Keypair().pubkey())), (108, b'\2'), (72, b'\1\0\0\0')):
            f = Fixture(); f.mutate_token(f.source, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): f.adapter.plan(f.keys)
            self.assertFalse(f.sent)
        f = self.f; f.set_token(f.adapter.claim, f.owner.pubkey())
        with self.assertRaises(ValueError): f.adapter.plan(f.keys)

    def test_lost_ack_resolves_exact_funding_without_duplicate_principal(self):
        f = self.f; plan, raw, txid = f.prepare()
        def lost(method, params):
            answer = f.rpc(method, params)
            if method == 'sendTransaction': raise ConnectionError('synthetic lost acknowledgment')
            return answer
        adapter = SolanaFundingAdapter(lost, f.terms)
        with self.assertRaises(ValueError): adapter.send(plan, raw, txid)
        reopened = SolanaFundingAdapter(f.rpc, f.terms)
        self.assertEqual(reopened.resolve(plan, raw, txid)['receipt']['status'], 'confirmed')
        with self.assertRaises(ValueError): reopened.send(plan, raw, txid)
        with self.assertRaises(ValueError): reopened.prepare(plan, f.keys)
        self.assertEqual(len(f.sent), 1); self.assertEqual(f.balance(f.source), 10_000_000 - f.terms['amount'])

    def test_expired_funding_renews_same_identity_after_adapter_restart(self):
        f = self.f; plan, old_raw, old_id = f.prepare(); proof = f.adapter.preparation_evidence(plan, old_raw, old_id)
        f.expire()
        self.assertIsInstance(f.vm.send_transaction(Transaction.from_bytes(old_raw)), FailedTransactionMetadata)
        resumed = SolanaFundingAdapter(f.rpc, f.terms)
        new_raw, new_id = resumed.prepare(plan, f.keys)
        evidence = resumed.renew(plan, old_raw, old_id, new_raw, new_id, proof)
        self.assertEqual(evidence['status'], 'renewable'); self.assertGreater(evidence['expiry_context_slot'], proof['context_slot'])
        self.assertEqual(evidence['old_raw_sha256'], hashlib.sha256(old_raw).hexdigest())
        resumed.send(plan, new_raw, new_id)
        self.assertEqual(resumed.receipt(plan, new_raw, new_id)['status'], 'confirmed')
        self.assertEqual(f.balance(plan['accounts']['vault']), f.terms['amount'])
        self.assertEqual(f.balance(f.source), 10_000_000 - f.terms['amount'])

    def test_renewal_refuses_live_hash_missing_provenance_and_stale_context(self):
        f = self.f; plan, old_raw, old_id = f.prepare(); proof = f.adapter.preparation_evidence(plan, old_raw, old_id)
        f.expire(); new_raw, new_id = f.adapter.prepare(plan, f.keys)
        for changed in (None, dict(proof, context_slot=f.slot), dict(proof, txid=new_id)):
            with self.subTest(proof=changed is None), self.assertRaises(ValueError):
                f.adapter.renew(plan, old_raw, old_id, new_raw, new_id, changed)
        original = f.adapter._rpc
        def valid_old(method, params):
            return f.result(True) if method == 'isBlockhashValid' and params[0] == proof['recent_blockhash'] else original(method, params)
        f.adapter._rpc = valid_old
        with self.assertRaises(ValueError): f.adapter.renew(plan, old_raw, old_id, new_raw, new_id, proof)
        f.adapter._rpc = original; f.context_override = proof['context_slot']
        with self.assertRaises(ValueError): f.adapter.renew(plan, old_raw, old_id, new_raw, new_id, proof)
        self.assertFalse(f.sent)

    def test_renewal_refuses_partial_identity_or_ambiguous_previous_execution(self):
        f = self.f; plan, old_raw, old_id = f.prepare(); proof = f.adapter.preparation_evidence(plan, old_raw, old_id)
        f.expire(); new_raw, new_id = f.adapter.prepare(plan, f.keys)
        for history in ({'slot': f.slot, 'err': None, 'confirmationStatus': 'processed'},
                        {'slot': f.slot, 'err': {'test': 'error'}, 'confirmationStatus': 'confirmed'}):
            f.history[old_id] = history
            with self.assertRaises(ValueError): f.adapter.renew(plan, old_raw, old_id, new_raw, new_id, proof)
        f.history.clear(); f.set_token(f.keys['vault'].pubkey(), Pubkey.from_string(plan['accounts']['authority']))
        self.assertEqual(f.adapter.observe(plan)['status'], 'conflict')
        with self.assertRaises(ValueError): f.adapter.renew(plan, old_raw, old_id, new_raw, new_id, proof)

    def test_full_receipt_conflict_pruned_history_and_wrong_actual_debit(self):
        f = self.f; plan, raw, txid = f.funded(); saved = copy.deepcopy(f.transactions[txid])
        f.transactions[txid]['transaction'][0] = base64.b64encode(raw + b'\0').decode()
        self.assertEqual(f.adapter.receipt(plan, raw, txid)['status'], 'conflict')
        f.transactions[txid] = copy.deepcopy(saved); f.transactions[txid]['meta']['fee'] = 999999
        self.assertEqual(f.adapter.receipt(plan, raw, txid)['status'], 'unknown')
        f.transactions.clear(); f.history.clear(); result = f.adapter.resolve(plan, raw, txid)
        self.assertEqual(result['status'], 'funded'); self.assertEqual(result['receipt']['status'], 'unknown')
        with self.assertRaises(ValueError): f.adapter.send(plan, raw, txid)

    def _ordinary_spend(self, f, source, destination, owner, success=True):
        instruction = Instruction(TOKEN, b'\x0c' + struct.pack('<Q', f.terms['amount']) + b'\x06',
            [Meta(Pubkey.from_string(source), False, True), Meta(f.mint, False, False),
             Meta(Pubkey.from_string(destination), False, True), Meta(owner.pubkey(), True, False)])
        message = Message.new_with_blockhash([instruction], owner.pubkey(), f.vm.latest_blockhash())
        request = {'key': list(bytes(owner)), 'message': base64.b64encode(bytes(message)).decode()}
        env = dict(os.environ); env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1]) + os.pathsep + env.get('PYTHONPATH', '')
        child = subprocess.run([sys.executable, '-B', __file__, '--owner-signer'], input=json.dumps(request).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        raw = base64.b64decode(child.stdout.strip(), validate=True); tx = Transaction.from_bytes(raw)
        tx.verify_and_hash_message(); self.assertEqual(len(tx.signatures), 1)
        result = f.vm.send_transaction(tx)
        if success: self.assertNotIsInstance(result, FailedTransactionMetadata, str(result))
        else: self.assertIsInstance(result, FailedTransactionMetadata)

    def test_independent_claim_owner_signs_following_ordinary_spl_spend_in_child(self):
        f = self.f; plan, raw, txid = f.funded()
        claim_terms = f.adapter.settlement_terms(plan, str(f.claimant.pubkey())); adapter = SolanaAdapter(f.rpc, claim_terms)
        with self.assertRaises(ValueError): adapter.prepare('foreign-claim', f.owner, f.secret)
        claim_raw, claim_id = adapter.prepare('foreign-claim', f.claimant, f.secret); adapter.send('foreign-claim', claim_raw, claim_id)
        self.assertEqual(adapter.receipt('foreign-claim', claim_raw, claim_id)['status'], 'confirmed')
        self._ordinary_spend(f, plan['accounts']['claim'], plan['accounts']['refund'], f.owner, success=False)
        self.assertEqual(f.balance(plan['accounts']['claim']), f.terms['amount'])
        self._ordinary_spend(f, plan['accounts']['claim'], plan['accounts']['refund'], f.claimant)
        self.assertEqual(f.balance(plan['accounts']['claim']), 0); self.assertEqual(f.balance(plan['accounts']['refund']), f.terms['amount'])
        self.assertEqual(f.adapter.receipt(plan, raw, txid)['status'], 'confirmed')
        self.assertEqual(f.adapter.observe(plan)['status'], 'consumed')
        with self.assertRaises(ValueError): f.adapter.prepare(plan, f.keys)

    def test_independent_refund_owner_signs_following_ordinary_spl_spend_in_child(self):
        f = self.f; plan, raw, txid = f.funded(); f.vm.warp_to_slot(f.terms['deadline_slot']); f.expire()
        adapter = SolanaAdapter(f.rpc, f.adapter.settlement_terms(plan, str(f.owner.pubkey())))
        with self.assertRaises(ValueError): adapter.prepare('foreign-refund', f.claimant)
        refund_raw, refund_id = adapter.prepare('foreign-refund', f.owner); adapter.send('foreign-refund', refund_raw, refund_id)
        self.assertEqual(adapter.receipt('foreign-refund', refund_raw, refund_id)['status'], 'confirmed')
        self._ordinary_spend(f, plan['accounts']['refund'], str(f.source), f.claimant, success=False)
        self.assertEqual(f.balance(plan['accounts']['refund']), f.terms['amount'])
        self._ordinary_spend(f, plan['accounts']['refund'], str(f.source), f.owner)
        self.assertEqual(f.balance(plan['accounts']['refund']), 0); self.assertEqual(f.balance(f.source), 10_000_000)
        self.assertEqual(f.adapter.observe(plan)['status'], 'consumed')
        with self.assertRaises(ValueError): f.adapter.prepare(plan, f.keys)


if __name__ == '__main__':
    if sys.argv[1:] == ['--owner-signer']: owner_signer_child()
    else: unittest.main(verbosity=2)
