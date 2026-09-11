"""Offline signed-wire and RPC-evidence tests; no network or real funds."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import unittest

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from swap_runtime.solana import SolanaAdapter, profile


def account(owner, data, executable=False):
    return {'owner': str(owner), 'data': [base64.b64encode(data).decode(), 'base64'],
            'executable': executable, 'lamports': 1_000_000}


class Fixture:
    def __init__(self):
        self.payer = Keypair()
        self.program = Keypair().pubkey()
        self.pd = Keypair().pubkey()
        self.genesis = str(Hash.new_unique())
        self.secret = bytes([81]) * 32
        self.slot, self.processed = 190, 200
        self.blockhash = Hash.new_unique()
        self.valid = {str(self.blockhash): True}
        self.history, self.transaction = None, None
        self.calls, self.sent = [], []
        self.balance = 1_000_000
        self.fee = 5000
        self.code = b'\x7fELF' + bytes(60)
        manifest = {'profile': profile.make_profile('devnet-usdc', str(self.program), self.genesis),
                    'artifact': {'bytes': len(self.code), 'sha256': hashlib.sha256(self.code).hexdigest()}}
        names = ['state', 'vault', 'claim', 'refund', 'source', 'depositor']
        terms = {name: str(Keypair().pubkey()) for name in names}
        terms['mint'] = manifest['profile']['mint']
        authority, bump = Pubkey.find_program_address([b'xds-swap-v1', bytes(Pubkey.from_string(terms['state']))], self.program)
        terms.update(authority=str(authority), manifest=manifest, payer=str(self.payer.pubkey()), amount=1_234_567,
                     hashlock=hashlib.sha256(self.secret).hexdigest(), deadline_slot=220,
                     min_context_slot=100, max_finality_lag_slots=32)
        self.terms = terms
        mint = bytearray(82); mint[44:46] = b'\x06\x01'
        self.accounts = {
            str(self.payer.pubkey()): account('11111111111111111111111111111111', b''),
            str(self.program): account(profile.LOADER, struct.pack('<I', 2) + bytes(self.pd), True),
            str(self.pd): account(profile.LOADER, struct.pack('<IQB', 3, 10, 0) + bytes(32) + self.code + bytes(16)),
            terms['mint']: account(profile.TOKEN, bytes(mint)),
        }
        state = (b'XDSV0001' + bytes([1, bump]) + bytes(6) + struct.pack('<QQ', terms['amount'], terms['deadline_slot'])
                 + bytes.fromhex(terms['hashlock']) + b''.join(bytes(Pubkey.from_string(terms[k])) for k in ('vault', 'mint', 'claim', 'refund')))
        self.accounts[terms['state']] = account(self.program, state)
        for name in ('vault', 'claim', 'refund'):
            token = bytearray(165); token[:32] = bytes(Pubkey.from_string(terms['mint']))
            token[32:64] = bytes(authority if name == 'vault' else Keypair().pubkey())
            token[64:72] = struct.pack('<Q', terms['amount'] if name == 'vault' else 0)
            token[108] = 1
            self.accounts[terms[name]] = account(profile.TOKEN, bytes(token))
        self.adapter = SolanaAdapter(self.rpc, terms)

    def change(self, name, offset, value):
        a = self.accounts[self.terms[name]]
        data = bytearray(base64.b64decode(a['data'][0])); data[offset:offset+len(value)] = value
        a['data'][0] = base64.b64encode(data).decode()

    def result(self, value):
        return {'context': {'slot': self.slot}, 'value': value}

    def rpc(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if method == 'getGenesisHash': return self.genesis
        if method == 'getAccountInfo':
            value = self.accounts.get(params[0])
            if value is not None and params[0] == self.terms['payer']:
                value = dict(value, lamports=self.balance)
            return self.result(value)
        if method == 'getMultipleAccounts': return self.result([self.accounts.get(key) for key in params[0]])
        if method == 'getSlot': return self.processed
        if method == 'getBalance': return self.result(self.balance)
        if method == 'getFeeForMessage': return self.result(self.fee)
        if method == 'getLatestBlockhash':
            return self.result({'blockhash': str(self.blockhash), 'lastValidBlockHeight': 400})
        if method == 'getSignatureStatuses': return self.result([self.history])
        if method == 'getTransaction': return self.transaction
        if method == 'isBlockhashValid': return self.result(self.valid.get(params[0], False))
        if method == 'sendTransaction':
            self.sent.append(params)
            return str(Transaction.from_bytes(base64.b64decode(params[0])).signatures[0])
        raise AssertionError('Unexpected RPC method: ' + method)

    def prepare(self, kind='foreign-claim'):
        return self.adapter.prepare(kind, self.payer, self.secret if kind == 'foreign-claim' else None)

    def receipt(self, raw, txid, *, failed=False, wrong_bytes=False):
        self.history = {'slot': 180, 'err': {'InstructionError': [0, 'Custom']} if failed else None,
                        'confirmationStatus': 'finalized', 'confirmations': None}
        self.transaction = {'slot': 180, 'transaction': [base64.b64encode(raw + b'\0' if wrong_bytes else raw).decode(), 'base64'],
                            'meta': {'err': self.history['err']}}
        if not failed:
            self.change('state', 8, b'\2')
            self.change('vault', 64, bytes(8))


class SolanaAdapterTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()

    def test_prepare_validate_exact_bytes_and_fee_query_contains_dummy_only(self):
        f = self.f; raw, txid = f.prepare()
        checked = f.adapter.validate('foreign-claim', raw, txid)
        self.assertEqual(checked['secret'], f.secret.hex())
        self.assertEqual(checked['payer'], str(f.payer.pubkey()))
        self.assertEqual(len(checked['semantic_hash']), 64)
        for method, params in f.calls:
            self.assertNotIn(method, ('simulateTransaction', 'sendTransaction'))
            if method == 'getFeeForMessage':
                data = base64.b64decode(params[0])
                self.assertNotIn(f.secret, data)
                self.assertEqual(bytes(Message.from_bytes(data).instructions[0].data), b'\1' + bytes(32))

    def test_wire_mutation_extra_instruction_wrong_signer_and_wrong_secret_rejected(self):
        f = self.f; raw, txid = f.prepare(); original = Transaction.from_bytes(raw)
        with self.assertRaises(Exception): f.adapter.validate('foreign-claim', raw + b'\0', txid)
        with self.assertRaises(Exception): f.adapter.validate('foreign-claim', raw, str(Keypair().sign_message(b'bad')))
        cases = [([f.adapter._ix('foreign-claim', f.secret)] * 2, f.payer),
                 ([f.adapter._ix('foreign-claim', bytes(32))], f.payer),
                 ([f.adapter._ix('foreign-claim', f.secret)], Keypair())]
        for ixs, payer in cases:
            tx = Transaction([payer], Message(ixs, payer.pubkey()), original.message.recent_blockhash)
            with self.assertRaises(Exception):
                f.adapter.validate('foreign-claim', bytes(tx), str(tx.signatures[0]))
        ix = f.adapter._ix('foreign-claim', f.secret)
        metas = list(ix.accounts); metas[3] = AccountMeta(Keypair().pubkey(), False, True)
        tx = Transaction([f.payer], Message([Instruction(f.program, ix.data, metas)], f.payer.pubkey()), f.blockhash)
        with self.assertRaises(ValueError): f.adapter.validate('foreign-claim', bytes(tx), str(tx.signatures[0]))

    def test_zero_preimage_is_never_used_as_dummy_fee_query(self):
        f = self.f; f.secret = bytes(32)
        f.terms['hashlock'] = hashlib.sha256(f.secret).hexdigest()
        f.change('state', 32, bytes.fromhex(f.terms['hashlock']))
        f.adapter = SolanaAdapter(f.rpc, f.terms)
        f.prepare()
        for method, params in f.calls:
            if method == 'getFeeForMessage':
                message = Message.from_bytes(base64.b64decode(params[0]))
                self.assertNotEqual(bytes(message.instructions[0].data)[1:], f.secret)

    def test_fees_lag_frozen_and_refund_exact_finalized_slot(self):
        f = self.f
        self.assertTrue(f.adapter.observe()['fees_ready'])
        f.balance = 4999
        self.assertFalse(f.adapter.observe()['fees_ready'])
        with self.assertRaises(ValueError): f.prepare()
        f.balance = 5000
        with self.assertRaises(ValueError): f.prepare('foreign-refund')
        f.slot, f.processed = 220, 230
        raw, txid = f.prepare('foreign-refund')
        self.assertNotIn('secret', f.adapter.validate('foreign-refund', raw, txid))
        f.change('claim', 108, b'\2')
        self.assertFalse(f.adapter.observe()['claim_ready'])
        self.assertTrue(f.adapter.observe()['refund_eligible'])
        f.processed = 260
        self.assertEqual(f.adapter.observe()['status'], 'unknown')

    def test_chain_profile_pda_escrow_terms_and_vault_mismatch_rejected(self):
        for key, replacement in (('authority', str(Keypair().pubkey())), ('mint', str(Keypair().pubkey()))):
            terms = copy.deepcopy(self.f.terms); terms[key] = replacement
            with self.assertRaises(ValueError): SolanaAdapter(self.f.rpc, terms)
        self.f.genesis = str(Hash.new_unique())
        self.assertEqual(self.f.adapter.observe()['status'], 'unknown')
        self.f = Fixture(); self.f.change('state', 16, struct.pack('<Q', 1))
        self.assertEqual(self.f.adapter.observe()['status'], 'unknown')
        self.f = Fixture(); self.f.change('vault', 72, b'\1\0\0\0')
        self.assertEqual(self.f.adapter.observe()['status'], 'unknown')

    def test_non_system_executable_data_bearing_or_missing_payer_cannot_pay(self):
        for invalid in (account(profile.TOKEN, b''), account('11111111111111111111111111111111', b'', True),
                        account('11111111111111111111111111111111', bytes(80)), None):
            f = Fixture()
            f.accounts[f.terms['payer']] = invalid
            observed = f.adapter.observe()
            self.assertEqual(observed['status'], 'unspent')
            self.assertFalse(observed['fees_ready'])
            self.assertFalse(observed['payer_usable'])
            with self.assertRaises(ValueError): f.prepare()
            self.assertFalse(f.sent)

    def test_finalized_receipt_survives_payer_account_closed(self):
        f = self.f; raw, txid = f.prepare(); f.receipt(raw, txid)
        del f.accounts[f.terms['payer']]
        f.balance = 0
        self.assertFalse(f.adapter.observe()['fees_ready'])
        self.assertEqual(f.adapter.receipt('foreign-claim', raw, txid)['status'], 'confirmed')

    def test_send_only_exact_signed_bytes_without_preflight(self):
        f = self.f; raw, txid = f.prepare()
        self.assertEqual(f.adapter.send('foreign-claim', raw, txid), txid)
        self.assertEqual(base64.b64decode(f.sent[0][0]), raw)
        self.assertEqual(f.sent[0][1], {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0, 'minContextSlot': 190})

    def test_finalized_receipt_requires_full_bytes_execution_and_tombstone(self):
        f = self.f; raw, txid = f.prepare()
        unknown = f.adapter.receipt('foreign-claim', raw, txid)
        self.assertEqual(unknown['status'], 'unknown')
        self.assertFalse(unknown.get('publicly_observed', False))
        f.receipt(raw, txid)
        confirmed = f.adapter.receipt('foreign-claim', raw, txid)
        self.assertEqual(confirmed['status'], 'confirmed')
        self.assertTrue(confirmed['publicly_observed'])
        f.change('state', 8, b'\3')
        self.assertEqual(f.adapter.receipt('foreign-claim', raw, txid)['status'], 'unknown')
        f.receipt(raw, txid, wrong_bytes=True)
        self.assertEqual(f.adapter.receipt('foreign-claim', raw, txid)['status'], 'conflict')

    def test_finalized_receipt_survives_receiver_closing_destination(self):
        f = self.f; raw, txid = f.prepare(); f.receipt(raw, txid)
        del f.accounts[f.terms['claim']]
        del f.accounts[f.terms['refund']]
        self.assertEqual(f.adapter.receipt('foreign-claim', raw, txid)['status'], 'confirmed')

    def test_closed_claim_destination_preserves_refund_path(self):
        f = self.f; del f.accounts[f.terms['claim']]
        f.slot, f.processed = 220, 230
        observation = f.adapter.observe()
        self.assertEqual(observation['status'], 'unspent')
        self.assertFalse(observation['claim_ready'])
        self.assertTrue(observation['refund_eligible'])
        with self.assertRaises(ValueError): f.prepare()
        raw, txid = f.prepare('foreign-refund')
        self.assertEqual(f.adapter.validate('foreign-refund', raw, txid)['kind'], 'foreign-refund')

    def test_failed_and_pending_execution_never_report_success(self):
        f = self.f; raw, txid = f.prepare()
        f.history = {'slot': 180, 'err': None, 'confirmationStatus': 'confirmed'}
        pending = f.adapter.receipt('foreign-claim', raw, txid)
        self.assertEqual(pending['status'], 'pending')
        self.assertFalse(pending.get('publicly_observed', False))
        f.receipt(raw, txid, failed=True)
        failed = f.adapter.receipt('foreign-claim', raw, txid)
        self.assertEqual(failed['status'], 'failed')
        self.assertFalse(failed.get('publicly_observed', False))

    def test_renewal_requires_rooted_expiry_and_subsequent_funded_state(self):
        f = self.f; old_raw, old_txid = f.prepare(); old_hash = str(f.blockhash)
        provenance = f.adapter.preparation_evidence('foreign-claim', old_raw, old_txid)
        f.blockhash = Hash.new_unique(); f.valid[str(f.blockhash)] = True
        new_raw, new_txid = f.prepare()
        with self.assertRaises(ValueError): f.adapter.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, provenance)
        f.slot += 1
        f.valid[old_hash] = False
        evidence = f.adapter.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, provenance)
        self.assertTrue(evidence['history_may_be_pruned'])
        self.assertEqual(evidence['status'], 'renewable')
        self.assertGreaterEqual(evidence['unspent_context_slot'], evidence['expiry_context_slot'])
        self.assertFalse(f.sent)
        f.history = {'slot': 180, 'err': None, 'confirmationStatus': 'confirmed'}
        with self.assertRaises(ValueError): f.adapter.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, provenance)
        f.history = None; f.change('state', 8, b'\2'); f.change('vault', 64, bytes(8))
        with self.assertRaises(ValueError): f.adapter.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, provenance)

    def test_restart_cannot_treat_bank_predating_acquisition_as_expiry(self):
        f = self.f; old_raw, old_txid = f.prepare()
        provenance = f.adapter.preparation_evidence('foreign-claim', old_raw, old_txid)
        old_hash = str(f.blockhash)
        f.blockhash = Hash.new_unique(); f.valid[str(f.blockhash)] = True
        new_raw, new_txid = f.prepare()
        restarted = SolanaAdapter(f.rpc, f.terms)
        f.valid[old_hash] = False
        f.slot -= 1
        with self.assertRaises(ValueError):
            restarted.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, provenance)
        self.assertFalse(any(method == 'isBlockhashValid' for method, _ in f.calls))
        with self.assertRaises(ValueError):
            restarted.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, {})
        changed = dict(provenance, raw_sha256='00'*32)
        with self.assertRaises(ValueError):
            restarted.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, changed)


@unittest.skipUnless(os.environ.get('XDS_SOLANA_BUILD'), 'Set XDS_SOLANA_BUILD for compiled-ELF adapter/CPI qualification')
class SolanaAdapterVmTests(unittest.TestCase):
    def fixture(self):
        package = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('solana_profile_vm_fixture', package / 'solana/tests/test_vm.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        vm = module.ProfileFixture(); vm.fund()
        bridge = Fixture()
        manifest = json.loads((Path(os.environ['XDS_SOLANA_BUILD']) / 'build-manifest.json').read_text())
        bridge.terms = {name: str(vm.keys[i]) for i, name in enumerate(('state', 'vault', 'mint', 'claim', 'refund', 'source', 'depositor', 'authority'))}
        bridge.terms.update(manifest=manifest, payer=str(vm.relayer.pubkey()), amount=vm.amount,
                            hashlock=hashlib.sha256(vm.secret).hexdigest(), deadline_slot=vm.deadline,
                            min_context_slot=0, max_finality_lag_slots=32)
        bridge.program = Pubkey.from_string(manifest['profile']['program_id'])
        bridge.genesis = manifest['profile']['genesis_hash']
        code = (Path(os.environ['XDS_SOLANA_BUILD']) / 'solana_escrow.so').read_bytes()
        # Loader metadata/finality/fees are RPC fixtures. Actual settlement bytes
        # execute the selected ELF and real SPL Token CPI inside LiteSVM.
        bridge.accounts[str(bridge.program)] = account(profile.LOADER, struct.pack('<I', 2) + bytes(bridge.pd), True)
        bridge.accounts[str(bridge.pd)] = account(profile.LOADER, struct.pack('<IQB', 3, 0, 0) + bytes(32) + code)
        original_rpc = bridge.rpc
        def rpc(method, params):
            bridge.slot = bridge.processed = vm.vm.get_clock().slot
            bridge.blockhash = vm.vm.latest_blockhash()
            bridge.valid[str(bridge.blockhash)] = True
            bridge.balance = vm.vm.get_account(vm.relayer.pubkey()).lamports
            for name in ('state', 'vault', 'mint', 'claim', 'refund', 'payer'):
                key = bridge.terms[name]; value = vm.vm.get_account(Pubkey.from_string(key))
                if value:
                    bridge.accounts[key] = {'owner': str(value.owner), 'executable': value.executable,
                                            'lamports': value.lamports, 'data': [base64.b64encode(value.data).decode(), 'base64']}
                else:
                    bridge.accounts.pop(key, None)
            if method == 'sendTransaction':
                raw = base64.b64decode(params[0]); tx = Transaction.from_bytes(raw)
                result = vm.vm.send_transaction(tx)
                if isinstance(result, module.base.FailedTransactionMetadata):
                    raise AssertionError(str(result))
                bridge.sent.append(params)
                bridge.history = {'slot': bridge.slot, 'err': None, 'confirmationStatus': 'finalized'}
                bridge.transaction = {'slot': bridge.slot, 'transaction': [params[0], 'base64'], 'meta': {'err': None}}
                return str(tx.signatures[0])
            return original_rpc(method, params)
        adapter = SolanaAdapter(rpc, bridge.terms)
        return vm, bridge, adapter

    def test_compiled_escrow_claim_exact_amount_and_observed_receipt(self):
        vm, bridge, adapter = self.fixture()
        raw, txid = adapter.prepare('foreign-claim', vm.relayer, vm.secret)
        adapter.send('foreign-claim', raw, txid)
        self.assertEqual(vm.balance(vm.claim), vm.amount)
        self.assertEqual(vm.balance(vm.vault), 0)
        self.assertEqual(adapter.receipt('foreign-claim', raw, txid)['status'], 'confirmed')

    def test_compiled_escrow_refund_at_deadline(self):
        vm, bridge, adapter = self.fixture()
        with self.assertRaises(ValueError): adapter.prepare('foreign-refund', vm.relayer)
        vm.vm.warp_to_slot(vm.deadline)
        raw, txid = adapter.prepare('foreign-refund', vm.relayer)
        adapter.send('foreign-refund', raw, txid)
        self.assertEqual(vm.balance(vm.refund), vm.amount)
        self.assertEqual(adapter.receipt('foreign-refund', raw, txid)['status'], 'confirmed')

    def test_expired_wire_rejected_by_vm_and_semantic_renewal_settles_once(self):
        vm, bridge, adapter = self.fixture()
        old_raw, old_txid = adapter.prepare('foreign-claim', vm.relayer, vm.secret)
        provenance = adapter.preparation_evidence('foreign-claim', old_raw, old_txid)
        old_hash = str(Transaction.from_bytes(old_raw).message.recent_blockhash)
        vm.vm.expire_blockhash(); bridge.valid[old_hash] = False
        vm.vm.warp_to_slot(vm.vm.get_clock().slot + 1)
        rejected = vm.vm.send_transaction(Transaction.from_bytes(old_raw))
        self.assertIn('BlockhashNotFound', str(rejected))
        new_raw, new_txid = adapter.prepare('foreign-claim', vm.relayer, vm.secret)
        self.assertEqual(adapter.renew('foreign-claim', old_raw, old_txid, new_raw, new_txid, provenance)['status'], 'renewable')
        adapter.send('foreign-claim', new_raw, new_txid)
        self.assertEqual(vm.balance(vm.claim), vm.amount)
        self.assertEqual(vm.balance(vm.vault), 0)
        with self.assertRaises(ValueError): adapter.send('foreign-claim', old_raw, old_txid)


if __name__ == '__main__':
    unittest.main(verbosity=2)
