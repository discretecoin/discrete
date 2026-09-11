"""Fixed escrow settlement and rooted blockhash renewal, without remote secrets.

Only canonical one-instruction legacy transactions are accepted. The caller must
journal exact signed bytes before send. Null/pruned signature history is never
proof of nonexecution; renewal additionally requires rooted blockhash expiry and
a subsequent finalized observation of the same still-funded escrow.

SolanaAdapter(rpc, terms) requires manifest (the trusted Solana build manifest),
state/vault/mint/claim/refund/source/depositor/authority/payer as base58 strings,
amount as raw u64 token units, hashlock as lowercase 32-byte hex, deadline_slot,
min_context_slot and max_finality_lag_slots. Kinds are foreign-claim/refund.
prepare(kind, solders.Keypair, secret=None) returns exact (bytes, signature ID).
validate is offline and verifies signatures and the complete canonical message.
observe exposes claim_ready/refund_ready/fees_ready separately: admission must
require claim_ready AND fees_ready before publishing the paired XDS secret.
receipt distinguishes exact finalized success/error, pending, unknown, conflict.
renew validates two previously prepared wires and returns evidence only; it
neither persists nor sends. The coordinator owns journal durability and release.

The chain binding, finality and expiry observations trust the selected validating
RPC service; this is not a light client or independent consensus proof. Fees are
quoted for an equal-size, single-signature claim containing a non-preimage dummy.
No compute-budget or additional instruction is permitted, and no real preimage
is sent to a fee quote or simulation endpoint.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.sysvar import CLOCK
from solders.transaction import Transaction

_spec = importlib.util.spec_from_file_location('xds_solana_deployment_profile',
                                              Path(__file__).resolve().parents[2] / 'solana/profile.py')
profile = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(profile)
KINDS = ('foreign-claim', 'foreign-refund')
KEYS = ('state', 'vault', 'mint', 'claim', 'refund', 'source', 'depositor', 'authority')


def _integer(value, name, maximum=2**64-1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('Invalid ' + name)
    return value


def _context(result, minimum=0):
    slot = _integer(result['context']['slot'], 'context slot')
    if slot < minimum:
        raise ValueError('Stale RPC account context')
    return slot


class SolanaAdapter:
    def __init__(self, rpc, terms):
        required = {'manifest', *KEYS, 'payer', 'amount', 'hashlock', 'deadline_slot',
                    'min_context_slot', 'max_finality_lag_slots'}
        if not isinstance(terms, dict) or set(terms) != required:
            raise ValueError('Unexpected or missing Solana contract terms')
        self.terms = json.loads(json.dumps(terms))
        self.manifest = self.terms['manifest']
        self.profile = profile.validate_profile(self.manifest['profile'])
        self.keys = [Pubkey.from_string(terms[name]) for name in KEYS]
        self.keys += [Pubkey.from_string(profile.TOKEN), CLOCK]
        if len(set(self.keys)) != 10 or terms['mint'] != self.profile['mint']:
            raise ValueError('Aliased account or mint/profile mismatch')
        self.program = Pubkey.from_string(self.profile['program_id'])
        self.payer = Pubkey.from_string(terms['payer'])
        authority, self.bump = Pubkey.find_program_address([b'xds-swap-v1', bytes(self.keys[0])], self.program)
        if authority != self.keys[7]:
            raise ValueError('PDA authority does not match this state/program')
        if _integer(terms['amount'], 'principal') == 0:
            raise ValueError('Zero principal')
        _integer(terms['deadline_slot'], 'deadline slot')
        _integer(terms['min_context_slot'], 'minimum context')
        if _integer(terms['max_finality_lag_slots'], 'finality lag') == 0:
            raise ValueError('Finality lag bound required')
        self.hashlock = bytes.fromhex(terms['hashlock'])
        if len(self.hashlock) != 32 or self.hashlock.hex() != terms['hashlock']:
            raise ValueError('Canonical 32-byte hashlock required')
        self._rpc = rpc
        self._minimum = terms['min_context_slot']
        self._prepared = None

    def _call(self, method, params):
        try:
            return self._rpc(method, params)
        except Exception:
            raise ValueError('RPC unavailable: ' + method) from None

    def _ix(self, kind, secret=None):
        if kind not in KINDS:
            raise ValueError('Unsupported settlement kind')
        data = b'\x01' + secret if kind == 'foreign-claim' else b'\x02'
        return Instruction(self.program, data, [AccountMeta(key, False, i in (0, 1, 3, 4, 5))
                                               for i, key in enumerate(self.keys)])

    def validate(self, kind, raw, txid):
        if kind not in KINDS or not isinstance(raw, bytes) or not 1 <= len(raw) <= 1232:
            raise ValueError('Unsupported or oversized settlement transaction')
        tx = Transaction.from_bytes(raw)
        if bytes(tx) != raw or len(tx.signatures) != 1 or str(tx.signatures[0]) != txid:
            raise ValueError('Noncanonical transaction or signature identity mismatch')
        Signature.from_string(txid)
        tx.verify_and_hash_message()
        message = tx.message
        if len(message.instructions) != 1:
            raise ValueError('Exactly one escrow instruction is required')
        data = bytes(message.instructions[0].data)
        secret = None
        if kind == 'foreign-claim':
            if len(data) != 33 or data[0] != 1 or hashlib.sha256(data[1:]).digest() != self.hashlock:
                raise ValueError('Invalid claim preimage')
            secret = data[1:]
        elif data != b'\x02':
            raise ValueError('Invalid refund instruction')
        expected = Message.new_with_blockhash([self._ix(kind, secret)], self.payer, message.recent_blockhash)
        if bytes(expected) != bytes(message):
            raise ValueError('Transaction differs from pinned accounts, signer, destination or instruction')
        normalized = Message.new_with_blockhash([self._ix(kind, secret)], self.payer, Hash.default())
        result = {'kind': kind, 'txid': txid, 'payer': str(self.payer), 'amount': self.terms['amount'],
                  'recent_blockhash': str(message.recent_blockhash),
                  'semantic_hash': hashlib.sha256(bytes(normalized)).hexdigest(),
                  'raw_sha256': hashlib.sha256(raw).hexdigest()}
        if secret is not None:
            result['secret'] = secret.hex()
        return result

    def _latest(self, minimum):
        result = self._call('getLatestBlockhash', [{'commitment': 'finalized', 'minContextSlot': minimum}])
        slot = _context(result, minimum)
        blockhash = Hash.from_string(result['value']['blockhash'])
        last_valid = _integer(result['value']['lastValidBlockHeight'], 'last valid block height')
        return blockhash, slot, last_valid

    def _token(self, account):
        data = profile.account_data(account, profile.TOKEN, False, 165)
        if data[:32] != bytes(self.keys[2]) or data[108] not in (1, 2) or any(data[109:113]):
            raise ValueError('Invalid initialized non-native token account')
        return data

    def _destination(self, account):
        # A closed, reinitialized or frozen fixed destination blocks its branch,
        # but must not disable recovery to the other fixed destination.
        try:
            return self._token(account)
        except (ValueError, TypeError, KeyError):
            return None

    def _observe(self):
        verified = profile.verify_rpc(self.manifest, self._call)
        minimum = max(self._minimum, verified['context_slot'])
        result = self._call('getMultipleAccounts', [[str(key) for key in self.keys[:5]],
                            {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': minimum}])
        slot = _context(result, minimum)
        if len(result['value']) != 5:
            raise ValueError('Incomplete escrow account observation')
        state_a, vault_a, mint_a, claim_a, refund_a = result['value']
        state = profile.account_data(state_a, str(self.program), False, 192)
        expected = (b'XDSV0001' + bytes([state[8], self.bump]) + bytes(6)
                    + struct.pack('<QQ', self.terms['amount'], self.terms['deadline_slot'])
                    + self.hashlock + b''.join(bytes(key) for key in self.keys[1:5]))
        if state != expected or state[8] not in (1, 2, 3):
            raise ValueError('Escrow state does not match immutable swap terms')
        mint = profile.account_data(mint_a, profile.TOKEN, False, 82)
        if mint[44:46] != b'\x06\x01':
            raise ValueError('Wrong mint decimal/initialization profile')
        vault = self._token(vault_a)
        # Receivers may close their token accounts after settlement. The exact
        # finalized tombstone remains usable as evidence after that normal action.
        claim, refund = (self._destination(a) for a in (claim_a, refund_a)) if state[8] == 1 else (None, None)
        if vault[32:64] != bytes(self.keys[7]) or any(vault[72:76]) or any(vault[129:133]):
            raise ValueError('Vault authority/delegate/close-authority differs from escrow')
        balance = struct.unpack_from('<Q', vault, 64)[0]
        if state[8] == 1 and balance < self.terms['amount']:
            raise ValueError('Funded escrow has insufficient principal')
        # Fee calculation uses a fixed dummy preimage, never the real secret. The
        # canonical transaction has one signature and no priority-fee instruction.
        blockhash, latest_slot, _ = self._latest(slot)
        dummy_secret = bytes(32)
        if hashlib.sha256(dummy_secret).digest() == self.hashlock:
            dummy_secret = bytes([1]) * 32
        dummy = Message.new_with_blockhash([self._ix('foreign-claim', dummy_secret)], self.payer, blockhash)
        fee = self._call('getFeeForMessage', [base64.b64encode(bytes(dummy)).decode(),
                        {'commitment': 'finalized', 'minContextSlot': latest_slot}])
        fee_slot = _context(fee, latest_slot)
        fee_value = _integer(fee['value'], 'transaction fee')
        payer = self._call('getAccountInfo', [str(self.payer),
                           {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': fee_slot}])
        payer_slot = _context(payer, fee_slot)
        payer_account = payer['value']
        payer_value = 0 if payer_account is None else _integer(payer_account['lamports'], 'payer balance')
        try:
            # This profile signs ordinary recent-blockhash transactions, not
            # durable-nonce transactions. A token/program-owned account cannot
            # pay their fee even when it has sufficient lamports.
            profile.account_data(payer_account, '11111111111111111111111111111111', False, 0)
            payer_usable = True
        except ValueError:
            payer_usable = False
        processed = _integer(self._call('getSlot', [{'commitment': 'processed'}]), 'processed slot')
        if processed < payer_slot or processed < slot or processed - slot > self.terms['max_finality_lag_slots']:
            raise ValueError('Finalized observation exceeds allowed lag or RPC slots disagree')
        self._minimum = max(self._minimum, slot)
        funded = state[8] == 1
        claim_ready = funded and claim is not None and vault[108] == claim[108] == 1
        refund_ready = funded and refund is not None and vault[108] == refund[108] == 1
        return {'status': 'unspent' if funded else 'spent', 'state_status': state[8],
                'height': processed, 'context_slot': slot, 'finalized_height': slot,
                'confirmations': 1, 'final': True, 'genesis_hash': self.profile['genesis_hash'],
                'refund_eligible': refund_ready and slot >= self.terms['deadline_slot'],
                'claim_ready': claim_ready, 'refund_ready': refund_ready,
                'fees_ready': payer_usable and fee_value > 0 and payer_value >= fee_value,
                'payer_usable': payer_usable,
                'fee_lamports': fee_value, 'payer_balance_lamports': payer_value,
                'fee_context_slot': payer_slot, 'principal': self.terms['amount'],
                'vault_balance': balance, 'profile': verified,
                'scope': 'Finalized RPC observations under the selected endpoint and chain finality assumptions'}

    def observe(self):
        try:
            return self._observe()
        except Exception:
            return {'status': 'unknown', 'height': None, 'context_slot': None,
                    'confirmations': 0, 'final': False, 'refund_eligible': False,
                    'fees_ready': False, 'claim_ready': False, 'refund_ready': False,
                    'genesis_hash': self.profile['genesis_hash'],
                    'reason': 'Could not establish immutable profile, complete escrow state and bounded finalized RPC context'}

    def prepare(self, kind, key, secret=None):
        if not isinstance(key, Keypair) or key.pubkey() != self.payer:
            raise ValueError('Configured fee payer keypair required')
        if kind == 'foreign-claim' and (not isinstance(secret, bytes) or len(secret) != 32 or hashlib.sha256(secret).digest() != self.hashlock):
            raise ValueError('Invalid claim preimage')
        if kind == 'foreign-refund' and secret is not None:
            raise ValueError('Refund must not contain a secret')
        state = self._observe()
        ready = state['claim_ready'] if kind == 'foreign-claim' else state['refund_eligible']
        if not ready or not state['fees_ready']:
            raise ValueError('Escrow branch or fee payer is not ready')
        blockhash, acquired_slot, last_valid = self._latest(state['context_slot'])
        tx = Transaction([key], Message([self._ix(kind, secret)], self.payer), blockhash)
        raw, txid = bytes(tx), str(tx.signatures[0])
        self.validate(kind, raw, txid)
        self._prepared = {'source': 'solana-blockhash-acquisition-v1', 'txid': txid,
                          'raw_sha256': hashlib.sha256(raw).hexdigest(), 'recent_blockhash': str(blockhash),
                          'context_slot': acquired_slot, 'last_valid_block_height': last_valid,
                          'genesis_hash': self.profile['genesis_hash']}
        return raw, txid

    def preparation_evidence(self, kind, raw, txid):
        checked = self.validate(kind, raw, txid)
        if (self._prepared is None or self._prepared['txid'] != txid
                or self._prepared['raw_sha256'] != checked['raw_sha256']):
            raise ValueError('No acquisition evidence for the most recently prepared transaction')
        return dict(self._prepared)

    def _history(self, txid, minimum):
        result = self._call('getSignatureStatuses', [[txid], {'searchTransactionHistory': True}])
        _context(result, minimum)
        if len(result['value']) != 1:
            raise ValueError('Incomplete signature history result')
        status = result['value'][0]
        if status is not None:
            _integer(status['slot'], 'signature slot')
            if status.get('confirmationStatus') not in ('processed', 'confirmed', 'finalized') or 'err' not in status:
                raise ValueError('Malformed signature status')
        return status

    def receipt(self, kind, raw, txid):
        checked = self.validate(kind, raw, txid)
        base = {'status': 'unknown', 'txid': txid, 'raw_sha256': checked['raw_sha256'],
                'confirmations': 0, 'final': False, 'genesis_hash': self.profile['genesis_hash']}
        try:
            observation = self._observe()
            base.update(height=observation['height'], context_slot=observation['context_slot'])
            history = self._history(txid, observation['context_slot'])
            found = self._call('getTransaction', [txid, {'encoding': 'base64', 'commitment': 'finalized',
                                'maxSupportedTransactionVersion': 0}])
            if found is None:
                return dict(base, status='pending' if history and history['confirmationStatus'] != 'finalized' else 'unknown',
                            history_status=history, reason='No finalized full transaction; null may reflect pruned history')
            encoded = found['transaction']
            if not isinstance(encoded, list) or len(encoded) != 2 or encoded[1] != 'base64':
                raise ValueError('Full base64 transaction required')
            if base64.b64decode(encoded[0], validate=True) != raw:
                return dict(base, status='conflict', reason='Finalized full transaction bytes differ')
            slot = _integer(found['slot'], 'transaction slot')
            if history is None or history['confirmationStatus'] != 'finalized' or history['slot'] != slot or slot > observation['context_slot']:
                raise ValueError('Finalized transaction and account/history contexts disagree')
            meta = found['meta']
            if not isinstance(meta, dict) or 'err' not in meta or meta['err'] != history['err']:
                raise ValueError('Transaction execution evidence disagrees')
            if meta['err'] is not None:
                return dict(base, status='failed', final=True, confirmations=1, inclusion_slot=slot,
                            reason='Exact signed transaction finalized with an execution error')
            expected_status = 2 if kind == 'foreign-claim' else 3
            if observation['state_status'] != expected_status:
                raise ValueError('Successful spend contradicts the finalized escrow tombstone')
            return dict(base, status='confirmed', final=True, confirmations=1, inclusion_slot=slot,
                        state_status=expected_status, publicly_observed=True)
        except Exception:
            return dict(base, reason='Could not establish exact finalized transaction and matching escrow outcome')

    def send(self, kind, raw, txid):
        self.validate(kind, raw, txid)
        observation = self._observe()
        ready = observation['claim_ready'] if kind == 'foreign-claim' else observation['refund_eligible']
        if not ready or not observation['fees_ready']:
            raise ValueError('Escrow branch or fee payer is not ready')
        result = self._call('sendTransaction', [base64.b64encode(raw).decode(),
                            {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0,
                             'minContextSlot': observation['context_slot']}])
        if result != txid:
            raise ValueError('Broadcast acknowledgment does not match signed txid')
        return result

    def renew(self, kind, old_raw, old_txid, new_raw, new_txid, provenance):
        old = self.validate(kind, old_raw, old_txid)
        new = self.validate(kind, new_raw, new_txid)
        required = {'source', 'txid', 'raw_sha256', 'recent_blockhash', 'context_slot',
                    'last_valid_block_height', 'genesis_hash'}
        if (type(provenance) is not dict or set(provenance) != required
                or provenance['source'] != 'solana-blockhash-acquisition-v1'
                or provenance['txid'] != old_txid or provenance['raw_sha256'] != old['raw_sha256']
                or provenance['recent_blockhash'] != old['recent_blockhash']
                or provenance['genesis_hash'] != self.profile['genesis_hash']):
            raise ValueError('Authenticated prior blockhash acquisition evidence required')
        acquired = _integer(provenance['context_slot'], 'acquisition context', 2**64-2)
        _integer(provenance['last_valid_block_height'], 'last valid block height')
        # A node bank predating acquisition may report a future hash as unknown.
        # Only a later finalized context can qualify an acquired hash as expired.
        self._minimum = max(self._minimum, acquired + 1)
        if old['semantic_hash'] != new['semantic_hash'] or old['recent_blockhash'] == new['recent_blockhash'] or old_txid == new_txid:
            raise ValueError('Renewal must preserve every semantic field and replace only recent blockhash/signature')
        before = self._observe()
        if before['status'] != 'unspent':
            raise ValueError('Cannot renew a consumed escrow')
        history = self._history(old_txid, before['context_slot'])
        if history is not None and history['err'] is None:
            raise ValueError('Previous transaction has observed execution; reconcile before renewal')
        expiry = self._call('isBlockhashValid', [old['recent_blockhash'],
                            {'commitment': 'finalized', 'minContextSlot': before['context_slot']}])
        expiry_slot = _context(expiry, before['context_slot'])
        if expiry['value'] is not False:
            raise ValueError('Old transaction blockhash is not proven invalid in a finalized bank')
        self._minimum = max(self._minimum, expiry_slot)
        after = self._observe()
        if after['status'] != 'unspent' or after['context_slot'] < expiry_slot:
            raise ValueError('No still-funded finalized escrow observation after rooted expiry')
        current = self._call('isBlockhashValid', [new['recent_blockhash'],
                            {'commitment': 'finalized', 'minContextSlot': after['context_slot']}])
        current_slot = _context(current, after['context_slot'])
        if current['value'] is not True or current_slot > after['height']:
            raise ValueError('Replacement blockhash is not valid in the bounded finalized context')
        return {'status': 'renewable', 'old_txid': old_txid, 'new_txid': new_txid,
                'old_raw_sha256': old['raw_sha256'], 'new_raw_sha256': new['raw_sha256'],
                'semantic_hash': old['semantic_hash'], 'genesis_hash': self.profile['genesis_hash'],
                'expired_blockhash': old['recent_blockhash'], 'expiry_context_slot': expiry_slot,
                'acquisition_context_slot': acquired,
                'unspent_context_slot': after['context_slot'], 'previous_history_status': history,
                'history_may_be_pruned': history is None,
                'basis': 'Finalized blockhash invalidation plus subsequent finalized funded state; not null-history proof'}
