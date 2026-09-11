"""Owner-funded creation of one fixed escrow, with no implicit durable state.

The lifecycle stores the immutable public plan and auxiliary key material before
signing, then stores exact signed bytes and authenticated acquisition evidence
before send. This adapter never creates a second escrow identity during recovery.
Only legacy SPL Token and the canonical associated-token program are supported.
The funding owner owns source/refund; the independent claimant owns its ATA and
pays its own settlement fee. No private claimant key is needed to fund.
"""
import base64
import hashlib
import json
import struct

from solders.hash import Hash
from solders.instruction import AccountMeta as Meta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams, create_account, ID as SYSTEM
from solders.sysvar import CLOCK
from solders.transaction import Transaction

from .common import canonical
from .solana import SolanaAdapter, profile


TOKEN = Pubkey.from_string(profile.TOKEN)
ASSOCIATED = Pubkey.from_string('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
TERMS = {'manifest', 'owner', 'source', 'claim_owner', 'claim_payer', 'refund_owner', 'refund_payer',
         'amount', 'hashlock', 'deadline_slot', 'min_context_slot', 'max_finality_lag_slots',
         'min_funding_window_slots', 'max_funding_fee_lamports', 'max_rent_lamports', 'owner_reserve_lamports'}
PLAN = {'version', 'terms', 'accounts', 'rent', 'context_slot', 'quoted_fee_lamports', 'plan_id'}


def integer(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**64 - 1:
        raise ValueError('Invalid ' + name)
    return value


def public(value):
    if type(value) is not str:
        raise ValueError('Canonical public address required')
    key = Pubkey.from_string(value)
    if str(key) != value:
        raise ValueError('Canonical public address required')
    return key


def context(result, minimum):
    slot = integer(result['context']['slot'], 'RPC context')
    if slot < minimum:
        raise ValueError('Stale finalized RPC context')
    return slot


class SolanaFundingAdapter:
    def __init__(self, rpc, terms):
        if type(terms) is not dict or set(terms) != TERMS:
            raise ValueError('Explicit fixed owner funding terms required')
        self.terms = json.loads(canonical(terms))
        self.manifest = self.terms['manifest']
        self.profile = profile.validate_profile(self.manifest['profile'])
        self.program, self.mint = public(self.profile['program_id']), public(self.profile['mint'])
        self.owner, self.source = public(terms['owner']), public(terms['source'])
        self.claim_owner = public(terms['claim_owner'])
        if (terms['refund_owner'] != terms['owner'] or terms['refund_payer'] != terms['owner']
                or terms['claim_payer'] != terms['claim_owner'] or self.owner == self.claim_owner
                or not self.owner.is_on_curve() or not self.claim_owner.is_on_curve()):
            raise ValueError('Separate owner-controlled funding/refund and claim signers required')
        if len({self.owner, self.claim_owner, self.source, self.program, self.mint, TOKEN, ASSOCIATED, SYSTEM, CLOCK}) != 9:
            raise ValueError('Aliased owner/profile accounts')
        for key in ('amount', 'max_finality_lag_slots', 'min_funding_window_slots',
                    'max_funding_fee_lamports', 'max_rent_lamports'):
            integer(terms[key], key, 1)
        for key in ('deadline_slot', 'min_context_slot', 'owner_reserve_lamports'):
            integer(terms[key], key)
        lock = bytes.fromhex(terms['hashlock'])
        if len(lock) != 32 or lock.hex() != terms['hashlock']:
            raise ValueError('Canonical public hashlock required')
        self.claim, _ = Pubkey.find_program_address([bytes(self.claim_owner), bytes(TOKEN), bytes(self.mint)], ASSOCIATED)
        self._rpc, self._minimum, self._prepared = rpc, terms['min_context_slot'], None

    def _call(self, method, params):
        try:
            return self._rpc(method, params)
        except Exception:
            raise ValueError('RPC unavailable: ' + method) from None

    def _keys(self, keys, plan=None):
        if type(keys) is not dict or set(keys) != {'owner', 'state', 'vault', 'refund'}:
            raise ValueError('Funding owner and three retained auxiliary keypairs required')
        if not all(isinstance(key, Keypair) for key in keys.values()) or keys['owner'].pubkey() != self.owner:
            raise ValueError('Owner signing key differs from immutable terms')
        accounts = {name: str(keys[name].pubkey()) for name in ('state', 'vault', 'refund')}
        accounts['claim'] = str(self.claim)
        authority, _ = Pubkey.find_program_address([b'xds-swap-v1', bytes(keys['state'].pubkey())], self.program)
        accounts['authority'] = str(authority)
        if plan is not None and accounts != plan['accounts']:
            raise ValueError('Auxiliary keys differ from the retained escrow identity')
        self._account_keys(accounts)
        return accounts

    def _account_keys(self, accounts):
        if type(accounts) is not dict or set(accounts) != {'state', 'vault', 'claim', 'refund', 'authority'}:
            raise ValueError('Exact escrow account identities required')
        a = {name: public(value) for name, value in accounts.items()}
        authority, _ = Pubkey.find_program_address([b'xds-swap-v1', bytes(a['state'])], self.program)
        if a['claim'] != self.claim or a['authority'] != authority:
            raise ValueError('Claim ATA or escrow PDA differs')
        keys = [a['state'], a['vault'], self.mint, a['claim'], a['refund'], self.source, self.owner, authority, TOKEN, CLOCK]
        if len(set(keys)) != 10 or any(a[k] in (self.program, ASSOCIATED, SYSTEM, self.claim_owner) for k in ('state', 'vault', 'refund')):
            raise ValueError('Aliased escrow account identities')
        return keys

    def _check_plan(self, plan):
        if type(plan) is not dict or set(plan) != PLAN or type(plan['version']) is not int or plan['version'] != 1:
            raise ValueError('Unsupported immutable funding plan')
        if plan['terms'] != self.terms:
            raise ValueError('Funding plan differs from agreed owner terms')
        self._account_keys(plan['accounts'])
        rents = plan['rent']
        if type(rents) is not dict or set(rents) != {'state', 'vault', 'refund', 'claim_max'}:
            raise ValueError('Exact rent allocation required')
        for name, value in rents.items(): integer(value, name + ' rent', 1)
        if rents['vault'] != rents['refund'] or rents['vault'] != rents['claim_max'] or sum(rents.values()) > self.terms['max_rent_lamports']:
            raise ValueError('Rent allocation exceeds the explicit reserve')
        if integer(plan['quoted_fee_lamports'], 'quoted fee', 1) > self.terms['max_funding_fee_lamports']:
            raise ValueError('Funding fee exceeds the explicit cap')
        integer(plan['context_slot'], 'plan context')
        expected = hashlib.sha256(canonical({k: v for k, v in plan.items() if k != 'plan_id'})).hexdigest()
        if plan['plan_id'] != expected:
            raise ValueError('Funding plan identity differs')
        return plan

    def _instructions(self, plan):
        a, r = plan['accounts'], plan['rent']
        def create(name, size, owner):
            return create_account(CreateAccountParams(from_pubkey=self.owner, to_pubkey=public(a[name]),
                lamports=r[name], space=size, owner=owner))
        def initialize(name, owner):
            return Instruction(TOKEN, b'\x12' + bytes(owner),
                               [Meta(public(a[name]), False, True), Meta(self.mint, False, False)])
        instructions = [create('state', 192, self.program), create('vault', 165, TOKEN),
            initialize('vault', public(a['authority'])), create('refund', 165, TOKEN), initialize('refund', self.owner),
            Instruction(ASSOCIATED, b'\x01', [Meta(self.owner, True, True), Meta(self.claim, False, True),
                Meta(self.claim_owner, False, False), Meta(self.mint, False, False), Meta(SYSTEM, False, False), Meta(TOKEN, False, False)])]
        data = b'\0' + struct.pack('<QQ', self.terms['amount'], self.terms['deadline_slot']) + bytes.fromhex(self.terms['hashlock'])
        instructions.append(Instruction(self.program, data,
            [Meta(key, i in (0, 6), i in (0, 1, 3, 4, 5)) for i, key in enumerate(self._account_keys(a))]))
        return instructions

    def _token(self, account, owner, allow_frozen=False):
        data = profile.account_data(account, profile.TOKEN, False, 165)
        if (data[:32] != bytes(self.mint) or data[32:64] != bytes(owner)
                or data[108] not in ((1, 2) if allow_frozen else (1,))
                or any(data[72:76]) or any(data[109:113]) or any(data[129:133])):
            raise ValueError('Token mint, owner, native/delegate/close authority or initialization differs')
        return struct.unpack_from('<Q', data, 64)[0], data[108]

    def _snapshot(self, accounts):
        keys = self._account_keys(accounts)
        verified = profile.verify_rpc(self.manifest, self._call)
        minimum = max(self._minimum, verified['context_slot'])
        addresses = [accounts[k] for k in ('state', 'vault', 'refund')] + [str(self.source), str(self.owner), str(self.claim), str(ASSOCIATED)]
        result = self._call('getMultipleAccounts', [addresses,
            {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': minimum}])
        slot = context(result, minimum)
        if len(result['value']) != 7:
            raise ValueError('Incomplete coherent funding observation')
        state, vault, refund, source, owner, claim, associated = result['value']
        processed = integer(self._call('getSlot', [{'commitment': 'processed'}]), 'processed slot')
        if processed < slot or processed - slot > self.terms['max_finality_lag_slots']:
            raise ValueError('Funding observation exceeds the finality lag bound')
        self._minimum = max(self._minimum, slot)
        base = {'context_slot': slot, 'height': processed, 'final': True, 'genesis_hash': self.profile['genesis_hash'],
                'profile': verified, 'owner_ready': False, 'source_ready': False, 'claim_setup_ready': False,
                'owner_balance_lamports': 0, 'source_balance': None, 'status': 'unknown'}
        try:
            profile.account_data(owner, str(SYSTEM), False, 0)
            base.update(owner_ready=True, owner_balance_lamports=integer(owner['lamports'], 'owner lamports'))
        except (ValueError, TypeError, KeyError): pass
        try:
            amount, _ = self._token(source, self.owner)
            base.update(source_balance=amount, source_ready=amount >= self.terms['amount'])
        except (ValueError, TypeError, KeyError): pass
        try:
            if claim is not None: self._token(claim, self.claim_owner)
            base['claim_setup_ready'] = associated is not None and associated.get('executable') is True
        except (ValueError, TypeError, KeyError): pass
        if state is None:
            return dict(base, status='absent' if vault is None and refund is None else 'conflict')
        try:
            state_data = profile.account_data(state, str(self.program), False, 192)
            _, bump = Pubkey.find_program_address([b'xds-swap-v1', bytes(keys[0])], self.program)
            expected = (b'XDSV0001' + bytes([state_data[8], bump]) + bytes(6)
                + struct.pack('<QQ', self.terms['amount'], self.terms['deadline_slot']) + bytes.fromhex(self.terms['hashlock'])
                + b''.join(bytes(key) for key in keys[1:5]))
            if state_data != expected or state_data[8] not in (1, 2, 3):
                raise ValueError('Escrow state differs from the plan')
            balance, frozen = self._token(vault, keys[7], allow_frozen=True)
            if state_data[8] == 1 and balance < self.terms['amount']:
                raise ValueError('Funded escrow lacks principal')
            # Destination owners can spend/close accounts after settlement. The
            # exact consumed state remains evidence of prior funding in that case.
            if state_data[8] == 1:
                if refund is not None: self._token(refund, self.owner, allow_frozen=True)
                if claim is not None: self._token(claim, self.claim_owner, allow_frozen=True)
            return dict(base, status='funded' if state_data[8] == 1 else 'consumed',
                        state_status=state_data[8], vault_balance=balance, vault_frozen=frozen == 2)
        except (ValueError, TypeError, KeyError):
            return dict(base, status='conflict')

    def _latest(self, minimum):
        result = self._call('getLatestBlockhash', [{'commitment': 'finalized', 'minContextSlot': minimum}])
        slot = context(result, minimum)
        return Hash.from_string(result['value']['blockhash']), slot, integer(result['value']['lastValidBlockHeight'], 'last valid height')

    def _fee(self, plan, blockhash, minimum):
        message = Message.new_with_blockhash(self._instructions(plan), self.owner, blockhash)
        result = self._call('getFeeForMessage', [base64.b64encode(bytes(message)).decode(),
            {'commitment': 'finalized', 'minContextSlot': minimum}])
        slot = context(result, minimum)
        fee = integer(result['value'], 'funding fee', 1)
        if fee > self.terms['max_funding_fee_lamports']:
            raise ValueError('Current funding fee exceeds the explicit cap')
        refund = Instruction(self.program, b'\x02',
            [Meta(key, False, i in (0, 1, 3, 4, 5)) for i, key in enumerate(self._account_keys(plan['accounts']))])
        refund_message = Message.new_with_blockhash([refund], self.owner, blockhash)
        reserve = self._call('getFeeForMessage', [base64.b64encode(bytes(refund_message)).decode(),
            {'commitment': 'finalized', 'minContextSlot': slot}])
        reserve_slot = context(reserve, slot)
        if self.terms['owner_reserve_lamports'] < 2 * integer(reserve['value'], 'refund fee', 1):
            raise ValueError('Owner reserve must cover at least two currently quoted refund attempts')
        return fee, reserve_slot

    def _ready(self, plan, observation, fee):
        if (observation['status'] != 'absent' or not observation['owner_ready'] or not observation['source_ready']
                or not observation['claim_setup_ready'] or self.terms['deadline_slot'] - observation['height'] < self.terms['min_funding_window_slots']):
            raise ValueError('Unfunded identity, owner balances, destination or funding window unavailable')
        needed = sum(plan['rent'].values()) + fee + self.terms['owner_reserve_lamports']
        if observation['owner_balance_lamports'] < needed:
            raise ValueError('Owner lacks worst-case rent, funding fee and retained settlement reserve')

    def plan(self, keys):
        accounts = self._keys(keys)
        observation = self._snapshot(accounts)
        state_rent = integer(self._call('getMinimumBalanceForRentExemption', [192, {'commitment': 'finalized'}]), 'state rent', 1)
        token_rent = integer(self._call('getMinimumBalanceForRentExemption', [165, {'commitment': 'finalized'}]), 'token rent', 1)
        plan = {'version': 1, 'terms': self.terms, 'accounts': accounts,
            'rent': {'state': state_rent, 'vault': token_rent, 'refund': token_rent, 'claim_max': token_rent},
            'context_slot': observation['context_slot'], 'quoted_fee_lamports': 1}
        blockhash, slot, _ = self._latest(observation['context_slot'])
        fee, fee_slot = self._fee(plan, blockhash, slot)
        plan.update(quoted_fee_lamports=fee, context_slot=fee_slot)
        plan['plan_id'] = hashlib.sha256(canonical(plan)).hexdigest()
        self._check_plan(plan)
        self._ready(plan, observation, fee)
        return json.loads(canonical(plan))

    def prepare(self, plan, keys):
        self._check_plan(plan); self._keys(keys, plan)
        self._minimum = max(self._minimum, plan['context_slot'])
        observation = self._snapshot(plan['accounts'])
        blockhash, acquired, last_valid = self._latest(observation['context_slot'])
        fee, fee_slot = self._fee(plan, blockhash, acquired)
        self._minimum = max(self._minimum, fee_slot)
        after = self._snapshot(plan['accounts']); self._ready(plan, after, fee)
        current_rent = [integer(self._call('getMinimumBalanceForRentExemption', [size, {'commitment': 'finalized'}]), 'current rent', 1) for size in (192, 165)]
        if current_rent[0] > plan['rent']['state'] or current_rent[1] > plan['rent']['vault']:
            raise ValueError('Retained plan rent no longer covers initialization')
        tx = Transaction([keys[k] for k in ('owner', 'state', 'vault', 'refund')],
                         Message(self._instructions(plan), self.owner), blockhash)
        raw, txid = bytes(tx), str(tx.signatures[0]); checked = self.validate(plan, raw, txid)
        self._prepared = {'source': 'solana-funding-blockhash-acquisition-v1', 'plan_id': plan['plan_id'],
            'txid': txid, 'raw_sha256': checked['raw_sha256'], 'recent_blockhash': str(blockhash),
            'context_slot': acquired, 'last_valid_block_height': last_valid, 'genesis_hash': self.profile['genesis_hash']}
        return raw, txid

    def validate(self, plan, raw, txid):
        self._check_plan(plan)
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1232:
            raise ValueError('Bounded canonical funding transaction required')
        tx = Transaction.from_bytes(raw)
        if bytes(tx) != raw or len(tx.signatures) != 4 or str(tx.signatures[0]) != txid:
            raise ValueError('Funding wire/signature identity differs')
        tx.verify_and_hash_message()
        expected = Message.new_with_blockhash(self._instructions(plan), self.owner, tx.message.recent_blockhash)
        if bytes(tx.message) != bytes(expected):
            raise ValueError('Funding accounts, instructions, signers, rents or principal differ')
        normalized = Message.new_with_blockhash(self._instructions(plan), self.owner, Hash.default())
        return {'txid': txid, 'plan_id': plan['plan_id'], 'raw_sha256': hashlib.sha256(raw).hexdigest(),
            'semantic_hash': hashlib.sha256(bytes(normalized)).hexdigest(), 'recent_blockhash': str(tx.message.recent_blockhash),
            'amount': self.terms['amount'], 'owner': str(self.owner), 'state': plan['accounts']['state']}

    def preparation_evidence(self, plan, raw, txid):
        checked = self.validate(plan, raw, txid)
        if self._prepared is None or self._prepared['txid'] != txid or self._prepared['raw_sha256'] != checked['raw_sha256']:
            raise ValueError('Exact preparation acquisition evidence unavailable')
        return dict(self._prepared)

    def observe(self, plan):
        self._check_plan(plan)
        try:
            self._minimum = max(self._minimum, plan['context_slot'])
            return self._snapshot(plan['accounts'])
        except Exception:
            return {'status': 'unknown', 'final': False, 'context_slot': None, 'height': None,
                    'genesis_hash': self.profile['genesis_hash'], 'reason': 'No complete bounded finalized funding observation'}

    def _history(self, txid, minimum):
        result = self._call('getSignatureStatuses', [[txid], {'searchTransactionHistory': True}])
        context(result, minimum)
        if len(result['value']) != 1: raise ValueError('Incomplete signature history')
        history = result['value'][0]
        if history is not None:
            integer(history['slot'], 'signature slot')
            if history.get('confirmationStatus') not in ('processed', 'confirmed', 'finalized') or 'err' not in history:
                raise ValueError('Malformed signature history')
        return history

    def receipt(self, plan, raw, txid):
        checked = self.validate(plan, raw, txid)
        base = {'status': 'unknown', 'txid': txid, 'raw_sha256': checked['raw_sha256'], 'plan_id': plan['plan_id'], 'final': False}
        try:
            observation = self._snapshot(plan['accounts'])
            base.update(context_slot=observation['context_slot'], height=observation['height'])
            history = self._history(txid, observation['context_slot'])
            found = self._call('getTransaction', [txid, {'encoding': 'base64', 'commitment': 'finalized', 'maxSupportedTransactionVersion': 0}])
            if found is None:
                return dict(base, status='pending' if history and history['confirmationStatus'] != 'finalized' else 'unknown',
                            reason='No finalized full transaction; missing history is not nonexecution proof')
            wire = found['transaction']
            if type(wire) is not list or len(wire) != 2 or wire[1] != 'base64': raise ValueError('Full base64 transaction required')
            if base64.b64decode(wire[0], validate=True) != raw: return dict(base, status='conflict', reason='Finalized full bytes differ')
            slot = integer(found['slot'], 'inclusion slot')
            if history is None or history['confirmationStatus'] != 'finalized' or history['slot'] != slot or slot > observation['context_slot']:
                raise ValueError('Finalized history and accounts disagree')
            meta = found['meta']
            if type(meta) is not dict or 'err' not in meta or meta['err'] != history['err']:
                raise ValueError('Execution evidence differs')
            if meta['err'] is not None:
                return dict(base, status='failed', final=True, inclusion_slot=slot)
            if observation['status'] not in ('funded', 'consumed'):
                raise ValueError('Successful funding contradicts escrow state')
            fee = integer(meta['fee'], 'actual fee', 1)
            pre, post = integer(meta['preBalances'][0], 'payer prebalance'), integer(meta['postBalances'][0], 'payer postbalance')
            if fee > self.terms['max_funding_fee_lamports'] or not fee <= pre - post <= sum(plan['rent'].values()) + fee:
                raise ValueError('Actual funding lamport debit exceeds the approved allocation')
            return dict(base, status='confirmed', final=True, publicly_observed=True, inclusion_slot=slot,
                        escrow_status=observation['status'], fee_lamports=fee, owner_debit_lamports=pre - post)
        except Exception:
            return dict(base, reason='No exact finalized funding receipt with matching escrow and approved debit')

    def settlement_terms(self, plan, payer):
        self._check_plan(plan)
        if payer not in (self.terms['claim_payer'], self.terms['refund_payer']):
            raise ValueError('Pinned role settlement payer required')
        a = plan['accounts']
        result = dict(manifest=self.manifest, state=a['state'], vault=a['vault'], mint=str(self.mint), claim=a['claim'],
            refund=a['refund'], source=str(self.source), depositor=str(self.owner), authority=a['authority'], payer=payer,
            amount=self.terms['amount'], hashlock=self.terms['hashlock'], deadline_slot=self.terms['deadline_slot'],
            min_context_slot=plan['context_slot'], max_finality_lag_slots=self.terms['max_finality_lag_slots'])
        return json.loads(canonical(result))

    def resolve(self, plan, raw, txid):
        receipt = self.receipt(plan, raw, txid)
        observation = self.observe(plan)
        result = {'status': observation['status'], 'receipt': receipt, 'observation': observation}
        if observation['status'] in ('funded', 'consumed'):
            result['funded_terms'] = {role: self.settlement_terms(plan, self.terms[role + '_payer']) for role in ('claim', 'refund')}
        return result

    def send(self, plan, raw, txid):
        checked = self.validate(plan, raw, txid)
        self._minimum = max(self._minimum, plan['context_slot'])
        before = self._snapshot(plan['accounts'])
        valid = self._call('isBlockhashValid', [checked['recent_blockhash'],
            {'commitment': 'finalized', 'minContextSlot': before['context_slot']}])
        valid_slot = context(valid, before['context_slot'])
        if valid['value'] is not True: raise ValueError('Funding blockhash not valid in finalized context')
        fee, slot = self._fee(plan, Hash.from_string(checked['recent_blockhash']), valid_slot)
        self._minimum = max(self._minimum, slot)
        after = self._snapshot(plan['accounts']); self._ready(plan, after, fee)
        txid_result = self._call('sendTransaction', [base64.b64encode(raw).decode(),
            {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0, 'minContextSlot': after['context_slot']}])
        if txid_result != txid: raise ValueError('Funding acknowledgment differs from signed identity')
        return txid_result

    def renew(self, plan, old_raw, old_txid, new_raw, new_txid, provenance):
        old, new = self.validate(plan, old_raw, old_txid), self.validate(plan, new_raw, new_txid)
        required = {'source', 'plan_id', 'txid', 'raw_sha256', 'recent_blockhash', 'context_slot', 'last_valid_block_height', 'genesis_hash'}
        if (type(provenance) is not dict or set(provenance) != required
                or provenance['source'] != 'solana-funding-blockhash-acquisition-v1' or provenance['plan_id'] != plan['plan_id']
                or provenance['txid'] != old_txid or provenance['raw_sha256'] != old['raw_sha256']
                or provenance['recent_blockhash'] != old['recent_blockhash'] or provenance['genesis_hash'] != self.profile['genesis_hash']):
            raise ValueError('Authenticated acquisition for this exact retained funding attempt required')
        acquired = integer(provenance['context_slot'], 'acquisition slot')
        integer(provenance['last_valid_block_height'], 'last valid height')
        if old['semantic_hash'] != new['semantic_hash'] or old_txid == new_txid or old['recent_blockhash'] == new['recent_blockhash']:
            raise ValueError('Funding renewal may change only blockhash and signatures')
        self._minimum = max(self._minimum, plan['context_slot'], acquired + 1)
        before = self._snapshot(plan['accounts'])
        if before['status'] != 'absent': raise ValueError('Original escrow identity is already allocated, funded or unknown')
        history = self._history(old_txid, before['context_slot'])
        if history is not None and (history['err'] is None or history['confirmationStatus'] != 'finalized'):
            raise ValueError('Prior attempt has observed or ambiguous execution; reconcile first')
        expiry = self._call('isBlockhashValid', [old['recent_blockhash'],
            {'commitment': 'finalized', 'minContextSlot': before['context_slot']}])
        expiry_slot = context(expiry, before['context_slot'])
        if expiry['value'] is not False: raise ValueError('Old funding blockhash is not proven expired')
        self._minimum = max(self._minimum, expiry_slot)
        after = self._snapshot(plan['accounts'])
        if after['status'] != 'absent': raise ValueError('No coherent absence of original state/vault/refund after expiry')
        current = self._call('isBlockhashValid', [new['recent_blockhash'],
            {'commitment': 'finalized', 'minContextSlot': after['context_slot']}])
        current_slot = context(current, after['context_slot'])
        if current['value'] is not True or current_slot > after['height']:
            raise ValueError('Replacement hash is not valid in bounded finalized context')
        return {'status': 'renewable', 'plan_id': plan['plan_id'], 'old_txid': old_txid, 'new_txid': new_txid,
            'old_raw_sha256': old['raw_sha256'], 'new_raw_sha256': new['raw_sha256'], 'semantic_hash': old['semantic_hash'],
            'acquisition_context_slot': acquired, 'expiry_context_slot': expiry_slot, 'absent_context_slot': after['context_slot'],
            'previous_history_status': history, 'history_may_be_pruned': history is None,
            'genesis_hash': self.profile['genesis_hash'],
            'basis': 'Rooted blockhash expiry and later coherent absence of the same state/vault/refund; not null-history proof'}
