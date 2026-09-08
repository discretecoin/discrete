"""Qualified renewal for the immutable LOCAL LiteSVM escrow profile only.

This adapter directly observes an owned LiteSVM instance. It is not a production RPC
expiry/finality oracle. Only signed legacy single-instruction claim/refund transactions
are accepted; funding, durable nonce, lookup tables and arbitrary instructions fail closed.
"""
import pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'python-deps'))
from solders.hash import Hash
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from solders.transaction_status import TransactionErrorFieldless
from swap_journal import canonical,digest

PROGRAM=Pubkey.from_bytes(bytes([9])*32)
TOKEN=Pubkey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')

def checked_transaction(payload):
    if type(payload) is not bytes or not 0<len(payload)<=65536:raise ValueError('bounded signed Solana artifact required')
    try:
        tx=Transaction.from_bytes(payload);tx.sanitize();tx.verify()
        if bytes(tx)!=payload:raise ValueError('noncanonical Solana artifact')
    except Exception as error:raise ValueError('invalid signed legacy Solana transaction') from error
    message=tx.message
    if len(message.instructions)!=1:raise ValueError('only one immutable escrow instruction supported')
    ix=message.instructions[0]
    if message.account_keys[ix.program_id_index]!=PROGRAM or len(ix.accounts)!=10:
        raise ValueError('unsupported program/account profile')
    if bytes(ix.data[:1]) not in (b'\x01',b'\x02') or len(ix.data)!=(33 if ix.data[0]==1 else 1):
        raise ValueError('only claim/refund renewal supported')
    h=message.header
    # The entire decoded message is immutable except recent_blockhash. This also binds
    # fee payer, signer/writable permissions, account ordering, program and instruction bytes.
    semantic=bytes(Message.new_with_compiled_instructions(h.num_required_signatures,
      h.num_readonly_signed_accounts,h.num_readonly_unsigned_accounts,
      list(message.account_keys),Hash.default(),list(message.instructions)))
    return tx,digest(semantic)

class LiteSvmEscrowRecovery:
    def __init__(self,vm):self.vm=vm

    def contract_binding(self,payload):
        """Read the exact local escrow terms; no remote RPC or secret-bearing simulation."""
        tx,_=checked_transaction(payload);ix=tx.message.instructions[0]
        state_key=tx.message.account_keys[ix.accounts[0]];state=self.vm.get_account(state_key)
        if state is None or state.owner!=PROGRAM or state.executable or len(state.data)!=192 or state.data[:8]!=b'XDSV0001':
            raise ValueError('immutable escrow state unavailable')
        s=bytes(state.data)
        return {'program':str(PROGRAM),'state':str(state_key),'vault':str(Pubkey.from_bytes(s[64:96])),
          'mint':str(Pubkey.from_bytes(s[96:128])),'claim':str(Pubkey.from_bytes(s[128:160])),
          'refund':str(Pubkey.from_bytes(s[160:192])),'amount':int.from_bytes(s[16:24],'little'),
          'deadline':int.from_bytes(s[24:32],'little'),'hashlock':s[32:64].hex()}

    def broadcast_recovered(self,journal,swap,kind,admission_supplier=None):
        """Execute only an existing immutable settlement in the owned local VM.

        Recovery uncertainty is not exposure authorization. Unexposed snapshot claims
        still need fresh first-exposure admission; known exposed retries retain protection.
        Local simulation reads a preimage in-process, never through a remote RPC provider.
        """
        def validate(intent,terms):
            tx,_=checked_transaction(intent['payload'])
            if str(tx.signatures[0])!=intent['txid']:raise ValueError('recovery transaction identity mismatch')
            expected=1 if kind=='foreign-claim' else 2
            if tx.message.instructions[0].data[0]!=expected:raise ValueError('recovery role mismatch')
            binding=self.contract_binding(intent['payload'])
            if terms.get('solana_contract')!=binding:raise ValueError('recovery immutable terms mismatch')
            state=self.vm.get_account(Pubkey.from_string(binding['state']))
            if state.data[8]!=1:raise ValueError('recovery escrow already consumed')
            trial=self.vm.simulate_transaction(tx)
            if isinstance(trial,FailedTransactionMetadata):raise ValueError('recovery artifact does not currently execute in this VM')
            return {'source':'owned-litesvm-recovery-only','txid':intent['txid'],
              'payload_hash':digest(intent['payload']),'contract_hash':digest(canonical(binding)),
              'state_hash':digest(bytes(state.data)),'observed_slot':self.vm.get_clock().slot}
        def send(raw,txid):
            tx,_=checked_transaction(raw)
            if str(tx.signatures[0])!=txid:raise ValueError('recovery send identity mismatch')
            return self.vm.send_transaction(tx)
        return journal._broadcast_recovered(swap,kind,send,admission_supplier,validate)

    def renew(self,journal,swap,kind,replacement,*,expected_previous_txid):
        if kind not in ('foreign-claim','foreign-refund'):raise ValueError('foreign settlement renewal only')
        new,new_semantic=checked_transaction(replacement)
        expected_op=1 if kind=='foreign-claim' else 2
        if new.message.instructions[0].data[0]!=expected_op:raise ValueError('journal role differs from instruction')
        with journal.transaction():
            old=journal.intent(swap,kind)
            if old is None:raise ValueError('no original durable intent')
            previous,old_semantic=checked_transaction(old['payload'])
            if str(previous.signatures[0])!=old['txid']:raise ValueError('original transaction identity mismatch')
            if old_semantic!=new_semantic:raise ValueError('semantic intent changed')
            if old['payload']==replacement and old['attempt']>0 and old['evidence'] is not None and \
               old['evidence'].get('old_txid')==expected_previous_txid:
                return old # Exact retry after lost append response: no extra attempt or disclosure.
            if type(expected_previous_txid) is not str or expected_previous_txid!=old['txid']:
                raise ValueError('stale renewal predecessor')
            if previous.message.recent_blockhash==new.message.recent_blockhash:
                raise ValueError('blockhash unchanged')
            if old['status']=='confirmed':raise ValueError('confirmed attempt must first be reconciled')
            history=self.vm.get_transaction(previous.signatures[0])
            if history is not None and not isinstance(history,FailedTransactionMetadata):
                raise ValueError('old transaction already executed')
            # A different latest blockhash or caller-provided "rejected" bit is insufficient.
            # The owned VM must actually reject the old signed bytes for BlockhashNotFound.
            expired=self.vm.simulate_transaction(previous)
            if not isinstance(expired,FailedTransactionMetadata) or expired.err()!=TransactionErrorFieldless.BlockhashNotFound:
                raise ValueError('old blockhash is not proven expired by this VM')
            ix=previous.message.instructions[0]
            state_key=previous.message.account_keys[ix.accounts[0]]
            state=self.vm.get_account(state_key)
            if state is None or state.owner!=PROGRAM or state.executable or len(state.data)!=192 or \
               state.data[:8]!=b'XDSV0001' or state.data[8]!=1:
                raise ValueError('escrow not observed funded and unconsumed')
            if journal.recovery_required() and journal.terms(swap).get('solana_contract')!=self.contract_binding(old['payload']):
                raise ValueError('recovery immutable terms mismatch')
            # Actual program simulation rechecks committed vault, destinations, preimage,
            # timeout, token authority, balance, signatures and the new blockhash.
            trial=self.vm.simulate_transaction(new)
            if isinstance(trial,FailedTransactionMetadata):raise ValueError('replacement does not currently execute in this VM')
            evidence={'source':'owned-litesvm-only','old_txid':old['txid'],'old_attempt':old['attempt'],
              'old_payload_hash':digest(old['payload']),'old_blockhash':str(previous.message.recent_blockhash),
              'new_blockhash':str(new.message.recent_blockhash),'semantic_hash':old_semantic,
              'expiry_error':'BlockhashNotFound','state':str(state_key),
              'observed_state_hash':digest(bytes(state.data)),'observed_slot':self.vm.get_clock().slot,
              'observed_status':'funded-unconsumed','history':'absent' if history is None else 'failed'}
            journal.db.execute("UPDATE attempts SET status='rejected' WHERE swap=? AND kind=? AND attempt=?",
              (swap,kind,old['attempt']))
            journal._insert_attempt(swap,kind,old['attempt']+1,replacement,str(new.signatures[0]),evidence)
        return journal.intent(swap,kind)
