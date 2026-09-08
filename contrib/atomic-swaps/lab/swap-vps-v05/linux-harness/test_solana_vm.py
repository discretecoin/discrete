"""Execute compiled SBF escrow and real SPL Token CPI in solders LiteSVM.
Local mint is initialized/minted through actual SPL instructions; not Circle-issued USDC.
"""
import hashlib,json,pathlib,struct,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT/'python-deps'))
from solders.account import Account
from solders.instruction import Instruction,AccountMeta as Meta
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.message import Message
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from solders.system_program import create_account,CreateAccountParams
from solders.sysvar import CLOCK
from solders.litesvm import LiteSVM
from solders.compute_budget import set_compute_unit_limit

PID=Pubkey.from_bytes(bytes([9])*32)
TOKEN=Pubkey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
u64=lambda v:struct.pack('<Q',v)
sha=lambda b:hashlib.sha256(b).digest()

class Fixture:
    def __init__(self):
        self.vm=LiteSVM();self.vm.add_program_from_file(PID,ROOT/'solana_escrow.so')
        self.payer=Keypair();self.relayer=Keypair();self.mint=Keypair.from_seed(bytes([4])*32)
        self.state=Keypair();self.vault=Keypair();self.source=Keypair();self.claim=Keypair();self.refund=Keypair()
        self.authority,self.bump=Pubkey.find_program_address([b'xds-swap-v1',bytes(self.state.pubkey())],PID)
        self.vm.airdrop(self.payer.pubkey(),10_000_000_000);self.vm.airdrop(self.relayer.pubkey(),100_000_000)
        self.send([self.create(self.mint,82,TOKEN),Instruction(TOKEN,b'\x14\x06'+bytes(self.payer.pubkey())+b'\x01'+bytes(self.payer.pubkey()),[Meta(self.mint.pubkey(),False,True)])],[self.mint])
        for kp,owner in [(self.source,self.payer.pubkey()),(self.vault,self.authority),(self.claim,self.relayer.pubkey()),(self.refund,self.payer.pubkey())]:
            self.send([self.create(kp,165,TOKEN),Instruction(TOKEN,b'\x12'+bytes(owner),[Meta(kp.pubkey(),False,True),Meta(self.mint.pubkey(),False,False)])],[kp])
        self.send([Instruction(TOKEN,b'\x0e'+u64(10_000_000)+b'\x06',[Meta(self.mint.pubkey(),False,True),Meta(self.source.pubkey(),False,True),Meta(self.payer.pubkey(),True,False)])])
        self.send([self.create(self.state,192,PID)],[self.state])
        self.secret=bytes([77])*32;self.amount=1_234_567;self.deadline=self.vm.get_clock().slot+100
        self.keys=[self.state.pubkey(),self.vault.pubkey(),self.mint.pubkey(),self.claim.pubkey(),self.refund.pubkey(),self.source.pubkey(),self.payer.pubkey(),self.authority,TOKEN,CLOCK]
    def create(self,kp,size,owner):
        return create_account(CreateAccountParams(from_pubkey=self.payer.pubkey(),to_pubkey=kp.pubkey(),lamports=self.vm.minimum_balance_for_rent_exemption(size),space=size,owner=owner))
    def transaction(self,ixs,signers=(),payer=None,blockhash=None):
        payer=payer or self.payer
        return Transaction([payer,*signers],Message(ixs,payer.pubkey()),blockhash or self.vm.latest_blockhash())
    def send(self,ixs,signers=(),payer=None,ok=True):
        result=self.vm.send_transaction(self.transaction(ixs,signers,payer))
        if ok and isinstance(result,FailedTransactionMetadata):raise AssertionError(str(result))
        if not ok and not isinstance(result,FailedTransactionMetadata):raise AssertionError('unexpected acceptance: '+str(result))
        return result
    def ix(self,op,data=None,keys=None):
        keys=keys or self.keys
        if data is None:data=(b'\0'+u64(self.amount)+u64(self.deadline)+sha(self.secret) if op==0 else b'\x01'+self.secret if op==1 else b'\x02')
        return Instruction(PID,data,[Meta(k,op==0 and i in (0,6),i in (0,1,3,4,5)) for i,k in enumerate(keys)])
    def fund(self):return self.send([self.ix(0)],[self.state])
    def balance(self,kp):return struct.unpack_from('<Q',self.vm.get_account(kp.pubkey()).data,64)[0]
    def status(self):return self.vm.get_account(self.state.pubkey()).data[8]
    def mutate(self,kp,offset,data):
        account=self.vm.get_account(kp.pubkey());b=bytearray(account.data);b[offset:offset+len(data)]=data
        self.vm.set_account(kp.pubkey(),Account(account.lamports,bytes(b),account.owner,account.executable,account.rent_epoch))
    def freeze(self,kp,frozen):
        return self.send([Instruction(TOKEN,bytes([10 if frozen else 11]),[Meta(kp.pubkey(),False,True),Meta(self.mint.pubkey(),False,False),Meta(self.payer.pubkey(),True,False)])])

class SolanaVmTests(unittest.TestCase):
    def setUp(self):self.f=Fixture()
    def test_real_spl_fund_claim_exact_amount_no_redirect_and_next_transfer(self):
        f=self.f;f.fund();self.assertEqual(f.balance(f.vault),f.amount);self.assertEqual(f.balance(f.source),10_000_000-f.amount)
        f.send([f.ix(1)],payer=f.relayer);self.assertEqual(f.status(),2);self.assertEqual(f.balance(f.claim),f.amount);self.assertEqual(f.balance(f.vault),0)
        f.send([Instruction(TOKEN,b'\x0c'+u64(f.amount)+b'\x06',[Meta(f.claim.pubkey(),False,True),Meta(f.mint.pubkey(),False,False),Meta(f.refund.pubkey(),False,True),Meta(f.relayer.pubkey(),True,False)])],payer=f.relayer)
        self.assertEqual(f.balance(f.refund),f.amount)
    def test_refund_exact_slot_and_retry_after_rejection(self):
        f=self.f;f.fund();f.vm.warp_to_slot(f.deadline-1);f.send([f.ix(2)],payer=f.relayer,ok=False)
        self.assertEqual(f.status(),1);f.vm.warp_to_slot(f.deadline);f.vm.expire_blockhash();f.send([f.ix(2)],payer=f.relayer)
        self.assertEqual(f.status(),3);self.assertEqual(f.balance(f.refund),f.amount)
    def test_claim_after_deadline_and_both_spend_orders(self):
        f=self.f;f.fund();f.vm.warp_to_slot(f.deadline);f.send([f.ix(1)],payer=f.relayer)
        f.send([f.ix(2)],payer=f.relayer,ok=False);self.assertEqual(f.status(),2)
        f=Fixture();f.fund();f.vm.warp_to_slot(f.deadline);f.send([f.ix(2)],payer=f.relayer)
        f.send([f.ix(1)],payer=f.relayer,ok=False);self.assertEqual(f.status(),3)
    def test_wrong_secret_length_trailing_bytes_leave_funds_locked(self):
        f=self.f;f.fund()
        for data in [b'\x01'+b'\x42'*32,b'\x01'+f.secret[:-1],b'\x01'+f.secret+b'\0',b'\x03']:
            f.send([f.ix(1,data)],payer=f.relayer,ok=False)
        self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.vault),f.amount)
        f.send([f.ix(1)],payer=f.relayer)
    def test_wrong_destination_vault_authority_mint_program_and_alias(self):
        f=self.f;f.fund()
        for index,replacement in [(3,f.source.pubkey()),(1,f.source.pubkey()),(7,f.relayer.pubkey()),(2,f.source.pubkey()),(8,Pubkey.default())]:
            keys=f.keys.copy();keys[index]=replacement;f.send([f.ix(1,keys=keys)],payer=f.relayer,ok=False)
            self.assertEqual(f.status(),1)
        # Distinct, valid token destination has no alias excuse: fixed key must still reject it.
        alternate=Keypair();f.send([f.create(alternate,165,TOKEN),Instruction(TOKEN,b'\x12'+bytes(f.relayer.pubkey()),[Meta(alternate.pubkey(),False,True),Meta(f.mint.pubkey(),False,False)])],[alternate])
        keys=f.keys.copy();keys[3]=alternate.pubkey();f.send([f.ix(1,keys=keys)],payer=f.relayer,ok=False)
        f.send([f.ix(1)],payer=f.relayer)
    def test_issuer_freeze_preserves_funds_and_thaw_allows_retry(self):
        f=self.f;f.fund();f.freeze(f.vault,True);f.send([f.ix(1)],payer=f.relayer,ok=False)
        self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.vault),f.amount)
        f.freeze(f.vault,False);f.vm.expire_blockhash();f.send([f.ix(1)],payer=f.relayer);self.assertEqual(f.status(),2)
    def test_synthetic_inconsistent_supply_overflow_rejected(self):
        f=self.f;f.fund();f.mutate(f.claim,64,u64(2**64-1)) # impossible via honest mint; hostile state robustness only
        result=f.send([f.ix(1)],payer=f.relayer,ok=False)
        self.assertIn('Custom(4114)',str(result));self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.vault),f.amount)
        f.mutate(f.claim,64,u64(0));f.vm.expire_blockhash();f.send([f.ix(1)],payer=f.relayer)
    def test_compute_exhaustion_around_cpi_rolls_back_token_transfer(self):
        f=self.f;f.fund()
        # Execute the same real call at success-CU minus one: an actual VM budget failure, no mocked CPI.
        trial=f.vm.simulate_transaction(f.transaction([f.ix(1)],payer=f.relayer))
        used=trial.meta().compute_units_consumed()
        result=f.send([set_compute_unit_limit(used+149),f.ix(1)],payer=f.relayer,ok=False)
        self.assertIn('Tokenkeg',str(result));self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.vault),f.amount)
        self.assertEqual(f.balance(f.claim),0);f.send([f.ix(1)],payer=f.relayer)
    def test_closed_state_cannot_reinitialize_or_claim_twice(self):
        f=self.f;f.fund();f.vm.expire_blockhash()
        self.assertIn('Custom(4105)',str(f.send([f.ix(0)],[f.state],ok=False)));f.send([f.ix(1)],payer=f.relayer)
        f.vm.expire_blockhash();self.assertIn('Custom(4108)',str(f.send([f.ix(1)],payer=f.relayer,ok=False)))
        self.assertIn('Custom(4105)',str(f.send([f.ix(0)],[f.state],ok=False)))
        self.assertEqual(f.status(),2)
    def test_stale_blockhash_then_resign_same_identity(self):
        f=self.f;f.fund();tx=f.transaction([f.ix(1)],payer=f.relayer);f.vm.expire_blockhash()
        rejected=f.vm.send_transaction(tx)
        self.assertIsInstance(rejected,FailedTransactionMetadata);self.assertIn('BlockhashNotFound',str(rejected));self.assertEqual(f.status(),1)
        f.send([f.ix(1)],payer=f.relayer);self.assertEqual(f.status(),2)
    def test_atomic_two_instruction_conflict_rolls_back_first_transfer(self):
        f=self.f;f.fund();f.vm.warp_to_slot(f.deadline);f.send([f.ix(1),f.ix(2)],payer=f.relayer,ok=False)
        self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.claim),0);self.assertEqual(f.balance(f.vault),f.amount)
        f.send([f.ix(2)],payer=f.relayer)
    def test_funding_unsigned_state_and_delegate_or_close_authority(self):
        f=self.f
        ix=f.ix(0);metas=list(ix.accounts);metas[0]=Meta(f.state.pubkey(),False,True)
        unsigned=f.send([Instruction(PID,ix.data,metas)],ok=False)
        self.assertIn('Custom(4105)',str(unsigned))
        for offset in (72,129):
            f.vm.expire_blockhash() # Account mutation alone does not change the signed transaction identity.
            f.mutate(f.vault,offset,b'\x01\0\0\0');result=f.send([f.ix(0)],[f.state],ok=False)
            self.assertIn('Custom(4104)',str(result));self.assertNotIn('AlreadyProcessed',str(result))
            self.assertEqual(f.status(),0);self.assertEqual(f.balance(f.source),10_000_000);f.mutate(f.vault,offset,b'\0'*4)
        f.vm.expire_blockhash();f.fund()
    def test_distinct_valid_vault_and_mint_rejected_by_binding_not_alias(self):
        f=self.f;f.fund()
        vault=Keypair();f.send([f.create(vault,165,TOKEN),Instruction(TOKEN,b'\x12'+bytes(f.authority),[Meta(vault.pubkey(),False,True),Meta(f.mint.pubkey(),False,False)])],[vault])
        keys=f.keys.copy();keys[1]=vault.pubkey()
        self.assertIn('Custom(4108)',str(f.send([f.ix(1,keys=keys)],payer=f.relayer,ok=False)))
        mint=Keypair();f.send([f.create(mint,82,TOKEN),Instruction(TOKEN,b'\x14\x06'+bytes(f.payer.pubkey())+b'\0',[Meta(mint.pubkey(),False,True)])],[mint])
        keys=f.keys.copy();keys[2]=mint.pubkey()
        self.assertIn('Custom(4101)',str(f.send([f.ix(1,keys=keys)],payer=f.relayer,ok=False)))
        self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.vault),f.amount)
        f.send([f.ix(1)],payer=f.relayer)

if __name__=='__main__':unittest.main(verbosity=2)
