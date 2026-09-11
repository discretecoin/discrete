"""Real signed SBF/SPL attempts through the corrected journal and owned LiteSVM proof adapter."""
import dataclasses,pathlib,sqlite3,tempfile,unittest
from test_solana_vm import Fixture,Instruction,Meta,Keypair,FailedTransactionMetadata
from solders.hash import Hash
from solders.signature import Signature
from solders.transaction import Transaction
from solders.compute_budget import set_compute_unit_limit
from swap_journal import Journal,Admission
from solana_journal_adapter import LiteSvmEscrowRecovery
ROOT=pathlib.Path(__file__).resolve().parent
GOOD=Admission(11,60,120,120,600,True,True,True)
KEY=bytes([61])*32

class SolanaJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT,prefix='solana-journal-')
        self.path=pathlib.Path(self.tmp.name)/'journal.db'
        self.j=Journal(self.path,KEY,True);self.j.register('s',{'profile':'immutable-local-SBF'})
        self.f=Fixture();self.f.fund();self.adapter=LiteSvmEscrowRecovery(self.f.vm)
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def prepare(self,op=1):
        f=self.f;tx=f.transaction([f.ix(op)],payer=f.relayer)
        kind='foreign-claim' if op==1 else 'foreign-refund'
        self.j.prepare('s',kind,bytes(tx),str(tx.signatures[0]))
        return kind,tx
    def renew(self,kind,payload):
        old=self.j.intent('s',kind)
        return self.adapter.renew(self.j,'s',kind,payload,expected_previous_txid=old['txid'] if old else 'absent')
    def send(self,raw,tid):
        from solders.transaction import Transaction
        tx=Transaction.from_bytes(raw);self.assertEqual(str(tx.signatures[0]),tid)
        return self.f.vm.send_transaction(tx)
    def test_expired_prepared_attempt_renews_without_disclosing_then_claims(self):
        kind,old=self.prepare();self.f.vm.expire_blockhash()
        fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        renewal=self.renew(kind,bytes(fresh))
        self.assertEqual(renewal['attempt'],1);self.assertFalse(self.j.exposed('s'))
        self.assertEqual(self.j.intent('s',kind,0)['payload'],bytes(old))
        self.assertEqual(self.j.intent('s',kind,0)['status'],'rejected')
        self.assertEqual(renewal['evidence']['old_txid'],str(old.signatures[0]))
        self.assertEqual(renewal['evidence']['source'],'owned-litesvm-only')
        self.j.close();self.j=Journal(self.path,KEY)
        with self.assertRaises(ValueError):self.j.broadcast('s',kind,self.send)
        result=self.j.broadcast('s',kind,self.send,lambda:GOOD)
        self.assertNotIsInstance(result,FailedTransactionMetadata);self.assertEqual(self.f.status(),2)
    def test_expired_attempted_claim_renews_and_protective_retry_keeps_exposure(self):
        kind,old=self.prepare();self.f.vm.expire_blockhash()
        result=self.j.broadcast('s',kind,self.send,lambda:GOOD)
        self.assertIsInstance(result,FailedTransactionMetadata);self.assertTrue(self.j.exposed('s'))
        self.j.reconcile('s',kind,str(old.signatures[0]),'rejected')
        fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        with self.assertRaises(ValueError):self.j.prepare('s',kind,bytes(fresh),str(fresh.signatures[0]))
        self.renew(kind,bytes(fresh))
        self.assertTrue(self.j.exposed('s'));self.assertEqual(self.j.intent('s',kind,0)['stage'],'attempt-started')
        self.assertNotIsInstance(self.j.broadcast('s',kind,self.send),FailedTransactionMetadata)
        self.assertEqual(self.f.status(),2)
        with self.assertRaises(sqlite3.IntegrityError):self.j.db.execute('DELETE FROM attempts WHERE attempt=0')
    def test_rejected_label_or_changed_blockhash_is_not_expiry_proof(self):
        kind,old=self.prepare();self.j.reconcile('s',kind,str(old.signatures[0]),'rejected')
        fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer,blockhash=Hash.new_unique())
        with self.assertRaisesRegex(ValueError,'not proven expired'):self.renew(kind,bytes(fresh))
        self.assertEqual(self.j.intent('s',kind)['attempt'],0);self.assertEqual(self.f.status(),1)
    def test_semantic_redirect_role_secret_and_payer_changes_are_rejected(self):
        kind,old=self.prepare();self.f.vm.expire_blockhash()
        f=self.f;keys=f.keys.copy();keys[3]=f.source.pubkey()
        candidates=[f.transaction([f.ix(1,keys=keys)],payer=f.relayer),
          f.transaction([f.ix(1,b'\x01'+b'\x33'*32)],payer=f.relayer),
          f.transaction([f.ix(1)],payer=f.payer),f.transaction([f.ix(2)],payer=f.relayer)]
        ix=f.ix(1);metas=list(ix.accounts);metas[5]=Meta(metas[5].pubkey,False,False)
        candidates.append(f.transaction([Instruction(ix.program_id,ix.data,metas)],payer=f.relayer))
        for candidate in candidates:
            with self.assertRaises(ValueError):self.renew(kind,bytes(candidate))
        self.assertEqual(self.j.intent('s',kind)['attempt'],0);self.assertFalse(self.j.exposed('s'))
    def test_extra_instruction_funding_and_malformed_artifact_fail_closed(self):
        kind,old=self.prepare();self.f.vm.expire_blockhash();f=self.f
        candidates=[b'bad',bytes(old)+b'\0',bytes(f.transaction([set_compute_unit_limit(200_000),f.ix(1)],payer=f.relayer)),
          bytes(f.transaction([f.ix(0)],signers=[f.state]))]
        for raw in candidates:
            with self.assertRaises(ValueError):self.renew(kind,raw)
        with self.assertRaises(ValueError):self.renew('foreign-fund',bytes(old))
    def test_successfully_executed_old_attempt_cannot_be_renewed(self):
        kind,old=self.prepare()
        self.assertNotIsInstance(self.j.broadcast('s',kind,self.send,lambda:GOOD),FailedTransactionMetadata)
        self.f.vm.expire_blockhash();fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        with self.assertRaisesRegex(ValueError,'already executed'):self.renew(kind,bytes(fresh))
        self.assertEqual(self.j.intent('s',kind)['attempt'],0)
    def test_consumed_state_blocks_renewal_even_without_old_signature_history(self):
        kind,old=self.prepare();self.f.vm.expire_blockhash()
        other=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        self.assertNotIsInstance(self.f.vm.send_transaction(other),FailedTransactionMetadata)
        self.f.vm.expire_blockhash();fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        self.assertIsNone(self.f.vm.get_transaction(old.signatures[0]))
        with self.assertRaisesRegex(ValueError,'unconsumed'):self.renew(kind,bytes(fresh))
        self.assertEqual(self.j.intent('s',kind)['attempt'],0)
    def test_expired_refund_renews_only_when_replacement_really_executes(self):
        kind,old=self.prepare(2);self.f.vm.expire_blockhash()
        fresh=self.f.transaction([self.f.ix(2)],payer=self.f.relayer)
        with self.assertRaisesRegex(ValueError,'does not currently execute'):self.renew(kind,bytes(fresh))
        self.f.vm.warp_to_slot(self.f.deadline);self.renew(kind,bytes(fresh))
        self.assertNotIsInstance(self.j.broadcast('s',kind,self.send),FailedTransactionMetadata)
        self.assertEqual(self.f.status(),3);self.assertFalse(self.j.exposed('s'))
    def test_current_blockhash_and_unchanged_attempt_are_checked(self):
        kind,old=self.prepare()
        with self.assertRaisesRegex(ValueError,'unchanged'):self.renew(kind,bytes(old))
        self.f.vm.expire_blockhash()
        stale=self.f.transaction([self.f.ix(1)],payer=self.f.relayer,blockhash=Hash.new_unique())
        with self.assertRaisesRegex(ValueError,'does not currently execute'):self.renew(kind,bytes(stale))
        self.assertEqual(self.j.intent('s',kind)['attempt'],0)
    def test_original_transaction_identity_is_bound_to_proof(self):
        old=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        self.j.prepare('s','foreign-claim',bytes(old),'different-transaction-id')
        self.f.vm.expire_blockhash();fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        with self.assertRaisesRegex(ValueError,'identity mismatch'):
            self.renew('foreign-claim',bytes(fresh))
        self.assertEqual(self.j.intent('s','foreign-claim')['attempt'],0)
    def test_missing_signature_and_frozen_destination_do_not_authorize_renewal(self):
        kind,old=self.prepare();self.f.vm.expire_blockhash()
        fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        unsigned=Transaction.populate(fresh.message,[Signature.default()])
        with self.assertRaisesRegex(ValueError,'signed legacy'):self.renew(kind,bytes(unsigned))
        self.f.freeze(self.f.claim,True)
        with self.assertRaisesRegex(ValueError,'does not currently execute'):self.renew(kind,bytes(fresh))
        self.assertEqual(self.j.intent('s',kind)['attempt'],0);self.assertEqual(self.f.status(),1)
        self.f.freeze(self.f.claim,False);self.renew(kind,bytes(fresh))
        self.assertNotIsInstance(self.j.broadcast('s',kind,self.send,lambda:GOOD),FailedTransactionMetadata)

if __name__=='__main__':unittest.main(verbosity=2)
