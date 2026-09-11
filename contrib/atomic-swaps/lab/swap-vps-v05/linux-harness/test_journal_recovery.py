"""Owned local-ledger stale-backup recovery and real subprocess append interruption.
These checks do not establish production RPC truth, key custody or rollback detection.
"""
import dataclasses,hashlib,json,os,pathlib,sqlite3,subprocess,sys,tempfile,unittest
from unittest.mock import patch
from test_solana_vm import Fixture,FailedTransactionMetadata
from swap_journal import Admission,Journal,digest,protective_mode
from solana_journal_adapter import LiteSvmEscrowRecovery
ROOT=pathlib.Path(__file__).resolve().parent
KEY=bytes([71])*32
GOOD=Admission(11,60,120,120,600,True,True,True)

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT,prefix='recovery-test-');self.root=pathlib.Path(self.tmp.name)
        self.f=Fixture();self.f.fund();self.adapter=LiteSvmEscrowRecovery(self.f.vm)
        self.path=self.root/'live.db';self.j=Journal(self.path,KEY,True)
        self.tx=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        self.binding=self.adapter.contract_binding(bytes(self.tx))
        self.j.register('s',{'solana_contract':self.binding})
        self.j.prepare('s','foreign-claim',bytes(self.tx),str(self.tx.signatures[0]))
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def snapshot(self,name='snapshot.db'):
        path=self.root/name;copy=sqlite3.connect(path)
        try:self.j.db.backup(copy)
        finally:copy.close()
        return path
    def restore(self,snapshot=None):return Journal.restore(snapshot or self.snapshot(),self.root/'restored.db',KEY)
    def test_stale_unexposed_snapshot_does_not_inherit_protective_send_permission(self):
        restored=self.restore()
        try:
            self.assertTrue(restored.recovery_required());self.assertFalse(restored.exposed('s'))
            self.assertEqual(protective_mode(restored,'s',GOOD),'reconcile-and-protect')
            with self.assertRaises(ValueError):restored.broadcast('s','foreign-claim',lambda *_:self.fail('unqualified send'))
            unsafe=dataclasses.replace(GOOD,foreign_claim_remaining=0,incident=True)
            with self.assertRaises(ValueError):self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:unsafe)
            self.assertEqual(self.f.status(),1);self.assertFalse(restored.exposed('s'))
            self.assertEqual(restored.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0],0)
            result=self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:GOOD)
            self.assertNotIsInstance(result,FailedTransactionMetadata);self.assertEqual(self.f.status(),2)
            self.assertTrue(restored.exposed('s'));self.assertTrue(restored.recovery_required())
            evidence=json.loads(restored.db.execute('SELECT evidence FROM recovery_actions').fetchone()[0])
            self.assertEqual(evidence['source'],'owned-litesvm-recovery-only')
        finally:restored.close()
    def test_snapshot_before_original_settlement_cannot_send_again(self):
        snapshot=self.snapshot()
        result=self.j.broadcast('s','foreign-claim',lambda raw,tid:self.f.vm.send_transaction(self.tx),lambda:GOOD)
        self.assertNotIsInstance(result,FailedTransactionMetadata);self.assertEqual(self.f.status(),2)
        restored=self.restore(snapshot)
        try:
            self.assertFalse(restored.exposed('s'))
            with self.assertRaisesRegex(ValueError,'already consumed'):
                self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:GOOD)
            self.assertEqual(self.f.balance(self.f.claim),self.f.amount)
        finally:restored.close()
    def test_recovery_blocks_new_identity_new_funding_and_funding_replay(self):
        self.j.prepare('s','foreign-fund',b'funding-artifact','funding-id')
        restored=self.restore()
        try:
            for action in (lambda:restored.register('new',{'other':'swap'}),
              lambda:restored.prepare('s','xds-fund',b'new-funding','new-id'),
              lambda:restored.broadcast('s','foreign-fund',lambda *_:self.fail('funding send')),
              lambda:self.adapter.broadcast_recovered(restored,'s','foreign-fund')):
                with self.assertRaises(ValueError):action()
            self.assertEqual(restored.prepare('s','foreign-claim',bytes(self.tx),str(self.tx.signatures[0]))['attempt'],0)
            with self.assertRaises(sqlite3.IntegrityError):restored.db.execute('UPDATE journal_meta SET recovery_required=0')
        finally:restored.close()
    def test_recovered_refund_executes_without_secret_disclosure(self):
        refund=self.f.transaction([self.f.ix(2)],payer=self.f.relayer)
        self.j.prepare('s','foreign-refund',bytes(refund),str(refund.signatures[0]))
        restored=self.restore()
        try:
            with self.assertRaises(ValueError):self.adapter.broadcast_recovered(restored,'s','foreign-refund')
            self.f.vm.warp_to_slot(self.f.deadline)
            self.assertNotIsInstance(self.adapter.broadcast_recovered(restored,'s','foreign-refund'),FailedTransactionMetadata)
            self.assertEqual(self.f.status(),3);self.assertFalse(restored.exposed('s'))
        finally:restored.close()
    def test_missing_or_changed_immutable_terms_never_authorize_recovery(self):
        wrong=self.root/'wrong.db';j=Journal(wrong,KEY,True)
        try:
            j.register('s',{'solana_contract':dict(self.binding,amount=self.f.amount+1)})
            j.prepare('s','foreign-claim',bytes(self.tx),str(self.tx.signatures[0]))
        finally:j.close()
        restored=self.restore(wrong)
        try:
            with self.assertRaisesRegex(ValueError,'immutable terms'):
                self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:GOOD)
            self.assertFalse(restored.exposed('s'));self.assertEqual(self.f.status(),1)
        finally:restored.close()
    def test_expired_snapshot_can_renew_then_complete_with_fresh_admission(self):
        restored=self.restore();self.f.vm.expire_blockhash()
        try:
            fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
            self.adapter.renew(restored,'s','foreign-claim',bytes(fresh),expected_previous_txid=str(self.tx.signatures[0]))
            self.assertFalse(restored.exposed('s'))
            with self.assertRaises(ValueError):self.adapter.broadcast_recovered(restored,'s','foreign-claim')
            self.assertNotIsInstance(self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:GOOD),FailedTransactionMetadata)
            self.assertEqual(self.f.status(),2);self.assertEqual(restored.intent('s','foreign-claim')['attempt'],1)
        finally:restored.close()
    def test_known_attempt_started_snapshot_keeps_protective_retry(self):
        def lost(*_):raise TimeoutError('unknown response after durable attempt-started')
        with self.assertRaises(TimeoutError):self.j.broadcast('s','foreign-claim',lost,lambda:GOOD)
        restored=self.restore()
        try:
            self.assertTrue(restored.exposed('s'))
            result=self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:self.fail('must not stop known exposed protection'))
            self.assertNotIsInstance(result,FailedTransactionMetadata);self.assertEqual(self.f.status(),2)
        finally:restored.close()
    def test_restore_preserves_source_rejects_overwrite_and_persists_lock(self):
        source=self.snapshot();before=source.read_bytes();restored=self.restore(source)
        restored.close();self.assertEqual(source.read_bytes(),before)
        restored=Journal(self.root/'restored.db',KEY)
        try:
            self.assertTrue(restored.recovery_required())
            with self.assertRaises(FileExistsError):Journal.restore(source,self.root/'restored.db',KEY)
        finally:restored.close()
    def test_schema2_restore_migrates_only_new_copy_and_bad_key_fails_closed(self):
        source=self.snapshot();db=sqlite3.connect(source)
        db.executescript('''DROP TRIGGER sticky_recovery; DROP TRIGGER no_meta_delete;
          DROP TRIGGER immutable_recovery_action; DROP TRIGGER no_recovery_action_delete;
          DROP TABLE recovery_actions; DROP TABLE journal_meta; PRAGMA user_version=2;''');db.close()
        before=source.read_bytes()
        with self.assertRaises(ValueError):Journal(source,KEY)
        self.assertEqual(source.read_bytes(),before)
        restored=self.restore(source)
        try:
            self.assertTrue(restored.recovery_required());self.assertEqual(restored.db.execute('PRAGMA user_version').fetchone()[0],3)
            self.assertEqual(restored.intent('s','foreign-claim')['payload'],bytes(self.tx))
        finally:restored.close()
        self.assertEqual(source.read_bytes(),before)
        old=sqlite3.connect(source);self.assertEqual(old.execute('PRAGMA user_version').fetchone()[0],2);old.close()
        bad=self.root/'wrong-key.db'
        with self.assertRaises(Exception):Journal.restore(source,bad,bytes([72])*32)
        with self.assertRaises(ValueError):Journal(bad,KEY)
    def test_failure_before_publication_leaves_invalid_destination_and_locked_temp(self):
        source=self.snapshot();before=source.read_bytes();target=self.root/'interrupted.db'
        with patch('swap_journal.os.replace',side_effect=OSError('publication interrupted')):
            with self.assertRaises(OSError):Journal.restore(source,target,KEY)
        with self.assertRaises(ValueError):Journal(target,KEY)
        temps=list(self.root.glob('interrupted.db.restore-*.tmp'));self.assertEqual(len(temps),1)
        temp=Journal(temps[0],KEY)
        try:self.assertTrue(temp.recovery_required())
        finally:temp.close()
        self.assertEqual(source.read_bytes(),before)
    def test_inconsistent_attempt_marker_cannot_replace_explicit_exposure_admission(self):
        # Corrupted logical metadata can pass SQLite integrity_check. It is not evidence
        # that a secret was ever transmitted, and must not bypass the fresh admission gate.
        self.j.db.execute("UPDATE attempts SET stage='attempt-started'")
        restored=self.restore()
        try:
            self.assertFalse(restored.exposed('s'))
            with self.assertRaises(ValueError):self.adapter.broadcast_recovered(restored,'s','foreign-claim')
            self.assertEqual(self.f.status(),1)
            self.assertNotIsInstance(self.adapter.broadcast_recovered(restored,'s','foreign-claim',lambda:GOOD),FailedTransactionMetadata)
        finally:restored.close()
    def test_repeated_renewal_cas_idempotency_and_lost_append_response(self):
        old=self.j.intent('s','foreign-claim');history=[old['payload']]
        for number in range(1,4):
            self.f.vm.expire_blockhash();fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
            renewed=self.adapter.renew(self.j,'s','foreign-claim',bytes(fresh),expected_previous_txid=old['txid'])
            retried=self.adapter.renew(self.j,'s','foreign-claim',bytes(fresh),expected_previous_txid=old['txid'])
            self.assertEqual(renewed,retried);self.assertEqual(renewed['attempt'],number)
            history.append(bytes(fresh));old=renewed
        self.f.vm.expire_blockhash();fresh=self.f.transaction([self.f.ix(1)],payer=self.f.relayer)
        with self.assertRaisesRegex(ValueError,'stale renewal'):
            self.adapter.renew(self.j,'s','foreign-claim',bytes(fresh),expected_previous_txid=str(self.tx.signatures[0]))
        self.adapter.renew(self.j,'s','foreign-claim',bytes(fresh),expected_previous_txid=old['txid'])
        for number,payload in enumerate(history):self.assertEqual(self.j.intent('s','foreign-claim',number)['payload'],payload)
        result=self.j.broadcast('s','foreign-claim',lambda raw,tid:self.f.vm.send_transaction(fresh),lambda:GOOD)
        self.assertNotIsInstance(result,FailedTransactionMetadata);self.assertEqual(self.f.status(),2)
    def test_real_process_exit_during_append_has_only_old_or_complete_new_attempt(self):
        for stage in ('before-insert','after-insert','after-commit'):
            path=self.root/(stage+'.db')
            child=subprocess.run([sys.executable,'-B',__file__,'--append-crash',str(path),stage],cwd=ROOT)
            self.assertEqual(child.returncode,73)
            evidence=json.loads(path.with_suffix('.expected.json').read_text())
            j=Journal(path,KEY)
            try:
                self.assertTrue(j.exposed('s'));old=j.intent('s','foreign-claim',0)
                self.assertEqual(digest(old['payload']),evidence['old_hash']);self.assertEqual(old['stage'],'attempt-started')
                self.assertEqual(j.intent('s','foreign-claim')['attempt'],1 if stage=='after-commit' else 0)
                self.assertEqual(old['status'],'rejected' if stage=='after-commit' else 'unknown')
                self.assertEqual(j.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                if stage=='after-commit':
                    fresh=j.intent('s','foreign-claim',1);self.assertEqual(fresh['stage'],'prepared')
                    self.assertEqual(digest(fresh['payload']),evidence['new_hash'])
                    self.assertEqual(fresh['evidence']['old_txid'],old['txid'])
            finally:j.close()

def append_crash(path,stage):
    class InterruptJournal(Journal):
        def _insert_attempt(self,swap,kind,number,payload,txid,evidence=None):
            if number==1 and stage=='before-insert':os._exit(73)
            super()._insert_attempt(swap,kind,number,payload,txid,evidence)
            if number==1 and stage=='after-insert':os._exit(73)
    f=Fixture();f.fund();adapter=LiteSvmEscrowRecovery(f.vm)
    j=InterruptJournal(path,KEY,True);j.register('s',{'local':'append crash'})
    old=f.transaction([f.ix(1)],payer=f.relayer);j.prepare('s','foreign-claim',bytes(old),str(old.signatures[0]))
    f.vm.expire_blockhash();j.broadcast('s','foreign-claim',lambda raw,tid:f.vm.send_transaction(old),lambda:GOOD)
    fresh=f.transaction([f.ix(1)],payer=f.relayer)
    with pathlib.Path(path).with_suffix('.expected.json').open('w') as stream:
        json.dump({'old_hash':digest(bytes(old)),'new_hash':digest(bytes(fresh))},stream);stream.flush();os.fsync(stream.fileno())
    adapter.renew(j,'s','foreign-claim',bytes(fresh),expected_previous_txid=str(old.signatures[0]))
    os._exit(73)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--append-crash':append_crash(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
