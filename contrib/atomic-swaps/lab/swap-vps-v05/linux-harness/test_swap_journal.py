import dataclasses,json,os,pathlib,sqlite3,subprocess,sys,tempfile,unittest
from swap_journal import Admission,Journal,digest,protective_mode
ROOT=pathlib.Path(__file__).resolve().parent
GOOD=Admission(11,60,120,120,600,True,True,True)
KEY=bytes([19])*32 # Deterministic laboratory key; never a user wallet key.

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT,prefix='journal-test-');self.path=pathlib.Path(self.tmp.name)/'state.db'
        self.j=Journal(self.path,KEY,True);self.j.register('s',{'network':'laboratory','foreign_vault':'v','xds_outpoint':'o','net':1000})
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def test_timeout_retry_exact_artifact_without_second_funding(self):
        raw=b'fixed funding artifact';self.j.prepare('s','fund',raw,'id1');seen=[]
        def lost(b,tid):seen.append((b,tid));raise TimeoutError('accepted remotely, response lost')
        with self.assertRaises(TimeoutError):self.j.broadcast('s','fund',lost)
        self.assertEqual(self.j.intent('s','fund')['status'],'unknown')
        with self.assertRaises(ValueError):self.j.prepare('s','fund',b'different','id2')
        self.j.broadcast('s','fund',lambda b,t:seen.append((b,t)));self.assertEqual(seen[0],seen[1])
    def test_exposure_commits_before_sender_and_survives_reorg_restart(self):
        self.j.prepare('s','claim',b'secret-bearing','tid',True,GOOD)
        self.assertFalse(self.j.exposed('s'));self.assertEqual(self.j.intent('s','claim')['stage'],'prepared')
        def observe(b,t):
            other=Journal(self.path,KEY)
            try:self.assertTrue(other.exposed('s'))
            finally:other.close()
        self.j.broadcast('s','claim',observe,admission_supplier=lambda:GOOD)
        self.j.reconcile('s','claim','tid','confirmed');self.j.reconcile('s','claim','tid','unknown')
        self.j.close();self.j=Journal(self.path,KEY);self.assertTrue(self.j.exposed('s'))
        self.assertEqual(protective_mode(self.j,'s',dataclasses.replace(GOOD,incident=True)),'reconcile-and-protect')
    def test_low_confirmations_stale_freeze_fee_and_budget_guards(self):
        for changes in ({'confirmations':10},{'fresh_observations':False},{'fees_ready':False},{'incident':True},
                        {'verified_contracts':False},{'xds_claim_remaining':60},{'foreign_claim_remaining':120},{'xds_claim_budget':0}):
            with self.assertRaises(ValueError):self.j.prepare('s','claim',b'preimage','tid',True,dataclasses.replace(GOOD,**changes))
            self.assertFalse(self.j.exposed('s'));self.assertIsNone(self.j.intent('s','claim'))
    def test_ciphertext_wrong_key_corruption_and_missing_file_fail_closed(self):
        raw=b'private preimage data';self.j.prepare('s','claim',raw,'tid',True,GOOD)
        encrypted=self.j.db.execute('SELECT encrypted FROM attempts').fetchone()[0];self.assertNotIn(raw,encrypted)
        bad=Journal(self.path,bytes([20])*32)
        try:
            with self.assertRaises(Exception):bad.intent('s','claim')
        finally:bad.close()
        # Simulate corrupted storage while deliberately bypassing the SQL immutability guard.
        self.j.db.execute('DROP TRIGGER immutable_attempt')
        self.j.db.execute('UPDATE attempts SET encrypted=?',(encrypted[:-1]+bytes([encrypted[-1]^1]),))
        with self.assertRaises(Exception):self.j.intent('s','claim')
        with self.assertRaises(FileNotFoundError):Journal(self.path.with_name('absent.db'),KEY)
    def test_no_rebinding_no_exposure_reset_and_wrong_reconciliation(self):
        self.j.prepare('s','claim',b'secret','id',True,GOOD)
        self.j.broadcast('s','claim',lambda *_:None,admission_supplier=lambda:GOOD)
        with self.assertRaises(ValueError):self.j.register('s',{'network':'wrong'})
        with self.assertRaises(sqlite3.IntegrityError):self.j.db.execute("UPDATE swaps SET exposed=0 WHERE id='s'")
        with self.assertRaises(ValueError):self.j.reconcile('s','claim','another','confirmed')
        self.assertTrue(self.j.exposed('s'))
    def test_claim_kind_cannot_omit_exposure_gate(self):
        self.j.prepare('s','claim',b'secret','id',False)
        with self.assertRaises(ValueError):self.j.broadcast('s','claim',lambda *_:self.fail('must not send'))
        self.assertFalse(self.j.exposed('s'))
        self.j.broadcast('s','claim',lambda *_:None,admission_supplier=lambda:GOOD);self.assertTrue(self.j.exposed('s'))
    def test_stale_prepare_does_not_authorize_first_broadcast(self):
        self.j.prepare('s','claim',b'secret','id',admission=GOOD)
        unsafe=dataclasses.replace(GOOD,foreign_claim_remaining=0,incident=True)
        sent=[];calls=[]
        def current():calls.append(True);return unsafe
        with self.assertRaises(ValueError):self.j.broadcast('s','claim',lambda *x:sent.append(x),current)
        self.assertEqual(len(calls),1);self.assertFalse(sent);self.assertFalse(self.j.exposed('s'))
        self.assertEqual(self.j.intent('s','claim')['stage'],'prepared')
        self.j.broadcast('s','claim',lambda *x:sent.append(x),lambda:GOOD)
        self.assertEqual(len(sent),1);self.assertTrue(self.j.exposed('s'))
    def test_prepared_restart_still_requires_fresh_admission(self):
        self.j.prepare('s','foreign-claim',b'secret','id',admission=GOOD)
        self.j.close();self.j=Journal(self.path,KEY)
        self.assertFalse(self.j.exposed('s'))
        with self.assertRaises(ValueError):self.j.broadcast('s','foreign-claim',lambda *_:self.fail('must not send'))
        self.j.broadcast('s','foreign-claim',lambda *_:None,lambda:GOOD)
    def test_attempted_retry_protects_despite_new_incident(self):
        self.j.prepare('s','foreign-claim',b'secret','id')
        seen=[]
        def lost(raw,txid):seen.append((raw,txid));raise TimeoutError('response lost')
        with self.assertRaises(TimeoutError):self.j.broadcast('s','foreign-claim',lost,lambda:GOOD)
        self.j.close();self.j=Journal(self.path,KEY)
        self.j.broadcast('s','foreign-claim',lambda *x:seen.append(x),lambda:self.fail('retry admission must not stop protection'))
        self.assertEqual(seen[0],seen[1]);self.assertTrue(self.j.exposed('s'))
    def test_unknown_kinds_fail_closed_and_refund_does_not_disclose(self):
        for kind in ('btc-claim','cliam','foreign_claim','funding-retry',None):
            with self.assertRaises(ValueError):self.j.prepare('s',kind,b'secret','id')
        self.j.prepare('s','refund',b'refund','rid');self.j.broadcast('s','refund',lambda *_:None)
        self.assertFalse(self.j.exposed('s'));self.assertEqual(self.j.intent('s','refund')['stage'],'attempt-started')
    def test_admission_exception_and_attempt_history_guards(self):
        self.j.prepare('s','claim',b'secret','id')
        def broken():raise TimeoutError('observation failed')
        with self.assertRaises(TimeoutError):self.j.broadcast('s','claim',lambda *_:self.fail('must not send'),broken)
        self.assertFalse(self.j.exposed('s'));self.assertEqual(self.j.intent('s','claim')['stage'],'prepared')
        self.j.broadcast('s','claim',lambda *_:None,lambda:GOOD)
        for sql in ("UPDATE attempts SET stage='prepared'",'DELETE FROM attempts',"UPDATE attempts SET txid='changed'",'DELETE FROM intents'):
            with self.assertRaises(sqlite3.IntegrityError):self.j.db.execute(sql)
    def test_schema_one_is_not_silently_reinterpreted(self):
        old=self.path.with_name('old.db');db=sqlite3.connect(old);db.execute('PRAGMA user_version=1');db.close()
        with self.assertRaisesRegex(ValueError,'migration'):Journal(old,KEY)
    def test_process_kill_before_and_after_commit_and_after_rpc_side_effect(self):
        for stage in ('uncommitted','prepared','committed','sent'):
            path=self.path.with_name(stage+'.db')
            child=subprocess.run([sys.executable,'-B',__file__,'--crash',str(path),stage],cwd=ROOT)
            self.assertEqual(child.returncode,73)
            remote=pathlib.Path(str(path)+'.remote')
            self.assertEqual(remote.exists(),stage=='sent')
            if stage=='sent':self.assertEqual(remote.read_bytes(),b'secret')
            j=Journal(path,KEY)
            try:
                self.assertEqual(j.exposed('s'),stage in ('committed','sent'))
                if stage!='uncommitted':self.assertEqual(j.intent('s','claim')['payload'],b'secret')
                else:self.assertIsNone(j.intent('s','claim'))
                if stage=='prepared':self.assertEqual(j.intent('s','claim')['stage'],'prepared')
                if stage in ('committed','sent'):self.assertEqual(j.intent('s','claim')['stage'],'attempt-started')
            finally:j.close()

def crash(path,stage):
    j=Journal(path,KEY,True);j.register('s',{'test':'kill'})
    if stage=='uncommitted':
        j.db.execute('BEGIN IMMEDIATE');j.db.execute("UPDATE swaps SET exposed=1 WHERE id='s'");os._exit(73)
    j.prepare('s','claim',b'secret','tid',True,GOOD)
    if stage=='prepared':os._exit(73)
    if stage=='sent':
        def remote(b,t):
            with open(path+'.remote','wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
            os._exit(73)
        j.broadcast('s','claim',remote,lambda:GOOD)
    if stage=='committed':j.broadcast('s','claim',lambda *_:os._exit(73),lambda:GOOD)
    os._exit(73)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':crash(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
