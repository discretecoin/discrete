"""Durable journal invariants adapted from the frozen v05 donor.

Recovery callbacks here model qualified adapter boundaries; these tests do not
assert chain truth, production custody, or detection of whole-storage rollback.
"""
import dataclasses,json,os,pathlib,sqlite3,subprocess,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from swap_runtime.journal import Admission,Journal,digest,protective_mode
from unittest.mock import patch
GOOD=Admission(11,60,120,120,600,True,True,True)
KEY=bytes([19])*32 # Deterministic laboratory key; never a user wallet key.

class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='journal-test-');self.path=pathlib.Path(self.tmp.name)/'state.db'
        self.j=Journal(self.path,KEY,True);self.j.register('s',{'network':'laboratory','foreign_vault':'v','xds_outpoint':'o','net':1000})
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def test_attempt_evidence_is_copied_authenticated_and_restorable(self):
        evidence={'source':'solana-blockhash-acquisition-v1','context_slot':123,'txid':'tid'}
        first=self.j.prepare('s','foreign-refund',b'signed','tid',evidence=evidence)
        evidence['context_slot']=999
        self.assertEqual(first['evidence']['context_slot'],123)
        self.assertEqual(first['evidence']['_aad_version'],1)
        snapshot=self.j.snapshot(pathlib.Path(self.tmp.name)/'metadata-snapshot.db')
        recovered=Journal.restore(snapshot,pathlib.Path(self.tmp.name)/'metadata-restored.db',KEY)
        try:
            self.assertEqual(recovered.intent('s','foreign-refund'),first)
            self.assertTrue(recovered.recovery_required())
        finally:recovered.close()
        with self.assertRaisesRegex(ValueError,'evidence immutable'):
            self.j.prepare('s','foreign-refund',b'signed','tid',evidence=evidence)

    def test_evidence_tamper_and_marker_downgrade_fail_read_and_restore(self):
        self.j.prepare('s','foreign-refund',b'signed','tid',evidence={'context_slot':123})
        self.j.db.execute('DROP TRIGGER immutable_attempt')
        for index,evidence in enumerate(({'context_slot':122,'_aad_version':1},{'context_slot':123},None)):
            self.j.db.execute('UPDATE attempts SET evidence=?',(None if evidence is None else json.dumps(evidence,sort_keys=True,separators=(',',':')).encode(),))
            with self.assertRaises(Exception):self.j.intent('s','foreign-refund')
            with self.assertRaises(Exception):
                Journal.restore(self.path,pathlib.Path(self.tmp.name)/('tampered-'+str(index)+'.db'),KEY)

    def test_new_evidence_is_bounded_dict_and_marker_is_internal(self):
        for evidence in ([],{'_aad_version':1},{'large':'x'*16384},{'bad':float('nan')}):
            with self.subTest(evidence_type=type(evidence).__name__),self.assertRaises((ValueError,TypeError)):
                self.j.prepare('s','foreign-refund',b'signed','tid',evidence=evidence)
            self.assertIsNone(self.j.intent('s','foreign-refund'))

    def test_legacy_unsealed_evidence_remains_readable_but_has_no_authentication_marker(self):
        self.j.prepare('s','foreign-refund',b'signed','tid')
        self.j.db.execute('DROP TRIGGER immutable_attempt')
        self.j.db.execute('UPDATE attempts SET evidence=?',(b'{"source":"legacy-renewal"}',))
        legacy=self.j.intent('s','foreign-refund')
        self.assertNotIn('_aad_version',legacy['evidence'])
        recovered=Journal.restore(self.path,pathlib.Path(self.tmp.name)/'legacy-evidence.db',KEY)
        try:self.assertEqual(recovered.intent('s','foreign-refund'),legacy)
        finally:recovered.close()
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
            child=subprocess.run([sys.executable,'-B',__file__,'--crash',str(path),stage],cwd=ROOT,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
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


class RecoveryJournalTests(unittest.TestCase):
    """Scenario tests for the internal trusted-validator journal boundary."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='runtime-journal-recovery-')
        self.root = pathlib.Path(self.tmp.name)
        self.path = self.root / 'live.db'
        self.terms = {'network': 'owned-fixture', 'xds_outpoint': 'funding:0',
                      'foreign_contract': 'pinned', 'amount_atoms': 1000}
        self.j = Journal(self.path, KEY, True)
        self.j.register('s', self.terms)
        self.sequence = []
        self.remote_state = 'unspent'

    def tearDown(self):
        self.j.close()
        self.tmp.cleanup()

    def snapshot(self, name='snapshot.db'):
        path = self.root / name
        self.j.snapshot(path)
        return path

    def restored(self, source=None, name='restored.db'):
        return Journal.restore(source or self.snapshot(), self.root / name, KEY)

    def prepare(self, kind='xds-claim'):
        return self.j.prepare('s', kind, ('signed-' + kind).encode(), kind + '-id')

    def validator(self, expected_kind):
        # Models a trusted adapter that independently checks exact contract/wire
        # and authoritative ledger state. The source label itself is not proof.
        def validate(intent, terms):
            self.sequence.append('validate')
            if terms != self.terms or intent['payload'] != ('signed-' + expected_kind).encode():
                raise ValueError('contract or signed artifact mismatch')
            if intent['txid'] != expected_kind + '-id':
                raise ValueError('wrong transaction identity')
            if self.remote_state != 'unspent':
                raise ValueError('settlement not admissible: ' + self.remote_state)
            return {'source': 'verified-chain-settlement-v1', 'kind': expected_kind,
                    'txid': intent['txid'], 'payload_hash': digest(intent['payload']),
                    'verified_terms_hash': digest(json.dumps(terms, sort_keys=True).encode())}
        return validate

    def admission(self):
        self.sequence.append('admission')
        return GOOD

    def send(self, journal):
        def transmit(raw, txid):
            self.sequence.append('send')
            other = Journal(journal.path, KEY)
            try:
                self.assertTrue(other.recovery_required())
                self.assertEqual(other.intent('s', txid[:-3])['stage'], 'attempt-started')
                self.assertGreater(other.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)
                if txid[:-3].endswith('claim'):
                    self.assertTrue(other.exposed('s'))
            finally:
                other.close()
            return raw, txid
        return transmit

    def test_recovered_xds_and_foreign_claim_require_validation_fresh_admission_before_send(self):
        for kind in ('xds-claim', 'foreign-claim'):
            with self.subTest(kind=kind):
                self.prepare(kind)
                snapshot = self.snapshot(kind + '.db')
                recovered = self.restored(snapshot, kind + '-restored.db')
                try:
                    self.sequence.clear()
                    result = recovered._broadcast_recovered('s', kind, self.send(recovered),
                                                            self.admission, self.validator(kind))
                    self.assertEqual(result, (('signed-' + kind).encode(), kind + '-id'))
                    self.assertEqual(self.sequence, ['validate', 'admission', 'send'])
                    self.assertTrue(recovered.exposed('s'))
                    self.assertTrue(recovered.recovery_required())
                finally:
                    recovered.close()

    def test_stale_backup_claim_cannot_use_prepare_time_admission(self):
        self.j.prepare('s', 'xds-claim', b'signed-xds-claim', 'xds-claim-id', admission=GOOD)
        recovered = self.restored()
        try:
            for current in (None, lambda: dataclasses.replace(GOOD, fresh_observations=False),
                            lambda: dataclasses.replace(GOOD, foreign_claim_remaining=0, incident=True)):
                with self.assertRaises(ValueError):
                    recovered._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('unsafe send'),
                                                    current, self.validator('xds-claim'))
                self.assertFalse(recovered.exposed('s'))
                self.assertEqual(recovered.intent('s', 'xds-claim')['stage'], 'prepared')
                self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)
        finally:
            recovered.close()

    def test_recovery_validation_failure_or_missing_provenance_cannot_commit_attempt(self):
        self.prepare()
        recovered = self.restored()
        try:
            validators = (None, lambda *_: None, lambda *_: True,
                          lambda *_: {'source': 'unverified-http-response'},
                          lambda *_: {'source': 'verified-chain-settlement-v2'})
            for validate in validators:
                with self.subTest(validate=validate), self.assertRaises(ValueError):
                    recovered._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('unqualified send'),
                                                    self.admission, validate)
                self.assertFalse(recovered.exposed('s'))
                self.assertEqual(recovered.intent('s', 'xds-claim')['stage'], 'prepared')
            def unavailable(*_):
                raise TimeoutError('fresh ledger observation unavailable')
            with self.assertRaises(TimeoutError):
                recovered._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('uncertain send'),
                                                self.admission, unavailable)
            self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)
        finally:
            recovered.close()

    def test_recovered_refund_requires_current_eligibility_without_disclosing_secret(self):
        for kind in ('xds-refund', 'foreign-refund'):
            self.prepare(kind)
            recovered = self.restored(self.snapshot(kind + '.db'), kind + '-restored.db')
            try:
                self.remote_state = 'refund-not-yet-eligible'
                with self.assertRaises(ValueError):
                    recovered._broadcast_recovered('s', kind, lambda *_: self.fail('early refund'),
                                                    None, self.validator(kind))
                self.remote_state = 'unspent'
                self.sequence.clear()
                recovered._broadcast_recovered('s', kind, self.send(recovered),
                    lambda: self.fail('refund does not require first-secret admission'), self.validator(kind))
                self.assertEqual(self.sequence, ['validate', 'send'])
                self.assertFalse(recovered.exposed('s'))
            finally:
                recovered.close()

    def test_old_backup_after_original_settlement_uses_current_validator_and_never_resends(self):
        self.prepare()
        old_snapshot = self.snapshot()
        self.j.broadcast('s', 'xds-claim', lambda *_: None, lambda: GOOD)
        self.remote_state = 'already-spent'
        recovered = self.restored(old_snapshot)
        try:
            self.assertFalse(recovered.exposed('s'))
            with self.assertRaisesRegex(ValueError, 'already-spent'):
                recovered._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('duplicate settlement'),
                                                self.admission, self.validator('xds-claim'))
            self.assertEqual(recovered.intent('s', 'xds-claim')['stage'], 'prepared')
            self.assertFalse(recovered.exposed('s'))
        finally:
            recovered.close()

    def test_recovered_lost_ack_retains_exact_bytes_and_sticky_exposure_on_restart(self):
        self.prepare()
        recovered = self.restored()
        seen = []
        def lost(raw, txid):
            seen.append((raw, txid))
            self.send(recovered)(raw, txid)
            raise TimeoutError('accepted remotely; acknowledgment lost')
        with self.assertRaises(TimeoutError):
            recovered._broadcast_recovered('s', 'xds-claim', lost, self.admission, self.validator('xds-claim'))
        path = recovered.path
        recovered.close()
        recovered = Journal(path, KEY)
        try:
            self.assertTrue(recovered.exposed('s'))
            self.assertEqual(recovered.intent('s', 'xds-claim')['status'], 'unknown')
            self.sequence.clear()
            recovered._broadcast_recovered('s', 'xds-claim', lambda *args: seen.append(args),
                lambda: self.fail('known exposed retry must retain protective capability'), self.validator('xds-claim'))
            self.assertEqual(seen[0], seen[1])
            self.assertEqual(self.sequence, ['validate'])
            self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 2)
            recovered.reconcile('s', 'xds-claim', 'xds-claim-id', 'confirmed')
            recovered.reconcile('s', 'xds-claim', 'xds-claim-id', 'unknown')
            self.assertTrue(recovered.exposed('s'))
        finally:
            recovered.close()

    def test_recovery_never_creates_identity_intent_funding_or_session_transmission(self):
        for kind in ('xds-claim', 'xds-fund', 'foreign-fund', 'fund', 'session'):
            self.prepare(kind)
        recovered = self.restored()
        try:
            with self.assertRaises(ValueError):
                recovered.register('new', self.terms)
            with self.assertRaises(ValueError):
                recovered.register('s', dict(self.terms, amount_atoms=2000))
            with self.assertRaises(ValueError):
                recovered.prepare('s', 'xds-refund', b'new-refund', 'new-id')
            with self.assertRaises(ValueError):
                recovered.prepare('s', 'xds-claim', b'different-claim', 'different-id')
            recovered.register('s', self.terms)
            self.assertEqual(recovered.prepare('s', 'xds-claim', b'signed-xds-claim', 'xds-claim-id')['attempt'], 0)
            for kind in ('xds-claim', 'xds-fund', 'foreign-fund', 'fund', 'session'):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    recovered.broadcast('s', kind, lambda *_: self.fail('unqualified restored broadcast'))
            for kind in ('xds-fund', 'foreign-fund', 'fund', 'session'):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    recovered._broadcast_recovered('s', kind, lambda *_: self.fail('forbidden recovered action'),
                                                    self.admission, self.validator(kind))
                with self.subTest(private_kind=kind), self.assertRaises(ValueError):
                    recovered._broadcast('s', kind, lambda *_: self.fail('private recovery bypass'),
                                         self.admission, self.validator(kind))
            self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)
        finally:
            recovered.close()

    def test_private_broadcast_cannot_transmit_encrypted_session_material(self):
        secret_material = b'private role key and paired recovery configuration'
        self.j.prepare('s', 'session', secret_material, 'session-id')
        self.assertEqual(self.j.intent('s', 'session')['payload'], secret_material)
        encrypted = self.j.db.execute('SELECT encrypted FROM attempts WHERE kind=?', ('session',)).fetchone()[0]
        self.assertNotIn(secret_material, encrypted)
        for broadcast in (lambda: self.j.broadcast('s', 'session', lambda *_: self.fail('session leaked')),
                          lambda: self.j._broadcast('s', 'session', lambda *_: self.fail('session leaked'), None)):
            with self.assertRaises(ValueError):
                broadcast()
        self.assertFalse(self.j.exposed('s'))
        self.assertEqual(self.j.intent('s', 'session')['stage'], 'prepared')

    def test_restored_provenance_and_recovery_evidence_are_immutable(self):
        self.prepare()
        recovered = self.restored()
        try:
            recovered._broadcast_recovered('s', 'xds-claim', lambda *_: None, self.admission, self.validator('xds-claim'))
            for sql in ('UPDATE journal_meta SET recovery_required=0', 'DELETE FROM journal_meta',
                        "UPDATE recovery_actions SET evidence='{}'", 'DELETE FROM recovery_actions'):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    recovered.db.execute(sql)
            self.assertTrue(recovered.recovery_required())
        finally:
            recovered.close()

    def test_attempt_started_marker_without_exposure_cannot_bypass_restored_admission(self):
        self.prepare()
        self.j.db.execute("UPDATE attempts SET stage='attempt-started'")
        recovered = self.restored()
        try:
            with self.assertRaises(ValueError):
                recovered._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('marker is not exposure'),
                                                None, self.validator('xds-claim'))
            self.assertFalse(recovered.exposed('s'))
            recovered._broadcast_recovered('s', 'xds-claim', self.send(recovered), self.admission,
                                            self.validator('xds-claim'))
        finally:
            recovered.close()

    def test_snapshot_is_wal_consistent_preserves_live_journal_and_rejects_overwrite(self):
        self.prepare()
        self.assertEqual(self.j.db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        path = self.snapshot()
        before = path.read_bytes()
        self.j.broadcast('s', 'xds-claim', lambda *_: None, lambda: GOOD)
        self.assertEqual(path.read_bytes(), before)
        snapshot = Journal(path, KEY)
        try:
            self.assertFalse(snapshot.exposed('s'))
            self.assertEqual(snapshot.intent('s', 'xds-claim')['stage'], 'prepared')
            self.assertEqual(snapshot.intent('s', 'xds-claim')['payload'], b'signed-xds-claim')
        finally:
            snapshot.close()
        with self.assertRaises(FileExistsError):
            self.j.snapshot(path)
        self.assertTrue(self.j.exposed('s'))

    def test_restore_preserves_source_is_exclusive_and_lock_survives_restart(self):
        self.prepare()
        source = self.snapshot()
        before = source.read_bytes()
        recovered = self.restored(source)
        path = recovered.path
        recovered.close()
        self.assertEqual(source.read_bytes(), before)
        recovered = Journal(path, KEY)
        try:
            self.assertTrue(recovered.recovery_required())
            self.assertEqual(protective_mode(recovered, 's', GOOD), 'reconcile-and-protect')
            with self.assertRaises(FileExistsError):
                Journal.restore(source, path, KEY)
        finally:
            recovered.close()

    def test_failed_restore_publication_keeps_source_and_leaves_no_usable_unlocked_copy(self):
        self.prepare()
        source = self.snapshot()
        before = source.read_bytes()
        target = self.root / 'interrupted.db'
        with patch('swap_runtime.journal.os.replace', side_effect=OSError('publication interrupted')):
            with self.assertRaises(OSError):
                Journal.restore(source, target, KEY)
        with self.assertRaises(ValueError):
            Journal(target, KEY)
        copies = list(self.root.glob('interrupted.db.restore-*.tmp'))
        self.assertEqual(len(copies), 1)
        temp = Journal(copies[0], KEY)
        try:
            self.assertTrue(temp.recovery_required())
        finally:
            temp.close()
        self.assertEqual(source.read_bytes(), before)

    def test_wrong_restore_key_cannot_publish_usable_database(self):
        self.prepare()
        source = self.snapshot()
        before = source.read_bytes()
        target = self.root / 'wrong-key.db'
        with self.assertRaises(Exception):
            Journal.restore(source, target, bytes([42]) * 32)
        with self.assertRaises(ValueError):
            Journal(target, KEY)
        self.assertEqual(source.read_bytes(), before)

    def test_schema2_migrates_only_into_new_recovery_locked_copy(self):
        self.prepare()
        source = self.snapshot()
        db = sqlite3.connect(source)
        db.executescript('''DROP TRIGGER sticky_recovery; DROP TRIGGER no_meta_delete;
            DROP TRIGGER immutable_recovery_action; DROP TRIGGER no_recovery_action_delete;
            DROP TABLE recovery_actions; DROP TABLE journal_meta; PRAGMA user_version=2;''')
        db.close()
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            Journal(source, KEY)
        recovered = self.restored(source)
        try:
            self.assertTrue(recovered.recovery_required())
            self.assertEqual(recovered.intent('s', 'xds-claim')['payload'], b'signed-xds-claim')
            self.assertEqual(recovered.db.execute('PRAGMA user_version').fetchone()[0], 3)
        finally:
            recovered.close()
        self.assertEqual(source.read_bytes(), before)

    def test_recovery_validator_checks_attempt_binding_and_cannot_rebind_terms(self):
        self.j.prepare('s', 'xds-claim', b'another-signed-transaction', 'xds-claim-id')
        recovered = self.restored()
        try:
            with self.assertRaisesRegex(ValueError, 'signed artifact mismatch'):
                recovered._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('unbound artifact'),
                                                self.admission, self.validator('xds-claim'))
            self.assertFalse(recovered.exposed('s'))
            self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)
        finally:
            recovered.close()

    def test_private_recovery_entrypoint_rejects_normal_live_journal(self):
        self.prepare()
        with self.assertRaises(ValueError):
            self.j._broadcast_recovered('s', 'xds-claim', lambda *_: self.fail('wrong provenance'),
                                        self.admission, self.validator('xds-claim'))
        self.assertFalse(self.j.exposed('s'))

    def test_strict_retry_requires_fresh_admission_despite_possible_exposure(self):
        self.prepare()
        seen = []
        def before_send(*_):
            raise TimeoutError('crash boundary after journal commit, before network send')
        with self.assertRaises(TimeoutError):
            self.j.broadcast('s', 'xds-claim', before_send, lambda: GOOD)
        self.assertTrue(self.j.exposed('s'))
        unsafe = dataclasses.replace(GOOD, foreign_claim_remaining=0, incident=True)
        with self.assertRaises(ValueError):
            self.j._broadcast('s', 'xds-claim', lambda *args: seen.append(args),
                              lambda: unsafe, require_fresh=True)
        self.assertEqual(seen, [])
        self.assertTrue(self.j.exposed('s'))
        self.assertEqual(self.j.intent('s', 'xds-claim')['stage'], 'attempt-started')
        self.j._broadcast('s', 'xds-claim', lambda *args: seen.append(args),
                          lambda: GOOD, require_fresh=True)
        self.assertEqual(seen, [(b'signed-xds-claim', 'xds-claim-id')])

    def test_strict_restored_retry_rolls_back_new_evidence_on_failed_admission(self):
        self.prepare()
        self.j.broadcast('s', 'xds-claim', lambda *_: None, lambda: GOOD)
        recovered = self.restored()
        try:
            unsafe = dataclasses.replace(GOOD, fresh_observations=False)
            with self.assertRaises(ValueError):
                recovered._broadcast('s', 'xds-claim', lambda *_: self.fail('unsafe retry'),
                    lambda: unsafe, self.validator('xds-claim'), require_fresh=True)
            self.assertTrue(recovered.exposed('s'))
            self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 0)
            self.assertEqual(recovered.intent('s', 'xds-claim')['payload'], b'signed-xds-claim')
        finally:
            recovered.close()

    def test_refund_strict_flag_does_not_turn_refund_into_first_disclosure(self):
        self.prepare('xds-refund')
        sent = []
        self.j._broadcast('s', 'xds-refund', lambda *args: sent.append(args),
                          lambda: self.fail('non-disclosing refund admission'), require_fresh=True)
        self.assertEqual(sent, [(b'signed-xds-refund', 'xds-refund-id')])
        self.assertFalse(self.j.exposed('s'))

    def test_real_process_exit_after_recovery_commit_and_after_send_preserves_provenance(self):
        for stage in ('committed', 'sent'):
            path = self.root / (stage + '-recovered.db')
            child = subprocess.run([sys.executable, '-B', __file__, '--recovery-crash', str(path), stage],
                                   cwd=ROOT, timeout=20,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.assertEqual(child.returncode, 73)
            remote = pathlib.Path(str(path) + '.remote')
            self.assertEqual(remote.exists(), stage == 'sent')
            recovered = Journal(path, KEY)
            try:
                self.assertTrue(recovered.recovery_required())
                self.assertTrue(recovered.exposed('s'))
                self.assertEqual(recovered.intent('s', 'xds-claim')['stage'], 'attempt-started')
                self.assertEqual(recovered.intent('s', 'xds-claim')['payload'], b'secret')
                self.assertEqual(recovered.db.execute('SELECT COUNT(*) FROM recovery_actions').fetchone()[0], 1)
                self.assertEqual(recovered.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            finally:
                recovered.close()


def recovery_crash(path, stage):
    live_path = path + '.live'
    live = Journal(live_path, KEY, True)
    live.register('s', {'test': 'qualified-recovery-commit'})
    live.prepare('s', 'xds-claim', b'secret', 'tid')
    snapshot = live.snapshot(path + '.backup')
    live.close()
    recovered = Journal.restore(snapshot, path, KEY)
    def transmit(raw, txid):
        if stage == 'sent':
            with open(path + '.remote', 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        os._exit(73)
    recovered._broadcast_recovered('s', 'xds-claim', transmit, lambda: GOOD,
        lambda intent, terms: {'source': 'verified-chain-settlement-v1', 'txid': intent['txid']})
    os._exit(74)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':crash(sys.argv[2],sys.argv[3])
    elif len(sys.argv)>1 and sys.argv[1]=='--recovery-crash':recovery_crash(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
