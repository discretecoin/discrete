"""Local coordinator kernel, schema 3. Prepared bytes are not a transmission attempt.
AES-GCM key custody and production chain observations remain adapter/wallet responsibilities.
First exposure requires fresh admission immediately before durable attempt-started, then send.
Schema-2 snapshots can only migrate into a new, recovery-locked journal. Local backup
restore does not prove journal freshness or detect an out-of-band rollback of all storage.
"""
import contextlib,hashlib,json,os,pathlib,sqlite3,uuid
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(b):return hashlib.sha256(b).hexdigest()

CLAIM_KINDS=frozenset(('claim','xds-claim','foreign-claim','xds-pair-claim'))
KINDS=CLAIM_KINDS|frozenset(('fund','xds-fund','foreign-fund','refund','xds-refund','foreign-refund','handoff-refund'))

def checked_kind(kind):
    if type(kind) is not str or kind not in KINDS:raise ValueError('unknown intent kind')

RECOVERY_SCHEMA='''
CREATE TABLE journal_meta(id INTEGER PRIMARY KEY CHECK(id=1), lineage TEXT NOT NULL,
  recovery_required INTEGER NOT NULL CHECK(recovery_required IN(0,1)), source_digest TEXT);
CREATE TABLE recovery_actions(id INTEGER PRIMARY KEY, swap TEXT NOT NULL, kind TEXT NOT NULL,
  attempt INTEGER NOT NULL, evidence BLOB NOT NULL,
  FOREIGN KEY(swap,kind,attempt) REFERENCES attempts(swap,kind,attempt));
CREATE TRIGGER sticky_recovery BEFORE UPDATE ON journal_meta
  BEGIN SELECT RAISE(ABORT,'journal provenance immutable'); END;
CREATE TRIGGER no_meta_delete BEFORE DELETE ON journal_meta
  BEGIN SELECT RAISE(ABORT,'journal provenance immutable'); END;
CREATE TRIGGER immutable_recovery_action BEFORE UPDATE ON recovery_actions
  BEGIN SELECT RAISE(ABORT,'recovery evidence immutable'); END;
CREATE TRIGGER no_recovery_action_delete BEFORE DELETE ON recovery_actions
  BEGIN SELECT RAISE(ABORT,'recovery evidence immutable'); END;
'''

@dataclass(frozen=True)
class Admission:
    confirmations: int
    xds_claim_budget: int
    xds_claim_remaining: int
    foreign_claim_budget: int
    foreign_claim_remaining: int
    verified_contracts: bool
    fresh_observations: bool
    fees_ready: bool
    incident: bool=False

    def allow_first_exposure(self):
        numbers=(self.confirmations,self.xds_claim_budget,self.xds_claim_remaining,self.foreign_claim_budget,self.foreign_claim_remaining)
        if any(type(x) is not int or x<0 for x in numbers):return False
        return self.confirmations>=11 and self.xds_claim_budget>0 and self.foreign_claim_budget>0 and \
          self.xds_claim_remaining>self.xds_claim_budget and self.foreign_claim_remaining>self.foreign_claim_budget and \
          self.verified_contracts is True and self.fresh_observations is True and self.fees_ready is True and self.incident is False

class Journal:
    def __init__(self,path,key,create=False):
        self.path=pathlib.Path(path);self.aead=AESGCM(key)
        if create:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        elif not self.path.is_file():raise FileNotFoundError('recovery journal absent; cannot assume unexposed')
        self.db=sqlite3.connect(str(self.path),timeout=15,isolation_level=None)
        if not create and self.db.execute('PRAGMA user_version').fetchone()[0]!=3:
            self.close();raise ValueError('journal schema; explicit recovery or migration required')
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA foreign_keys=ON')
        if create:
            self.db.executescript('''BEGIN IMMEDIATE;
              CREATE TABLE swaps(id TEXT PRIMARY KEY, terms BLOB NOT NULL, exposed INTEGER NOT NULL DEFAULT 0 CHECK(exposed IN(0,1)));
              CREATE TABLE intents(swap TEXT NOT NULL REFERENCES swaps(id), kind TEXT NOT NULL,
                exposes INTEGER NOT NULL CHECK(exposes IN(0,1)),
                PRIMARY KEY(swap,kind));
              CREATE TABLE attempts(swap TEXT NOT NULL, kind TEXT NOT NULL, attempt INTEGER NOT NULL,
                payload_hash TEXT NOT NULL, encrypted BLOB NOT NULL, txid TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN('unknown','confirmed','rejected')),
                stage TEXT NOT NULL CHECK(stage IN('prepared','attempt-started')), evidence BLOB,
                PRIMARY KEY(swap,kind,attempt), FOREIGN KEY(swap,kind) REFERENCES intents(swap,kind));
              CREATE TRIGGER immutable_terms BEFORE UPDATE OF terms ON swaps BEGIN SELECT RAISE(ABORT,'immutable terms'); END;
              CREATE TRIGGER sticky_exposure BEFORE UPDATE OF exposed ON swaps WHEN NEW.exposed<OLD.exposed BEGIN SELECT RAISE(ABORT,'exposure irreversible'); END;
              CREATE TRIGGER no_swap_delete BEFORE DELETE ON swaps BEGIN SELECT RAISE(ABORT,'recovery history immutable'); END;
              CREATE TRIGGER immutable_intent BEFORE UPDATE ON intents BEGIN SELECT RAISE(ABORT,'immutable intent'); END;
              CREATE TRIGGER immutable_attempt BEFORE UPDATE OF swap,kind,attempt,payload_hash,encrypted,txid,evidence ON attempts
                BEGIN SELECT RAISE(ABORT,'immutable attempt artifact'); END;
              CREATE TRIGGER sticky_attempt BEFORE UPDATE OF stage ON attempts
                WHEN OLD.stage='attempt-started' AND NEW.stage!='attempt-started'
                BEGIN SELECT RAISE(ABORT,'attempt irreversible'); END;
              CREATE TRIGGER no_attempt_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,'attempt history immutable'); END;
              CREATE TRIGGER no_intent_delete BEFORE DELETE ON intents BEGIN SELECT RAISE(ABORT,'intent history immutable'); END;
              '''+RECOVERY_SCHEMA+'''
              INSERT INTO journal_meta VALUES(1,lower(hex(randomblob(16))),0,NULL);
              PRAGMA user_version=3;
              COMMIT;''')
        if self.db.execute('PRAGMA user_version').fetchone()[0]!=3 or self.db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
            self.close();raise ValueError('journal integrity/schema; explicit recovery or migration required')
        meta=self.db.execute('SELECT recovery_required FROM journal_meta WHERE id=1').fetchall()
        if len(meta)!=1 or meta[0][0] not in (0,1):self.close();raise ValueError('journal provenance absent')
    @classmethod
    def restore(cls,snapshot,destination,key):
        """Consistent SQLite backup into a NEW recovery-only journal, preserving the source.

        The reserved destination remains an invalid empty file until the complete locked
        database is atomically published. A crash before publication cannot expose a
        seemingly normal journal. This API cannot detect manual whole-storage rollback.
        """
        source=pathlib.Path(snapshot).resolve();target=pathlib.Path(destination).resolve()
        if not source.is_file() or source==target:raise ValueError('distinct existing snapshot required')
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        temp=target.with_name(target.name+'.restore-'+uuid.uuid4().hex+'.tmp')
        fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        original=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)
        copied=sqlite3.connect(temp,isolation_level=None)
        try:
            original.backup(copied)
            copied.execute('PRAGMA journal_mode=DELETE');copied.execute('PRAGMA synchronous=FULL')
            version=copied.execute('PRAGMA user_version').fetchone()[0]
            if version not in (2,3) or copied.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise ValueError('unsupported or damaged recovery snapshot')
            aead=AESGCM(key)
            for swap,kind,number,h,enc,txid in copied.execute('SELECT swap,kind,attempt,payload_hash,encrypted,txid FROM attempts'):
                checked_kind(kind)
                payload=aead.decrypt(enc[:12],enc[12:],canonical([swap,kind,number,h,txid]))
                if digest(payload)!=h:raise ValueError('snapshot payload integrity')
            if copied.execute('PRAGMA foreign_key_check').fetchone() is not None:raise ValueError('snapshot references')
            snapshot_hash=digest(temp.read_bytes())
            if version==2:
                copied.executescript('BEGIN IMMEDIATE;'+RECOVERY_SCHEMA+
                  "INSERT INTO journal_meta VALUES(1,lower(hex(randomblob(16))),1,'"+snapshot_hash+"');PRAGMA user_version=3;COMMIT;")
            else:
                # Only this new unpublished copy changes provenance; the source remains read-only.
                copied.execute('BEGIN IMMEDIATE');copied.execute('DROP TRIGGER sticky_recovery')
                copied.execute('UPDATE journal_meta SET recovery_required=1,source_digest=? WHERE id=1',(snapshot_hash,))
                copied.execute("CREATE TRIGGER sticky_recovery BEFORE UPDATE ON journal_meta BEGIN SELECT RAISE(ABORT,'journal provenance immutable'); END;")
                copied.execute('COMMIT')
        finally:
            copied.close();original.close()
        with temp.open('r+b') as stream:os.fsync(stream.fileno())
        os.replace(temp,target)
        return cls(target,key)
    def close(self):self.db.close()
    def recovery_required(self):return bool(self.db.execute('SELECT recovery_required FROM journal_meta WHERE id=1').fetchone()[0])
    def terms(self,swap):
        row=self.db.execute('SELECT terms FROM swaps WHERE id=?',(swap,)).fetchone()
        if row is None:raise KeyError(swap)
        return json.loads(row[0])
    @contextlib.contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:yield;self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def register(self,swap,terms):
        encoded=canonical(terms)
        with self.transaction():
            old=self.db.execute('SELECT terms FROM swaps WHERE id=?',(swap,)).fetchone()
            if old and old[0]!=encoded:raise ValueError('swap identity reused with different terms')
            if old is None and self.recovery_required():raise ValueError('restored journal cannot register new swaps')
            self.db.execute('INSERT OR IGNORE INTO swaps(id,terms) VALUES(?,?)',(swap,encoded))
    def exposed(self,swap):
        row=self.db.execute('SELECT exposed FROM swaps WHERE id=?',(swap,)).fetchone()
        if row is None:raise KeyError(swap)
        return bool(row[0])
    def intent(self,swap,kind,attempt=None):
        checked_kind(kind)
        row=self.db.execute('''SELECT a.payload_hash,a.encrypted,a.txid,a.status,a.stage,a.attempt,i.exposes,a.evidence
          FROM attempts a JOIN intents i USING(swap,kind) WHERE a.swap=? AND a.kind=?
          AND (? IS NULL OR a.attempt=?) ORDER BY a.attempt DESC LIMIT 1''',(swap,kind,attempt,attempt)).fetchone()
        if not row:return None
        h,enc,txid,status,stage,number,exposes,evidence=row;aad=canonical([swap,kind,number,h,txid])
        payload=self.aead.decrypt(enc[:12],enc[12:],aad)
        if digest(payload)!=h:raise ValueError('payload integrity')
        return {'payload':payload,'txid':txid,'status':status,'stage':stage,'attempt':number,
                'exposes':bool(exposes),'evidence':None if evidence is None else json.loads(evidence)}
    def _insert_attempt(self,swap,kind,number,payload,txid,evidence=None):
        """Internal append primitive; qualified renewal is owned by the validating chain adapter."""
        h=digest(payload);nonce=os.urandom(12)
        enc=nonce+self.aead.encrypt(nonce,payload,canonical([swap,kind,number,h,txid]))
        self.db.execute('INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?)',
          (swap,kind,number,h,enc,txid,'unknown','prepared',None if evidence is None else canonical(evidence)))
    def prepare(self,swap,kind,payload,txid,exposes=False,admission=None):
        checked_kind(kind)
        if not isinstance(payload,bytes) or not payload or len(payload)>65536:raise ValueError('bounded artifact required')
        if type(exposes) is not bool or type(txid) is not str or not txid:raise ValueError('intent metadata')
        exposes=exposes or kind in CLAIM_KINDS
        with self.transaction():
            old=self.intent(swap,kind)
            if self.recovery_required() and old is None:raise ValueError('restored journal requires existing immutable intents')
            if old:
                if old['payload']!=payload or old['txid']!=txid or old['exposes']!=exposes:
                    raise ValueError('intent immutable; qualified chain adapter required for renewal')
            already=self.exposed(swap)
            # Optional early feedback; this snapshot never authorizes a later broadcast.
            if exposes and not already and admission is not None and not admission.allow_first_exposure():
                raise ValueError('early admission failed')
            if old:return old
            self.db.execute('INSERT INTO intents VALUES(?,?,?)',(swap,kind,int(exposes)))
            self._insert_attempt(swap,kind,0,payload,txid)
        return self.intent(swap,kind)
    def reconcile(self,swap,kind,txid,status):
        if status not in ('confirmed','rejected','unknown'):raise ValueError('status')
        with self.transaction():
            checked_kind(kind)
            row=self.db.execute('SELECT attempt FROM attempts WHERE swap=? AND kind=? AND txid=?',(swap,kind,txid)).fetchone()
            if row is None:raise ValueError('wrong transaction identity')
            self.intent(swap,kind,row[0]) # Verify stored authenticated artifact before a status change.
            # Confirmed -> unknown is valid after reorg. Sticky exposure remains unchanged.
            self.db.execute('UPDATE attempts SET status=? WHERE swap=? AND kind=? AND attempt=?',(status,swap,kind,row[0]))
    def broadcast(self,swap,kind,send,admission_supplier=None):
        if self.recovery_required():raise ValueError('restored journal requires qualified recovery adapter')
        return self._broadcast(swap,kind,send,admission_supplier)
    def _broadcast_recovered(self,swap,kind,send,admission_supplier,validate):
        """Internal adapter boundary; validation must read an owned authoritative local ledger."""
        if not self.recovery_required() or kind not in ('foreign-claim','foreign-refund'):
            raise ValueError('qualified recovery settlement only')
        return self._broadcast(swap,kind,send,admission_supplier,validate)
    def _broadcast(self,swap,kind,send,admission_supplier,validate=None):
        with self.transaction():
            intent=self.intent(swap,kind)
            if intent is None:raise ValueError('no durable intent')
            if self.recovery_required():
                if not callable(validate):raise ValueError('recovery validation absent')
                evidence=validate(intent,self.terms(swap))
                if type(evidence) is not dict or evidence.get('source')!='owned-litesvm-recovery-only':
                    raise ValueError('unsupported recovery adapter evidence')
                self.db.execute('INSERT INTO recovery_actions(swap,kind,attempt,evidence) VALUES(?,?,?,?)',
                  (swap,kind,intent['attempt'],canonical(evidence)))
            # Missing exposure is never inferred from a possibly stale attempt marker.
            if intent['exposes'] and not self.exposed(swap):
                admission=admission_supplier() if callable(admission_supplier) else None
                if not isinstance(admission,Admission) or not admission.allow_first_exposure():
                    raise ValueError('fresh first-exposure admission failed')
                self.db.execute('UPDATE swaps SET exposed=1 WHERE id=?',(swap,))
            if intent['stage']=='prepared':
                self.db.execute("UPDATE attempts SET stage='attempt-started' WHERE swap=? AND kind=? AND attempt=?",
                  (swap,kind,intent['attempt']))
        # COMMIT occurs before send. A crash from here on means possibly exposed, even if send never ran.
        # A timeout deliberately leaves unknown. Retries send exactly the stored artifact.
        return send(intent['payload'],intent['txid'])

def protective_mode(journal,swap,admission):
    if journal.recovery_required():return 'reconcile-and-protect'
    if journal.exposed(swap):return 'reconcile-and-protect'
    return 'eligible' if admission.allow_first_exposure() else 'wait-no-disclosure'
