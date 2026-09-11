"""One owner's fixed-terms settlement, exact retry and explicit backup recovery.

The foreign owner first claims XDS. The XDS owner learns the preimage from a
validated public XDS transaction and claims the foreign escrow. Funding remains
the native wallet / foreign contract setup operation; both funded contracts must
be observed independently before the first claim may leave this process.
"""
import hashlib
import json
import os
import time

from .common import SessionLock, canonical, hex_bytes, integer
from .journal import Journal, Admission
from .bitcoin import BitcoinAdapter


ROLES = {'xds-owner': frozenset(('xds-refund', 'foreign-claim')),
         'foreign-owner': frozenset(('xds-claim', 'foreign-refund'))}


def validate_config(config):
    fields = {'version', 'swap_id', 'role', 'foreign_chain', 'xds', 'foreign', 'policy'}
    if type(config) is not dict or set(config) != fields or type(config['version']) is not int or config['version'] != 1:
        raise ValueError('Unsupported session configuration')
    name = config['swap_id']
    if type(name) is not str or not 1 <= len(name) <= 80 or not name.isascii() or not name.replace('-', '').replace('_', '').isalnum():
        raise ValueError('Bounded ASCII swap identity required')
    if config['role'] not in ROLES or config['foreign_chain'] not in ('bitcoin', 'solana'):
        raise ValueError('Unsupported swap role or foreign chain')
    if type(config['xds']) is not dict or type(config['foreign']) is not dict:
        raise ValueError('Both immutable contract descriptions are required')
    xds_hash = hex_bytes(config['xds']['hashlock'], 32, 'XDS hashlock')
    if hex_bytes(config['foreign']['hashlock'], 32, 'foreign hashlock') != xds_hash:
        raise ValueError('Cross-chain hashlocks differ')
    policy = config['policy']
    if type(policy) is not dict or set(policy) != {'min_xds_confirmations', 'xds_claim_budget_blocks',
             'foreign_claim_budget_units', 'max_observation_seconds', 'solana_fee_attempt_reserve'}:
        raise ValueError('Explicit chain-native admission policy required')
    integer(policy['min_xds_confirmations'], 'XDS confirmations', 11, 100000)
    integer(policy['xds_claim_budget_blocks'], 'XDS claim budget', 2, 100000)
    integer(policy['foreign_claim_budget_units'], 'foreign claim budget', 1, 10000000)
    integer(policy['max_observation_seconds'], 'observation time', 1, 15)
    integer(policy['solana_fee_attempt_reserve'], 'fee reserve', 2, 10)
    return json.loads(canonical(config))


def _adapters(config, daemon, foreign, wallet):
    from .xds import XdsAdapter
    xds = XdsAdapter(daemon, config['xds'], wallet=wallet)
    if config['foreign_chain'] == 'bitcoin':
        remote = BitcoinAdapter(foreign, config['foreign'])
    else:
        from .solana import SolanaAdapter
        remote = SolanaAdapter(foreign, config['foreign'])
    return {'xds': xds, 'foreign': remote}


class Session:
    def __init__(self, path, key, swap_id, daemon, foreign, wallet=None, config=None):
        self.lock = SessionLock(path)
        self.journal = None
        try:
            # Constructors validate the entire configuration before any new file
            # becomes a registered session. Existing sessions load authenticated data.
            if config is not None:
                config = validate_config(config)
                if config['swap_id'] != swap_id:
                    raise ValueError('Session identity mismatch')
                self.adapters = _adapters(config, daemon, foreign, wallet)
            self.journal = Journal(path, key, create=config is not None)
            self.id = swap_id
            if config is not None:
                encoded = canonical(config)
                identity = hashlib.sha256(encoded).hexdigest()
                self.journal.register(swap_id, {'version': 1, 'config_sha256': identity})
                self.journal.prepare(swap_id, 'session', encoded, identity)
            stored = self.journal.intent(swap_id, 'session')
            if stored is None:
                raise ValueError('Authenticated session configuration missing')
            identity = hashlib.sha256(stored['payload']).hexdigest()
            if stored['txid'] != identity or self.journal.terms(swap_id) != {'version': 1, 'config_sha256': identity}:
                raise ValueError('Session terms differ from authenticated configuration')
            self.config = validate_config(json.loads(stored['payload']))
            if self.config['swap_id'] != swap_id:
                raise ValueError('Stored session identity differs')
            if config is None:
                self.adapters = _adapters(self.config, daemon, foreign, wallet)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.journal is not None:
            self.journal.close()
            self.journal = None
        self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _adapter(self, kind):
        if kind not in ROLES[self.config['role']]:
            raise ValueError('Settlement kind does not belong to this owner')
        return self.adapters['xds' if kind.startswith('xds-') else 'foreign']

    def observe(self):
        start = time.monotonic()
        xds = self.adapters['xds'].observe()
        foreign = self.adapters['foreign'].observe()
        # A second XDS read limits time spent on the foreign snapshot and catches
        # changed spentness/tip; these remain sequential trusted-node observations.
        last = self.adapters['xds'].observe()
        elapsed = time.monotonic() - start
        policy = self.config['policy']
        numeric = all(type(v) is int and v >= 0 for v in
                      (last.get('height'), last.get('confirmations'), foreign.get('height')))
        stable = (xds.get('height') == last.get('height') and
                  type(last.get('tip_hash')) is str and xds.get('tip_hash') == last.get('tip_hash') and
                  xds.get('block_hash') == last.get('block_hash') and
                  xds.get('status') == last.get('status') == 'unspent')
        contracts = (stable and last.get('final') is True and foreign.get('status') == 'unspent'
                     and foreign.get('final') is True)
        fees = last.get('fees_ready') is True
        if self.config['foreign_chain'] == 'bitcoin':
            deadline = self.config['foreign']['refund_height']
            # The signed Bitcoin spend uses the fixed embedded fee and exact
            # principal; readiness here does not promise a future market feerate.
            fees = fees and foreign.get('status') == 'unspent'
        else:
            deadline = self.config['foreign']['deadline_slot']
            contracts = contracts and foreign.get('claim_ready') is True
            balance, fee = foreign.get('payer_balance_lamports'), foreign.get('fee_lamports')
            fees = (fees and foreign.get('fees_ready') is True and type(balance) is int
                    and type(fee) is int and fee > 0 and balance >= policy['solana_fee_attempt_reserve'] * fee)
        admission = Admission(
            last.get('confirmations', 0) if numeric else 0,
            policy['xds_claim_budget_blocks'],
            max(0, self.config['xds']['refund_height'] - last['height']) if numeric else 0,
            policy['foreign_claim_budget_units'],
            max(0, deadline - foreign['height']) if numeric else 0,
            bool(contracts and numeric and last['confirmations'] >= policy['min_xds_confirmations']),
            0 <= elapsed <= policy['max_observation_seconds'], bool(fees))
        return admission, {'xds': last, 'foreign': foreign, 'observation_seconds': elapsed,
                           'allow_first_exposure': admission.allow_first_exposure()}

    def _public_proof(self):
        # Exposure-to-network evidence is authenticated separately from the
        # conservative attempt-started marker. A crashed pre-send attempt alone
        # must never authorize a later first disclosure after the budgets expire.
        rows = self.journal.db.execute('SELECT kind,attempt,evidence FROM recovery_actions WHERE swap=? ORDER BY id', (self.id,))
        for kind, attempt, encoded in rows:
            evidence = json.loads(encoded)
            if evidence.get('source') != 'verified-public-transaction-v1':
                continue
            sealed = bytes.fromhex(evidence['sealed'])
            raw = self.journal.aead.decrypt(sealed[:12], sealed[12:], canonical([self.id, kind, attempt, 'public']))
            checked = json.loads(raw)
            if checked.get('hashlock') != self.config['xds']['hashlock']:
                raise ValueError('Public witness binding differs from session')
            return True
        return False

    def _record_public(self, kind, intent, txid, observed_raw):
        nonce = os.urandom(12)
        sealed = nonce + self.journal.aead.encrypt(nonce,
            canonical({'hashlock': self.config['xds']['hashlock'], 'public_txid': txid,
                       'public_raw_sha256': hashlib.sha256(observed_raw).hexdigest()}),
            canonical([self.id, kind, intent['attempt'], 'public']))
        with self.journal.transaction():
            self.journal.db.execute('UPDATE swaps SET exposed=1 WHERE id=?', (self.id,))
            self.journal.db.execute('INSERT INTO recovery_actions(swap,kind,attempt,evidence) VALUES(?,?,?,?)',
                (self.id, kind, intent['attempt'], canonical({'source': 'verified-public-transaction-v1', 'sealed': sealed.hex()})))

    def prepare(self, kind, key, secret=None, public_xds_txid=None):
        adapter = self._adapter(kind)
        if self.journal.intent(self.id, kind) is not None:
            raise ValueError('Existing immutable intent: reconcile, retry, or qualified Solana renewal')
        if self.journal.recovery_required():
            raise ValueError('Recovery journal cannot create an absent intent; use retained original journal or native owner recovery')
        public = None
        if kind == 'foreign-claim':
            if secret is not None or not public_xds_txid:
                raise ValueError('Foreign claim requires an observed public XDS claim, not an injected private preimage')
            public = self.adapters['xds'].verify_public_spend(public_xds_txid, 'xds-claim')
            if 'secret' not in public or 'raw' not in public:
                raise ValueError('No validated public XDS claim witness')
            secret = hex_bytes(public['secret'], 32, 'public preimage')
        elif public_xds_txid is not None:
            raise ValueError('Public witness argument is only for the foreign claim')
        raw, txid = adapter.prepare(kind, key, secret)
        adapter.validate(kind, raw, txid)
        evidence = adapter.preparation_evidence(kind, raw, txid) if (
            self.config['foreign_chain'] == 'solana' and kind.startswith('foreign-')) else None
        self.journal.prepare(self.id, kind, raw, txid, evidence=evidence)
        intent = self.journal.intent(self.id, kind)
        if public is not None:
            self._record_public(kind, intent, public_xds_txid, bytes.fromhex(public['raw']))
        return self.describe(kind)

    def describe(self, kind):
        self._adapter(kind)
        intent = self.journal.intent(self.id, kind)
        if intent is None:
            return {'kind': kind, 'prepared': False}
        return {key: intent[key] for key in ('txid', 'status', 'stage', 'attempt')} | {'kind': kind, 'prepared': True}

    def reconcile(self, kind):
        adapter = self._adapter(kind)
        intent = self.journal.intent(self.id, kind)
        if intent is None:
            raise ValueError('No durable settlement intent')
        adapter.validate(kind, intent['payload'], intent['txid'])
        result = adapter.receipt(kind, intent['payload'], intent['txid'])
        status = result.get('status')
        if (kind.endswith('-claim') and status in ('pending', 'confirmed')
                and result.get('publicly_observed') is True and not self._public_proof()):
            # Adapter receipt binds the exact full signed wire to an observed
            # public transaction, independently of current confirmation depth.
            self._record_public(kind, intent, intent['txid'], intent['payload'])
        normalized = 'confirmed' if status == 'confirmed' and result.get('final') is True else 'unknown'
        if status == 'failed' and result.get('final') is True:
            normalized = 'rejected'
        self.journal.reconcile(self.id, kind, intent['txid'], normalized)
        return result

    def broadcast(self, kind):
        adapter = self._adapter(kind)
        receipt = self.reconcile(kind)
        if receipt.get('status') in ('confirmed', 'pending', 'conflict', 'failed'):
            return {'action': 'reconciled', 'receipt': receipt}
        intent = self.journal.intent(self.id, kind)
        proof = self._public_proof()
        if kind == 'foreign-claim' and not proof:
            # A crash between prepare and witness persistence can be retried by
            # re-observing the public candidate, never by assuming a secret leaked.
            raise ValueError('Public XDS witness must be re-observed before foreign claim retry')

        def validate(current, terms):
            adapter.validate(kind, current['payload'], current['txid'])
            observation = adapter.observe()
            if observation.get('status') != 'unspent':
                raise ValueError('No currently unspent exact settlement contract')
            if kind.endswith('-refund') and observation.get('refund_eligible') is not True:
                raise ValueError('Refund has not matured in the observed chain')
            return {'source': 'verified-chain-settlement-v1', 'kind': kind,
                    'txid': current['txid'], 'payload_sha256': hashlib.sha256(current['payload']).hexdigest(),
                    'contract_config_sha256': terms['config_sha256'], 'observation': observation}

        # Validate normal/recovered paths identically. Recovery repeats the same
        # validation inside the journal transaction before its audit record commits.
        validate(intent, self.journal.terms(self.id))
        ack = self.journal._broadcast(self.id, kind,
              lambda raw, txid: adapter.send(kind, raw, txid),
              lambda: self.observe()[0], validate=validate, require_fresh=not proof)
        return {'action': 'submitted', 'txid': ack, 'settlement': 'unknown-until-reconciled'}

    def reobserve_public_xds(self, kind, candidate_txid):
        self._adapter(kind)
        if not kind.endswith('-claim'):
            raise ValueError('Public witness is only associated with a claim intent')
        intent = self.journal.intent(self.id, kind)
        if intent is None:
            raise ValueError('Existing claim intent required')
        public = self.adapters['xds'].verify_public_spend(candidate_txid, 'xds-claim')
        if 'secret' not in public or 'raw' not in public:
            raise ValueError('No validated public XDS claim')
        checked = self._adapter(kind).validate(kind, intent['payload'], intent['txid'])
        if checked.get('secret') != public['secret']:
            raise ValueError('Stored claim differs from public preimage')
        self._record_public(kind, intent, candidate_txid, bytes.fromhex(public['raw']))
        return {'public_exposure_observed': True, 'candidate_txid': candidate_txid}

    def renew_solana(self, kind, key):
        if self.config['foreign_chain'] != 'solana' or not kind.startswith('foreign-'):
            raise ValueError('Only a Solana settlement blockhash may be renewed')
        adapter = self._adapter(kind)
        old = self.journal.intent(self.id, kind)
        if old is None:
            raise ValueError('Existing immutable intent required')
        stored = old['evidence']
        if not isinstance(stored, dict) or stored.get('_aad_version') != 1:
            raise ValueError('Authenticated blockhash acquisition provenance required for renewal')
        provenance = ({k: v for k, v in stored.items() if k != '_aad_version'}
                      if stored.get('source') == 'solana-blockhash-acquisition-v1' else stored.get('preparation'))
        if not isinstance(provenance, dict) or provenance.get('source') != 'solana-blockhash-acquisition-v1':
            raise ValueError('Authenticated blockhash acquisition provenance required for renewal')
        checked = adapter.validate(kind, old['payload'], old['txid'])
        secret = bytes.fromhex(checked['secret']) if 'secret' in checked else None
        raw, txid = adapter.prepare(kind, key, secret)
        preparation = adapter.preparation_evidence(kind, raw, txid)
        with self.journal.transaction():
            evidence = adapter.renew(kind, old['payload'], old['txid'], raw, txid, provenance)
            if evidence.get('status') != 'renewable':
                raise ValueError('No rooted renewal evidence')
            evidence = dict(evidence, preparation=preparation)
            self.journal._insert_attempt(self.id, kind, old['attempt'] + 1, raw, txid, evidence)
        return self.describe(kind)

    def snapshot(self, destination):
        return self.journal.snapshot(destination)
