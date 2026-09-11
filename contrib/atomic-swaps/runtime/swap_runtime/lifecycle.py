"""One independently keyed owner, from agreed unfunded terms to settlement.

The signed mailbox is an untrusted transport. Only validating chain adapters
establish funding; only the native witness scanner establishes public secrets.
All signed transactions are durable and backed up before transmission. Restore
is permanently protective: no new deposits or first native secret disclosure.
An operator must dedicate each funding wallet to this active owner operation.
External wallet spends can invalidate a draft; they never authorize reselection.
"""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import time
import uuid

from .common import canonical, hex_bytes, new_private_file, private_read, strict_json, sync_directory
from .journal import Journal
from .lifecycle_store import OwnerStore
from .lifecycle_settlement import OwnerSession
from .owner_protocol import PublicExchange, offer_hash, owner_key, validate_offer, validate_owner_key, schedule_ready
from .xds import XdsAdapter
from .xds_funding import XdsFundingAdapter
from .xds_discovery import XdsWitnessDiscovery
from .bitcoin import BitcoinAdapter, Contract as BitcoinContract
from .bitcoin_funding import BitcoinFundingAdapter


def _session_key(key):
    return hashlib.sha256(b'xds-owner-settlement-key-v1\0' + key).digest()


def _no_wallet(*_):
    raise ValueError('Funding wallet transport not configured for this owner')


class _CheckpointedAdapter:
    def __init__(self, session, adapter):
        self.session, self.adapter = session, adapter

    def __getattr__(self, name):
        return getattr(self.adapter, name)

    def send(self, kind, raw, txid):
        # Journal commits exposure/attempt-started before invoking this callback.
        # The authoritative paired checkpoint must include those exact markers.
        self.session.owner._checkpoint()
        if kind == 'xds-claim' and not self.session._public_proof():
            admission, _ = self.session.observe()
            if not admission.allow_first_exposure():
                raise ValueError('First exposure admission changed during external checkpoint')
        return self.adapter.send(kind, raw, txid)


class _GatedSession(OwnerSession):
    def _adapter(self, kind):
        adapter = super()._adapter(kind)
        owner = getattr(self, 'owner', None)
        if owner is not None and owner.checkpoint_sink is not None:
            return _CheckpointedAdapter(self, adapter)
        return adapter

    def observe(self):
        admission, facts = super().observe()
        # Called inside Journal's last pre-send admission, not merely at prepare.
        ready = self.owner._first_claim_ready(facts)
        admission = replace(admission, incident=not ready)
        facts['allow_first_exposure'] = admission.allow_first_exposure()
        return admission, facts


class Owner:
    def __init__(self, directory, key, daemon, foreign, wallet=None, foreign_wallet=None,
                 exchange_dir=None, backup_dir=None, offer=None, role=None, credentials=None,
                 durable_funding=False, checkpoint_sink=None):
        self.directory = Path(directory).absolute()
        self.store = self.session = None
        self.key = key
        self.daemon, self.foreign, self.wallet = daemon, foreign, wallet
        self.foreign_wallet = foreign_wallet
        if type(durable_funding) is not bool or (checkpoint_sink is not None and not callable(checkpoint_sink)):
            raise ValueError('Explicit durable preparation and checkpoint callback required')
        self.checkpoint_sink = checkpoint_sink
        try:
            create = None
            if offer is not None:
                offer = validate_offer(offer)
                if role not in ('xds-owner', 'foreign-owner') or exchange_dir is None or backup_dir is None:
                    raise ValueError('Explicit owner role, mailbox and backup directory required')
                credentials = self._credentials(offer, role, credentials)
                self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                create = dict(version=1, offer=offer, role=role, credentials=credentials,
                              exchange_dir=str(Path(exchange_dir).absolute()), backup_dir=str(Path(backup_dir).absolute()))
                if durable_funding:
                    create.update(version=2, durable_funding=True)
            elif role is not None or credentials is not None:
                raise ValueError('Existing owner uses its authenticated immutable identity')
            self.store = OwnerStore(self.directory / 'owner.db', key, create=create)
            config = self.store.get('config')
            fields = {'version', 'offer', 'role', 'credentials', 'exchange_dir', 'backup_dir'}
            if (type(config) is not dict or type(config.get('version')) is not int
                    or config['version'] not in (1, 2)
                    or set(config) != fields | ({'durable_funding'} if config['version'] == 2 else set())
                    or (config['version'] == 2 and config['durable_funding'] is not True)):
                raise ValueError('Unsupported owner configuration')
            self.durable_funding = config['version'] == 2
            offline_recovery = (self.store.recovery_required()
                                and self.store.get('freshness.offline-recovery') is True)
            if self.store.get('freshness.binding') is not None and self.checkpoint_sink is None and not offline_recovery:
                raise ValueError('Anchored owner requires its external checkpoint coordinator')
            self.offer, self.role = validate_offer(config['offer']), config['role']
            self.credentials = self._credentials(self.offer, self.role, config['credentials'])
            self.peer = 'foreign-owner' if self.role == 'xds-owner' else 'xds-owner'
            self.chain = self.offer['foreign_chain']
            self.signer = owner_key(self.chain, self.credentials['foreign_key'])
            self.rho = bytes.fromhex(self.credentials['xds_rho'])
            self.exchange = PublicExchange(exchange_dir or config['exchange_dir'], self.offer)
            self.backup_dir = Path(backup_dir or config['backup_dir']).absolute()
            if self.backup_dir == self.directory or self.directory in self.backup_dir.parents:
                raise ValueError('Backup directory must be outside the live owner directory')
            self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.native_funding = XdsFundingAdapter(daemon, self.offer['xds'], wallet)
            if self.chain == 'bitcoin':
                self.foreign_funding = BitcoinFundingAdapter(foreign, foreign_wallet or _no_wallet, self.offer['foreign'])
            else:
                from .solana_funding import SolanaFundingAdapter
                self.foreign_funding = SolanaFundingAdapter(foreign, self.offer['foreign'])
            self._open_session(create=False)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _credentials(offer, role, values):
        required = {'xds_rho', 'foreign_key'} | ({'secret'} if role == 'foreign-owner' else set())
        optional = {'solana_accounts'} if offer['foreign_chain'] == 'solana' and role == 'foreign-owner' else set()
        if type(values) is not dict or not required <= set(values) or set(values) - required - optional:
            raise ValueError('Exact private owner credentials required')
        hex_bytes(values['xds_rho'], 32, 'native role seed')
        validate_owner_key(offer, role, owner_key(offer['foreign_chain'], values['foreign_key']))
        if role == 'foreign-owner' and hashlib.sha256(hex_bytes(values['secret'], 32, 'owner secret')).hexdigest() != offer['xds']['hashlock']:
            raise ValueError('Owner secret differs from agreed hashlock')
        if 'solana_accounts' in values:
            from solders.keypair import Keypair
            if type(values['solana_accounts']) is not dict or set(values['solana_accounts']) != {'state', 'vault', 'refund'}:
                raise ValueError('Exact retained auxiliary account keys required')
            for value in values['solana_accounts'].values():
                Keypair.from_bytes(hex_bytes(value, 64, 'auxiliary keypair'))
        import json
        return json.loads(canonical(values))

    def close(self):
        if self.session is not None:
            self.session.close()
            self.session = None
        if self.store is not None:
            self.store.close()
            self.store = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def status(self):
        # Local authenticated state only. A previous observation is not live finality.
        return dict(swap_id=self.offer['swap_id'], role=self.role, foreign_chain=self.chain,
                    recovery_required=self.store.recovery_required(),
                    last_action=self.store.get('last_action', 'initialized'),
                    own_funding_retained=self.store.get('funding.attempt') is not None,
                    paired=self.session is not None,
                    last_settlement=self.store.get('settlement.status'))

    def _result(self, action, **values):
        self.store.put('last_action', action)
        return dict(action=action, swap_id=self.offer['swap_id'], role=self.role, **values)

    def backup(self, destination):
        companion = None
        if self.session is not None:
            temporary = self.directory / ('snapshot-' + uuid.uuid4().hex)
            try:
                self.session.snapshot(temporary)
                companion = private_read(temporary, 64 * 1024 * 1024)
            finally:
                if temporary.exists():
                    temporary.unlink()
        self.store.backup(destination, companion=companion)
        return Path(destination)

    def _checkpoint(self):
        path = self.backup(self.backup_dir / (offer_hash(self.offer) + '-' + self.role + '-' + uuid.uuid4().hex + '.backup'))
        if self.checkpoint_sink is not None:
            self.checkpoint_sink(path)
        return path

    @classmethod
    def restore(cls, snapshot, directory, key):
        target = Path(directory).absolute()
        target.mkdir(mode=0o700, parents=True, exist_ok=False)
        restored = OwnerStore.restore(snapshot, target / 'owner.db', key)
        if restored['companion'] is not None:
            with OwnerStore(target / 'owner.db', key) as state:
                config = state.get('config')
                offer = validate_offer(config['offer'])
                expected = dict(version=1, swap_id=offer['swap_id'], role=config['role'],
                    foreign_chain=offer['foreign_chain'], xds=state.get('terms.xds'),
                    foreign=state.get('terms.foreign'), policy=offer['policy'])
                if (expected['xds'] is None or expected['foreign'] is None
                        or state.get('settlement.config', expected) != expected):
                    raise ValueError('Owner backup does not bind its paired companion')
            temporary = target / 'companion.snapshot'
            new_private_file(temporary, restored['companion'])
            try:
                companion = Journal.restore(temporary, target / 'settlement.db', _session_key(key))
                try:
                    from .session import validate_config
                    saved = companion.intent(offer['swap_id'], 'session')
                    digest = hashlib.sha256(canonical(expected)).hexdigest()
                    if (saved is None or saved['txid'] != digest
                            or validate_config(strict_json(saved['payload'])) != expected
                            or companion.terms(offer['swap_id']) != {'version': 1, 'config_sha256': digest}
                            or companion.db.execute('SELECT COUNT(*) FROM swaps').fetchone()[0] != 1):
                        raise ValueError('Restored settlement companion differs from owner agreement')
                finally:
                    companion.close()
            finally:
                temporary.unlink()
        return dict(action='restored-protective', recovery_required=True, directory=str(target))

    def _open_session(self, create=True):
        xds, foreign = self.store.get('terms.xds'), self.store.get('terms.foreign')
        if xds is None or foreign is None:
            if (self.directory / 'settlement.db').exists():
                raise ValueError('Orphan settlement companion')
            return
        config = dict(version=1, swap_id=self.offer['swap_id'], role=self.role, foreign_chain=self.chain,
                      xds=xds, foreign=foreign, policy=self.offer['policy'])
        prior = self.store.get('settlement.config')
        path = self.directory / 'settlement.db'
        if prior is not None and prior != config:
            raise ValueError('Paired owner terms differ from retained session')
        if not create and not path.exists():
            return
        if not path.exists() and self.store.recovery_required():
            # A stale backup with authenticated contracts may create protective
            # intents, but a fresh journal must first pass explicit restore.
            temporary = self.directory / ('recovery-seed-' + uuid.uuid4().hex)
            with OwnerSession(temporary, _session_key(self.key), self.offer['swap_id'], self.daemon,
                              self.foreign, self.wallet, config=config) as seed:
                snapshot = self.directory / ('recovery-snapshot-' + uuid.uuid4().hex)
                seed.snapshot(snapshot)
            Journal.restore(snapshot, path, _session_key(self.key)).close()
            temporary.unlink()
            snapshot.unlink()
        elif prior is not None and not path.exists():
            raise ValueError('Settlement journal missing; restore an authenticated backup')
        elif not path.exists():
            # Publish a complete, closed SQLite file before committing its owner
            # pointer. A crash on either side leaves an unambiguous retry state.
            temporary = self.directory / ('session-stage-' + uuid.uuid4().hex)
            with OwnerSession(temporary, _session_key(self.key), self.offer['swap_id'], self.daemon,
                              self.foreign, self.wallet, config=config):
                pass
            os.link(temporary, path)
            sync_directory(path.parent)
            temporary.unlink()
        self.session = _GatedSession(path, _session_key(self.key), self.offer['swap_id'], self.daemon,
                                     self.foreign, self.wallet)
        self.session.owner = self
        if self.session.config != config or (self.store.recovery_required() and not self.session.journal.recovery_required()):
            raise ValueError('Settlement companion configuration or recovery provenance differs')
        self.store.once('settlement.config', config)

    def _identity(self):
        if self.wallet is None:
            raise ValueError('Owner native signing wallet required')
        result = self.wallet('swap_role', {'rho': self.rho.hex()})
        side = 'refund' if self.role == 'xds-owner' else 'claim'
        terms = self.offer['xds']
        if (type(result) is not dict or result.get('genesis_hash') != terms['genesis_hash']
                or result.get('commitment') != terms[side + '_commitment'] or result.get('address') != terms[side + '_address']):
            raise ValueError('Native signing wallet differs from agreed owner identity')

    def _clock_ready(self, phase):
        start = time.monotonic()
        native = self.native_funding._snapshot()
        if self.chain == 'bitcoin':
            other = self.foreign_funding._chain._snapshot()[1]
        else:
            if self.foreign('getGenesisHash', []) != self.offer['foreign']['manifest']['profile']['genesis_hash']:
                return False
            other = self.foreign('getSlot', [{'commitment': 'processed'}])
        return (native == self.native_funding._snapshot()
                and time.monotonic() - start <= self.offer['schedule']['max_observation_seconds']
                and schedule_ready(self.offer, native[0], other, phase))

    def _first_claim_ready(self, facts):
        if self.store.recovery_required() or self.store.get('cancelled'):
            return False
        if self.exchange.read(self.peer, 'cancel') is not None:
            return False
        start = time.monotonic()
        ready = schedule_ready(self.offer, facts['xds'].get('height'), facts['foreign'].get('height'), 'first-claim')
        if self.chain == 'solana':
            from .solana import SolanaAdapter
            terms = dict(self.store.get('terms.foreign'), payer=self.offer['foreign']['claim_payer'])
            claimant = SolanaAdapter(self.foreign, terms).observe()
            balance, fee = claimant.get('payer_balance_lamports'), claimant.get('fee_lamports')
            ready = (ready and claimant.get('status') == 'unspent' and claimant.get('final') is True
                     and claimant.get('claim_ready') is True and claimant.get('fees_ready') is True
                     and type(balance) is int and type(fee) is int and fee > 0
                     and balance >= self.offer['policy']['solana_fee_attempt_reserve'] * fee)
        return ready and facts['observation_seconds'] + time.monotonic() - start <= self.offer['schedule']['max_observation_seconds']

    def _keys(self):
        from solders.keypair import Keypair
        saved = self.store.get('solana.accounts')
        if saved is None:
            if self.store.recovery_required():
                raise ValueError('Recovery cannot allocate new escrow accounts')
            saved = self.credentials.get('solana_accounts') or {name: bytes(Keypair()).hex() for name in ('state', 'vault', 'refund')}
            self.store.once('solana.accounts', saved)
        return dict(owner=self.signer, **{name: Keypair.from_bytes(bytes.fromhex(value)) for name, value in saved.items()})

    def _funding_args(self, packet, native=False):
        raw, txid = bytes.fromhex(packet['raw']), packet['txid']
        return (raw, txid) if native else (packet['plan'], raw, txid)

    def _attempt(self, name):
        number = self.store.get(name + '.current', 0)
        label = name + ('.attempt' if name == 'funding' else '.intent')
        return self.store.get(label if number == 0 else label + '.' + str(number))

    def _acquisition(self, name):
        number = self.store.get(name + '.current', 0)
        return self.store.get(name + '.acquisition' + ('.' + str(number) if number else ''))

    def _solana_expired(self, adapter, raw, txid, kind=None, plan=None):
        checked = adapter.validate(plan, raw, txid) if plan is not None else adapter.validate(kind, raw, txid)
        observation = adapter.observe(plan) if plan is not None else adapter.observe()
        minimum = observation.get('context_slot')
        if type(minimum) is not int or minimum < 0 or observation.get('status') == 'unknown':
            raise ValueError('Current finalized Solana observation required before submission')
        validity = self.foreign('isBlockhashValid', [checked['recent_blockhash'],
            {'commitment': 'finalized', 'minContextSlot': minimum}])
        if (type(validity) is not dict or type(validity.get('context')) is not dict
                or type(validity['context'].get('slot')) is not int or validity['context']['slot'] < minimum
                or type(validity.get('value')) is not bool):
            raise ValueError('Bounded finalized blockhash validity required')
        # False only dispatches to adapter.renew, whose later rooted expiry and
        # exact still-unconsumed contract checks independently authorize renewal.
        return validity['value'] is False

    def _renew(self, name, adapter, old, kind=None):
        if self.chain != 'solana' or (name == 'funding' and (self.role != 'foreign-owner' or self.store.recovery_required())):
            raise ValueError('Only qualified retained Solana attempts may renew')
        provenance = self._acquisition(name)
        if provenance is None:
            raise ValueError('Retained authenticated blockhash acquisition required')
        if name == 'funding':
            if (self.store.get('cancelled') or self.exchange.read(self.peer, 'cancel') is not None
                    or self.exchange.read(self.role, 'funding') is not None or not self._clock_ready('funding')):
                raise ValueError('Published funding or exhausted window cannot renew')
            raw, txid = adapter.prepare(old['plan'], self._keys())
            evidence = adapter.renew(old['plan'], bytes.fromhex(old['raw']), old['txid'], raw, txid, provenance)
            acquired = adapter.preparation_evidence(old['plan'], raw, txid)
            packet = dict(plan=old['plan'], raw=raw.hex(), txid=txid)
        else:
            raw, txid = adapter.prepare(kind, self.signer)
            evidence = adapter.renew(kind, bytes.fromhex(old['raw']), old['txid'], raw, txid, provenance)
            acquired = adapter.preparation_evidence(kind, raw, txid)
            packet = dict(kind=kind, raw=raw.hex(), txid=txid)
        if evidence.get('status') != 'renewable':
            raise ValueError('Authoritative rooted renewal evidence absent')
        number = self.store.get(name + '.current', 0) + 1
        if number > 100:
            raise ValueError('Owner attempt bound reached')
        suffix = '.' + str(number)
        label = name + ('.attempt' if name == 'funding' else '.intent') + suffix
        self.store.batch([(label, packet, True), (name + '.acquisition' + suffix, acquired, True),
                          (name + '.renewal' + suffix, evidence, True), (name + '.current', number, False)])
        self._checkpoint()
        return self._result(name + '-renewed')

    def _funded_terms(self, packet, native):
        if native:
            if packet['plan'] != self.native_funding.plan():
                raise ValueError('Native funding plan differs from signed offer')
            return self.native_funding.validate(*self._funding_args(packet, True))['terms']
        self.foreign_funding.validate(*self._funding_args(packet))
        if self.chain == 'bitcoin':
            terms = dict(self.offer['foreign']['contract'], funding_txid=packet['txid'], funding_vout=0)
            BitcoinContract.parse(terms)
            return terms
        payer = self.offer['foreign']['claim_payer' if self.role == 'xds-owner' else 'refund_payer']
        return self.foreign_funding.settlement_terms(packet['plan'], payer)

    def _peer_funding(self):
        packet = self.exchange.read(self.peer, 'funding')
        if packet is None:
            return False
        native = self.peer == 'xds-owner'
        adapter = self.native_funding if native else self.foreign_funding
        terms = self._funded_terms(packet, native)
        receipt = adapter.receipt(*self._funding_args(packet, native))
        if receipt.get('publicly_observed') is not True or receipt.get('final') is not True or receipt.get('status') != 'confirmed':
            return False
        label = 'terms.xds' if native else 'terms.foreign'
        self.store.batch([('peer.funding', packet, True), (label, terms, True)])
        return True

    def _fund(self):
        native = self.role == 'xds-owner'
        adapter = self.native_funding if native else self.foreign_funding
        packet = self._attempt('funding')
        if packet is not None:
            receipt = adapter.receipt(*self._funding_args(packet, native))
            if receipt.get('publicly_observed') is True and receipt.get('status') in ('pending', 'confirmed'):
                self.exchange.publish(self.role, 'funding', packet, self.signer)
                return self._result('funding-observed', status=receipt['status'], final=receipt.get('final') is True)
            if receipt.get('status') == 'conflict':
                return self._result('funding-conflict')
            if receipt.get('status') == 'failed':
                if not native and self.chain == 'solana' and not self.store.recovery_required():
                    if self._solana_expired(adapter, bytes.fromhex(packet['raw']), packet['txid'], plan=packet['plan']):
                        return self._renew('funding', adapter, packet)
                return self._result('funding-failed-await-expiry')
        if self.store.recovery_required() or self.store.get('cancelled') or self.exchange.read(self.peer, 'cancel') is not None:
            return self._result('protective-no-funding')
        if not self._clock_ready('second-funding' if native else 'funding'):
            return self._result('wait-funding-window')
        if native:
            if not self._peer_funding():
                return self._result('wait-foreign-funding')
            observation = self._foreign_adapter().observe()
            if observation.get('status') != 'unspent' or observation.get('final') is not True:
                return self._result('wait-foreign-unspent')
        if packet is None:
            self._identity()
            if native and self.durable_funding and self.store.get('funding.prepare-started') is not True:
                from . import xds_preparation
                if not xds_preparation.scan_ready(adapter):
                    return self._result('wait-native-wallet-scan')
            plan = self.store.get('funding.plan')
            if plan is None:
                plan = adapter.plan() if native or self.chain == 'bitcoin' else adapter.plan(self._keys())
                self.store.once('funding.plan', plan)
            started = self.store.get('funding.prepare-started') is True
            if native and started and not self.durable_funding:
                return self._result('native-prepare-response-uncertain')
            operation = None
            if native and self.durable_funding:
                from . import xds_preparation
                operation = self.store.get('funding.operation')
                if operation is None:
                    if started:
                        raise ValueError('Durable native operation identity missing')
                    xds_preparation.capabilities(adapter)
                    operation_id = os.urandom(32).hex()
                    operation = dict(version=1, operation_id=operation_id,
                        request_hash=xds_preparation.request_hash(adapter, self.rho, operation_id))
                    self.store.once('funding.operation', operation)
                if (type(operation) is not dict or set(operation) != {'version', 'operation_id', 'request_hash'}
                        or type(operation['version']) is not int or operation['version'] != 1
                        or operation['request_hash'] != xds_preparation.request_hash(adapter, self.rho, operation['operation_id'])):
                    raise ValueError('Retained native operation binding differs')
            self.store.once('funding.prepare-started', True)
            if self.checkpoint_sink is not None or (native and self.durable_funding):
                # Persist exact selected inputs/auxiliary identities before a
                # wallet can reserve or sign them, including an anchored reopen.
                self._checkpoint()
            if native and self.durable_funding:
                raw, txid = xds_preparation.prepare(adapter, self.rho, operation['operation_id'], resume=started)
            elif native:
                raw, txid = adapter.prepare(self.rho)
            elif self.chain == 'bitcoin':
                raw, txid = adapter.prepare(plan)
            else:
                raw, txid = adapter.prepare(plan, self._keys())
            packet = dict(plan=plan, raw=raw.hex(), txid=txid)
            terms = self._funded_terms(packet, native)
            entries = [('funding.attempt', packet, True), ('terms.xds' if native else 'terms.foreign', terms, True)]
            if not native and self.chain == 'solana':
                entries.append(('funding.acquisition', adapter.preparation_evidence(plan, raw, txid), True))
            self.store.batch(entries)
        if self.checkpoint_sink is not None:
            self.store.put('funding.send-started', True)
        self._checkpoint()
        if not self._clock_ready('second-funding' if native else 'funding'):
            return self._result('wait-funding-window')
        if native:
            # Backup fsync/signing may outlive the earlier counter-deposit read.
            # Re-read it at the final transmission boundary as well.
            started = time.monotonic()
            observation = self._foreign_adapter().observe()
            if (observation.get('status') != 'unspent' or observation.get('final') is not True
                    or time.monotonic() - started > self.offer['schedule']['max_observation_seconds']
                    or not self._clock_ready('second-funding')):
                return self._result('wait-foreign-unspent')
        self.store.put('funding.send-started', True)
        if not native and self.chain == 'solana' and self._solana_expired(
                adapter, bytes.fromhex(packet['raw']), packet['txid'], plan=packet['plan']):
            return self._renew('funding', adapter, packet)
        try:
            adapter.send(*self._funding_args(packet, native))
        except Exception:
            if not native and self.chain == 'solana':
                # An uncertain send or a newly finalized deposit is not expiry.
                # The next step reconciles these exact bytes before the explicit
                # expiry gate can authorize renewal.
                return self._result('funding-unknown')
            raise
        return self._result('funding-submitted')

    def _foreign_adapter(self):
        terms = self.store.get('terms.foreign')
        if self.chain == 'bitcoin':
            return BitcoinAdapter(self.foreign, terms)
        from .solana import SolanaAdapter
        return SolanaAdapter(self.foreign, terms)

    def _own_refund(self):
        native = self.role == 'xds-owner'
        terms = self.store.get('terms.xds' if native else 'terms.foreign')
        if terms is None:
            return None
        kind = 'xds-refund' if native else 'foreign-refund'
        adapter = XdsAdapter(self.daemon, terms, self.wallet) if native else self._foreign_adapter()
        intent = self._attempt('refund')
        if intent is not None:
            raw, txid = bytes.fromhex(intent['raw']), intent['txid']
            adapter.validate(kind, raw, txid)
            receipt = adapter.receipt(kind, raw, txid)
            if receipt.get('status') == 'failed' and not native and self.chain == 'solana':
                if self._solana_expired(adapter, raw, txid, kind=kind):
                    return self._renew('refund', adapter, intent, kind)
                return self._result('refund-failed-await-expiry')
            if receipt.get('status') in ('pending', 'confirmed', 'conflict', 'failed'):
                self.store.put('settlement.status', dict(kind=kind, status=receipt['status'], final=receipt.get('final') is True))
                return self._result('refund-observed', status=receipt['status'], final=receipt.get('final') is True)
        before = adapter.observe()
        if before.get('status') != 'unspent' or before.get('final') is not True or before.get('refund_eligible') is not True:
            return None
        if intent is None:
            self._identity() if native else validate_owner_key(self.offer, self.role, self.signer)
            raw, txid = adapter.prepare(kind, self.rho if native else self.signer)
            adapter.validate(kind, raw, txid)
            after = adapter.observe()
            if (after.get('status') != 'unspent' or after.get('final') is not True or after.get('refund_eligible') is not True
                    or after.get('genesis_hash') != before.get('genesis_hash') or after.get('block_hash') != before.get('block_hash')):
                raise ValueError('Own refund changed during signing')
            intent = dict(kind=kind, raw=raw.hex(), txid=txid)
            entries = [('refund.intent', intent, True)]
            if not native and self.chain == 'solana':
                entries.append(('refund.acquisition', adapter.preparation_evidence(kind, raw, txid), True))
            self.store.batch(entries)
        self._checkpoint()
        if not native and self.chain == 'solana' and self._solana_expired(
                adapter, bytes.fromhex(intent['raw']), intent['txid'], kind=kind):
            return self._renew('refund', adapter, intent, kind)
        try:
            adapter.send(kind, bytes.fromhex(intent['raw']), intent['txid'])
        except Exception:
            if not native and self.chain == 'solana':
                # Preserve the retained refund after an uncertain response;
                # receipt and expiry checks run before a later transmission.
                return self._result('refund-unknown')
            raise
        return self._result('refund-submitted')

    def _discover(self):
        result = XdsWitnessDiscovery(self.daemon, self.store.get('terms.xds')).scan(self.store.get('scanner.cursor'))
        entries = [('scanner.cursor', result['cursor'], False)]
        for candidate in result['candidates']:
            if candidate['kind'] == 'xds-claim' and self.store.get('scanner.claim') is None:
                # Atomically retain full public proof before advancing its cursor.
                entries.append(('scanner.claim', candidate['proof'], True))
                break
        self.store.batch(entries)
        return self.store.get('scanner.claim')

    def step(self):
        # Protect our existing deposit before depending on peer availability.
        result = self._own_refund()
        if result is not None:
            # A competing native claim can invalidate a retained refund after
            # reorg. Keep the protective foreign-claim path reachable if its
            # full public witness is independently discovered.
            if (self.role != 'xds-owner' or self.session is None
                    or result.get('status') not in ('conflict', 'failed') or self._discover() is None):
                return result
        if self.session is not None:
            kind = 'xds-claim' if self.role == 'foreign-owner' else 'foreign-claim'
            intent = self.session.journal.intent(self.offer['swap_id'], kind)
            proof = self._discover() if self.role == 'xds-owner' else None
            if intent is None:
                if kind == 'foreign-claim' and proof is not None:
                    self.session.prepare_observed_claim(self.signer, proof)
                elif kind == 'xds-claim' and not self.store.recovery_required() and not self.store.get('cancelled'):
                    admission, _ = self.session.observe()
                    if not admission.allow_first_exposure():
                        return self._result('wait-first-claim-admission')
                    self._identity()
                    self.session.prepare(kind, self.rho, bytes.fromhex(self.credentials['secret']))
                else:
                    return self._result('wait-public-claim' if kind == 'foreign-claim' else 'protective-no-first-claim')
            elif kind == 'foreign-claim' and proof is not None and not self.session._public_proof():
                self.session.prepare_observed_claim(self.signer, proof)
            receipt = self.session.reconcile(kind)
            if kind == 'foreign-claim' and self.chain == 'solana' and receipt.get('status') in ('unknown', 'failed'):
                retained = self.session.journal.intent(self.offer['swap_id'], kind)
                if self._solana_expired(self.session.adapters['foreign'], retained['payload'], retained['txid'], kind=kind):
                    self.session.renew_solana(kind, self.signer)
                    self._checkpoint()
                    return self._result('claim-renewed')
                if receipt.get('status') == 'failed':
                    return self._result('claim-failed-await-expiry')
            if receipt.get('status') in ('confirmed', 'pending', 'failed', 'conflict'):
                self.store.put('settlement.status', dict(kind=kind, status=receipt['status'], final=receipt.get('final') is True))
                return self._result('claim-observed', status=receipt['status'], final=receipt.get('final') is True)
            if kind == 'xds-claim' and self.store.recovery_required() and not self.session._public_proof():
                return self._result('protective-no-first-claim')
            self._checkpoint()
            try:
                self.session.broadcast(kind)
            except Exception:
                if kind == 'foreign-claim' and self.chain == 'solana':
                    self.session.renew_solana(kind, self.signer)
                    self._checkpoint()
                    return self._result('claim-renewed')
                raise
            return self._result('claim-submitted')
        if self.store.recovery_required():
            if self.store.get('terms.xds') is not None and self.store.get('terms.foreign') is not None:
                self._open_session()
                return self._result('protective-pair-restored')
            # A foreign deposit can wait for its refund independently of the
            # absent counter-deposit and absent native signing wallet.
            own_terms = self.store.get('terms.xds' if self.role == 'xds-owner' else 'terms.foreign')
            return self._result('protective-await-refund' if own_terms is not None else 'protective-no-funding')
        if self.store.get('cancelled'):
            return self._result('cancelled-await-refund')
        self._identity()
        self.exchange.publish(self.role, 'accept', {'offer_hash': offer_hash(self.offer)}, self.signer)
        if self.exchange.read(self.peer, 'accept') is None:
            return self._result('wait-peer-acceptance')
        self._peer_funding()
        if self.store.get('funding.attempt') is not None:
            native = self.role == 'xds-owner'
            adapter = self.native_funding if native else self.foreign_funding
            packet = self._attempt('funding')
            receipt = adapter.receipt(*self._funding_args(packet, native))
            if receipt.get('publicly_observed') is True:
                self.exchange.publish(self.role, 'funding', packet, self.signer)
            if (receipt.get('status') == 'confirmed' and receipt.get('publicly_observed') is True
                    and receipt.get('final') is True and self.store.get('peer.funding') is not None):
                self._open_session()
                return self._result('paired-contracts-observed')
        return self._fund()

    def cancel(self):
        self.store.once('cancelled', True)
        self.exchange.publish(self.role, 'cancel', {'offer_hash': offer_hash(self.offer)}, self.signer)
        self._checkpoint()
        return self._result('cancelled-await-refund')
