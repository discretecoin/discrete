"""Qualified owner recovery on top of the unchanged settlement journal.

prepare_observed_claim is an INTERNAL boundary: public_proof must be retrieved
from the authenticated OwnerStore acquisition log populated exclusively by
XdsWitnessDiscovery. Neither CLI arguments, mailbox packets, nor arbitrary
signed drafts establish public observation. Local wire verification establishes
the contract/witness, but cannot distinguish a private signed draft from a
previously public transaction; that provenance belongs to the owner log.

This helper never creates funding or a first XDS claim. A restored owner may
protect a previously observed public preimage or prepare an absent own refund
after current authoritative observations establish its exact matured contract.
It does not weaken Session.prepare or Journal.prepare recovery restrictions.
"""
import hashlib
import os

from .common import canonical, hex_bytes, integer
from .session import Session
from .xds import XdsAdapter, _hex


class OwnerSession(Session):
    def _owner_binding(self):
        stored = self.journal.intent(self.id, 'session')
        if stored is None or stored['payload'] != canonical(self.config):
            raise ValueError('Owner configuration differs from authenticated session')
        digest = hashlib.sha256(stored['payload']).hexdigest()
        if stored['txid'] != digest or self.journal.terms(self.id) != {'version': 1, 'config_sha256': digest}:
            raise ValueError('Owner contract commitment differs from authenticated session')
        return digest

    def _owner_observation(self, kind):
        observation = self._adapter(kind).observe()
        if (type(observation) is not dict or observation.get('status') != 'unspent'
                or observation.get('final') is not True):
            raise ValueError('Currently confirmed unspent owner contract required')
        native = kind.startswith('xds-')
        terms = self.config['xds' if native else 'foreign']
        solana = not native and self.config['foreign_chain'] == 'solana'
        genesis = terms['manifest']['profile']['genesis_hash'] if solana else terms['genesis_hash']
        if observation.get('genesis_hash') != genesis:
            raise ValueError('Owner recovery observation network differs')
        integer(observation.get('height'), 'owner observed height', 0, 2**64 - 1)
        confirmations = integer(observation.get('confirmations'), 'owner confirmations', 1, 2**64 - 1)
        minimum = 1 if solana else terms['min_confirmations']
        if native:
            minimum = max(minimum, self.config['policy']['min_xds_confirmations'])
        if confirmations < minimum:
            raise ValueError('Owner recovery confirmations are insufficient')
        if not solana:
            hex_bytes(observation.get('block_hash'), 32, 'owner funding block')
            if native:
                hex_bytes(observation.get('tip_hash'), 32, 'owner native tip')
        if kind.endswith('-refund'):
            current = observation.get('finalized_height') if solana else observation['height']
            deadline = terms['deadline_slot'] if solana else terms['refund_height']
            if (observation.get('refund_eligible') is not True
                    or integer(current, 'owner refund clock', 0, 2**64 - 1) < deadline):
                raise ValueError('Owner refund has not matured on its authoritative chain')
        if solana and (observation.get('fees_ready') is not True
                       or observation.get('refund_ready' if kind.endswith('-refund') else 'claim_ready') is not True):
            raise ValueError('Owner Solana branch or fee payer is unavailable')
        if native and observation.get('fees_ready') is not True:
            raise ValueError('Owner native exit fee is unavailable')
        # Audit only the normalized public chain facts; no arbitrary RPC fields.
        fields = ('status', 'final', 'height', 'confirmations', 'block_hash', 'tip_hash', 'genesis_hash',
                  'refund_eligible', 'finalized_height', 'context_slot', 'fees_ready', 'claim_ready', 'refund_ready')
        return {name: observation[name] for name in fields if name in observation}

    @staticmethod
    def _same_contract(before, after):
        if (before['genesis_hash'] != after['genesis_hash'] or before.get('block_hash') != after.get('block_hash')
                or after['height'] < before['height']
                or (after['height'] == before['height'] and before.get('tip_hash') != after.get('tip_hash'))
                or ('finalized_height' in before and after['finalized_height'] < before['finalized_height'])):
            raise ValueError('Owner chain changed during protective preparation')

    def _append_owner_intent(self, kind, raw, txid, evidence):
        # Called only inside the qualified caller's transaction after role,
        # immutable configuration, exact signed bytes and chain checks.
        if kind not in ('foreign-claim', 'xds-refund', 'foreign-refund'):
            raise ValueError('Qualified protective owner settlement only')
        self._adapter(kind)
        expected = 'owner-observed-claim-preparation-v1' if kind == 'foreign-claim' else 'owner-recovery-refund-preparation-v1'
        if (not self.journal.db.in_transaction or type(evidence) is not dict or evidence.get('source') != expected
                or (kind.endswith('-refund') and not self.journal.recovery_required())):
            raise ValueError('Qualified owner preparation transaction required')
        if type(raw) is not bytes or not 1 <= len(raw) <= 65536 or type(txid) is not str or not txid:
            raise ValueError('Bounded signed owner artifact required')
        if self.journal.intent(self.id, kind) is not None:
            raise ValueError('Existing immutable owner intent must be reconciled')
        exposes = kind == 'foreign-claim'
        self.journal.db.execute('INSERT INTO intents VALUES(?,?,?)', (self.id, kind, int(exposes)))
        self.journal._insert_attempt(self.id, kind, 0, raw, txid, evidence)
        nonce = os.urandom(12)
        sealed = nonce + self.journal.aead.encrypt(nonce, canonical(evidence),
            canonical([self.id, kind, 0, 'owner-protective-preparation-v1']))
        self.journal.db.execute('INSERT INTO recovery_actions(swap,kind,attempt,evidence) VALUES(?,?,?,?)',
            (self.id, kind, 0, canonical({'source': 'owner-protective-preparation-v1', 'sealed': sealed.hex()})))

    def prepare_observed_claim(self, key, public_proof):
        """Protect a scanner-acquired witness loaded from authenticated OwnerStore.

        This method has no external/CLI proof-input interface. Already signed
        foreign intent bytes are reused without signing again, allowing recovery
        from a crash between intent persistence and _record_public persistence.
        """
        kind = 'foreign-claim'
        adapter = self._adapter(kind)
        binding = self._owner_binding()
        if type(public_proof) is not dict or public_proof.get('kind') != 'xds-claim':
            raise ValueError('Authenticated owner scanner claim proof required')
        if public_proof.get('status') not in ('unknown', 'pending', 'confirmed') or type(public_proof.get('final')) is not bool:
            raise ValueError('Qualified scanner receipt status required')
        if type(public_proof.get('publicly_observed')) is not bool:
            raise ValueError('Exact scanner receipt metadata required')
        if public_proof.get('status') in ('pending', 'confirmed') and public_proof['publicly_observed'] is not True:
            raise ValueError('Positive public receipt must record actual full wire observation')
        raw = _hex(public_proof.get('raw'), None, 'saved public native wire')
        txid = _hex(public_proof.get('txid'), 32, 'saved public native identity').hex()
        acquisition = public_proof.get('acquisition')
        if (type(acquisition) is not dict or set(acquisition) != {'source', 'full_wire_fetched', 'txid', 'raw_sha256'}
                or acquisition.get('source') != 'xds-witness-discovery-v1'
                or acquisition.get('full_wire_fetched') is not True or acquisition.get('txid') != txid
                or acquisition.get('raw_sha256') != hashlib.sha256(raw).hexdigest()):
            raise ValueError('Authenticated full-wire scanner acquisition required')
        # Construct a fresh offline validator from the authenticated exact native
        # contract; neither a supplied secret nor a mutable RPC result is trusted.
        checked = XdsAdapter(None, self.config['xds']).validate('xds-claim', raw, txid)
        secret = hex_bytes(public_proof.get('secret'), 32, 'saved public witness')
        if checked.get('secret') != secret.hex() or hashlib.sha256(secret).hexdigest() != self.config['foreign']['hashlock']:
            raise ValueError('Saved public preimage differs from the exact paired contracts')
        old = self.journal.intent(self.id, kind)
        if old is not None:
            current = adapter.validate(kind, old['payload'], old['txid'])
            if current.get('secret') != secret.hex():
                raise ValueError('Existing foreign intent differs from the saved public witness')
            self._record_public(kind, old, txid, raw)
            return self.describe(kind)
        before = self._owner_observation(kind)
        prepared, identity = adapter.prepare(kind, key, secret)
        result = adapter.validate(kind, prepared, identity)
        if result.get('secret') != secret.hex():
            raise ValueError('Prepared foreign claim differs from saved public witness')
        acquisition = adapter.preparation_evidence(kind, prepared, identity) if self.config['foreign_chain'] == 'solana' else None
        with self.journal.transaction():
            if self._owner_binding() != binding:
                raise ValueError('Owner claim configuration changed')
            after = self._owner_observation(kind)
            self._same_contract(before, after)
            evidence = dict(source='owner-observed-claim-preparation-v1', config_sha256=binding,
                public_txid=txid, public_raw_sha256=hashlib.sha256(raw).hexdigest(),
                recovery_required=self.journal.recovery_required(), observation=after)
            if acquisition is not None:
                evidence['preparation'] = acquisition
            self._append_owner_intent(kind, prepared, identity, evidence)
        self._record_public(kind, self.journal.intent(self.id, kind), txid, raw)
        return self.describe(kind)

    def prepare_recovery_refund(self, kind, key):
        """Append only an absent own refund to an explicitly recovery-locked log."""
        if kind not in ('xds-refund', 'foreign-refund'):
            raise ValueError('Owner recovery permits own refund only')
        adapter = self._adapter(kind)
        binding = self._owner_binding()
        if not self.journal.recovery_required():
            raise ValueError('Explicit recovery-locked journal required')
        if self.journal.intent(self.id, kind) is not None:
            raise ValueError('Existing immutable owner refund must be reconciled')
        before = self._owner_observation(kind)
        raw, txid = adapter.prepare(kind, key)
        checked = adapter.validate(kind, raw, txid)
        if 'secret' in checked:
            raise ValueError('Owner refund cannot expose a preimage')
        acquisition = adapter.preparation_evidence(kind, raw, txid) if (
            self.config['foreign_chain'] == 'solana' and kind == 'foreign-refund') else None
        with self.journal.transaction():
            if not self.journal.recovery_required() or self._owner_binding() != binding:
                raise ValueError('Owner recovery provenance changed')
            after = self._owner_observation(kind)
            self._same_contract(before, after)
            evidence = dict(source='owner-recovery-refund-preparation-v1', config_sha256=binding,
                            observation=after, recovery_required=True)
            if acquisition is not None:
                evidence['preparation'] = acquisition
            self._append_owner_intent(kind, raw, txid, evidence)
        return self.describe(kind)
