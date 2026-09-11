"""Offline signed transport/admission tests; no RPC or chain finality claims."""
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec, utils
from solders.keypair import Keypair

from swap_runtime.bitcoin import N, pubkey
from swap_runtime.common import canonical
from swap_runtime.owner_protocol import (MAX_BYTES, PublicExchange, offer_hash,
    owner_key, schedule_ready, validate_offer, validate_owner_key)


def configuration(chain='bitcoin'):
    lock = hashlib.sha256(b'public fixture hashlock only').hexdigest()
    native = dict(genesis_hash='11' * 32, hashlock=lock, nonce='12' * 32,
        claim_commitment='13' * 32, refund_commitment='14' * 32,
        claim_address='native-claim-fixture', refund_address='native-refund-fixture',
        refund_height=200, funding_value_atoms=1001, net_amount_atoms=1000,
        fee_atoms=1, min_confirmations=11)
    if chain == 'bitcoin':
        keys = {role: ec.generate_private_key(ec.SECP256K1()) for role in ('xds-owner', 'foreign-owner')}
        foreign = dict(contract=dict(genesis_hash='21' * 32, hashlock=lock,
            claim_pubkey=pubkey(keys['xds-owner']).hex(), refund_pubkey=pubkey(keys['foreign-owner']).hex(),
            refund_height=1000, funding_value_sats=100000, claim_script='0014' + '22' * 20,
            refund_script='0014' + '23' * 20, fee_sats=1000, min_confirmations=6),
            funding_fee_sats=1000, change_address='bcrt1qpublicfixturechange',
            change_script='0014' + '24' * 20, min_input_confirmations=2)
    else:
        keys = {role: Keypair() for role in ('xds-owner', 'foreign-owner')}
        claim, owner = (str(keys[role].pubkey()) for role in ('xds-owner', 'foreign-owner'))
        manifest = json.loads((Path(__file__).parent / 'fixtures/solana-v06/build-manifest.json').read_text())
        foreign = dict(manifest=manifest, owner=owner, source=str(Keypair().pubkey()),
            claim_owner=claim, claim_payer=claim, refund_owner=owner, refund_payer=owner,
            amount=1234567, hashlock=lock, deadline_slot=1000, min_context_slot=0,
            max_finality_lag_slots=128, min_funding_window_slots=50,
            max_funding_fee_lamports=25000, max_rent_lamports=20000000, owner_reserve_lamports=10000)
    offer = dict(version=1, swap_id='owner-exchange-fixture', foreign_chain=chain, xds=native, foreign=foreign,
        policy=dict(min_xds_confirmations=11, xds_claim_budget_blocks=2, foreign_claim_budget_units=2,
                    max_observation_seconds=15, solana_fee_attempt_reserve=2),
        schedule=dict(xds_min_funding_blocks=40, foreign_min_funding_units=200,
            foreign_min_before_xds_fund=250, foreign_min_before_xds_claim=20,
            max_observation_seconds=15, xds_block_upper_ms=2000, foreign_unit_lower_ms=1000,
            safety_margin_ms=1000))
    return offer, keys


class OwnerOfferTests(unittest.TestCase):
    def test_both_profiles_are_offline_detached_and_order_independent(self):
        for chain in ('bitcoin', 'solana'):
            offer, _ = configuration(chain)
            with patch('swap_runtime.owner_protocol._no_rpc', side_effect=AssertionError('RPC forbidden')) as rpc:
                clean = validate_offer(offer)
                self.assertEqual(offer_hash(offer), offer_hash(dict(reversed(list(offer.items())))))
                self.assertEqual(clean, validate_offer(json.dumps(offer).encode()))
                rpc.assert_not_called()
            clean['xds']['net_amount_atoms'] = 55
            self.assertEqual(offer['xds']['net_amount_atoms'], 1000)

    def test_exact_fields_and_types_at_every_offer_level(self):
        offer, _ = configuration()
        for path in ((), ('xds',), ('foreign',), ('foreign', 'contract'), ('policy',), ('schedule',)):
            for operation in ('unknown', 'missing'):
                bad = copy.deepcopy(offer)
                section = bad
                for key in path: section = section[key]
                if operation == 'unknown': section['unexpected'] = 1
                else: del section[next(iter(section))]
                with self.subTest(path=path, operation=operation), self.assertRaises(ValueError): validate_offer(bad)
        for value in (True, '1', 1.0, None):
            bad = copy.deepcopy(offer); bad['version'] = value
            with self.assertRaises(ValueError): validate_offer(bad)
        for value in ('../escape', 'a/b', '', 'a' * 81, 'не-ascii'):
            bad = copy.deepcopy(offer); bad['swap_id'] = value
            with self.assertRaises(ValueError): validate_offer(bad)

    def test_hashlock_fee_confirmation_and_role_constraints(self):
        offer, _ = configuration()
        patches = [(('xds', 'hashlock'), '99' * 32), (('xds', 'fee_atoms'), 2),
                   (('xds', 'net_amount_atoms'), 999), (('xds', 'min_confirmations'), 10),
                   (('xds', 'min_confirmations'), 12), (('policy', 'min_xds_confirmations'), 10),
                   (('policy', 'xds_claim_budget_blocks'), True)]
        for path, value in patches:
            bad = copy.deepcopy(offer); bad[path[0]][path[1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): validate_offer(bad)
        bad = copy.deepcopy(offer)
        bad['foreign']['contract']['refund_pubkey'] = bad['foreign']['contract']['claim_pubkey']
        with self.assertRaises(ValueError): validate_offer(bad)
        sol, _ = configuration('solana')
        sol['foreign']['claim_payer'] = sol['foreign']['owner']
        with self.assertRaises(ValueError): validate_offer(sol)

    def test_strict_json_duplicate_size_depth_float_and_cycle(self):
        offer, _ = configuration()
        raw = canonical(offer)
        with self.assertRaises(ValueError): validate_offer(b'{"version":1,' + raw[1:])
        for bad in (b' ' * (MAX_BYTES + 1), b'NaN', b'{', b'\xff'):
            with self.assertRaises(ValueError): validate_offer(bad)
        cyclic = {}; cyclic['cycle'] = cyclic
        with self.assertRaises(ValueError): validate_offer(cyclic)
        for value in (1.5, float('nan'), 2**65, object()):
            bad = copy.deepcopy(offer); bad['schedule']['safety_margin_ms'] = value
            with self.assertRaises(ValueError): validate_offer(bad)

    def test_independent_owner_keys_and_canonical_private_decoding(self):
        for chain in ('bitcoin', 'solana'):
            offer, keys = configuration(chain)
            for role, key in keys.items():
                material = key.private_numbers().private_value.to_bytes(32, 'big') if chain == 'bitcoin' else bytes(key)
                decoded = owner_key(chain, material.hex())
                self.assertEqual(validate_owner_key(offer, role, key), validate_owner_key(offer, role, decoded))
                other = 'foreign-owner' if role == 'xds-owner' else 'xds-owner'
                with self.assertRaises(ValueError): validate_owner_key(offer, other, key)
                with self.assertRaises(ValueError): validate_owner_key(offer, '../role', key)
            with self.assertRaises(ValueError): validate_owner_key(offer, 'xds-owner', object())
        for chain, value in (('bitcoin', '00' * 32), ('bitcoin', N.to_bytes(32, 'big').hex()),
                             ('bitcoin', 'ff' * 31), ('solana', '00' * 32), ('solana', 'ff' * 64), ('other', '00')):
            with self.assertRaises(ValueError) as caught: owner_key(chain, value)
            self.assertNotIn(value, str(caught.exception))

    def test_native_and_foreign_funding_schedule_floors(self):
        offer, _ = configuration()
        for name, value in (('xds_min_funding_blocks', 13), ('foreign_min_funding_units', 8),
                            ('foreign_min_before_xds_fund', 199), ('foreign_min_before_xds_claim', 1),
                            ('max_observation_seconds', 16), ('xds_block_upper_ms', 0), ('safety_margin_ms', -1)):
            bad = copy.deepcopy(offer); bad['schedule'][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): validate_offer(bad)
        sol, _ = configuration('solana'); sol['schedule']['foreign_min_funding_units'] = 130
        with self.assertRaises(ValueError): validate_offer(sol)

    def test_schedule_each_phase_and_strict_time_boundary(self):
        for chain in ('bitcoin', 'solana'):
            offer, _ = configuration(chain)
            self.assertTrue(schedule_ready(offer, 100, 100, 'funding'))
            self.assertFalse(schedule_ready(offer, 161, 100, 'funding'))
            self.assertTrue(schedule_ready(offer, 160, 100, 'second-funding'))
            self.assertFalse(schedule_ready(offer, 161, 100, 'second-funding'))
            self.assertFalse(schedule_ready(offer, 100, 801, 'second-funding'))
            self.assertTrue(schedule_ready(offer, 198, 979, 'first-claim'))
            self.assertFalse(schedule_ready(offer, 199, 979, 'first-claim'))
            self.assertFalse(schedule_ready(offer, 198, 981, 'first-claim'))
            # Remaining 20 foreign units == 2 native blocks * 2000 + 16000 margin.
            offer['schedule']['safety_margin_ms'] = 16000
            self.assertFalse(schedule_ready(offer, 198, 980, 'first-claim'))
            self.assertTrue(schedule_ready(offer, 198, 979, 'first-claim'))
            for phase in ('', 'claim', '../funding'):
                with self.assertRaises(ValueError): schedule_ready(offer, 100, 100, phase)
            for height in (-1, True, 1.0, 2**64):
                with self.assertRaises(ValueError): schedule_ready(offer, height, 100, 'funding')


class PublicExchangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def exchange(self, chain='bitcoin'):
        offer, keys = configuration(chain)
        return PublicExchange(self.directory, offer), offer, keys

    def test_accept_cancel_funding_roundtrip_both_chains_both_roles(self):
        for chain in ('bitcoin', 'solana'):
            exchange, offer, keys = self.exchange(chain)
            for role in keys:
                for kind in ('accept', 'cancel', 'funding'):
                    body = {'offer_hash': offer_hash(offer)} if kind != 'funding' else {'plan': {'public': 1}, 'raw': '0104', 'txid': 'ab' * 32}
                    self.assertIsNone(exchange.read(role, kind))
                    path = exchange.publish(role, kind, body, keys[role])
                    wire = path.read_bytes()
                    self.assertEqual(body, exchange.read(role, kind))
                    self.assertEqual(path, exchange.publish(role, kind, body, keys[role]))
                    self.assertEqual(wire, path.read_bytes())
                    self.assertEqual(body, PublicExchange(self.directory, offer).read(role, kind))
                    self.assertLessEqual(path.stat().st_size, MAX_BYTES)

    def test_wrong_owner_role_is_rejected_before_any_file(self):
        exchange, _, keys = self.exchange()
        with self.assertRaises(ValueError):
            exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['foreign-owner'])
        self.assertEqual(list(self.directory.iterdir()), [])
        for role, kind in (('../xds-owner', 'accept'), ('xds-owner', '../accept'), ('other', 'funding')):
            with self.assertRaises(ValueError): exchange.read(role, kind)

    def test_tampered_body_role_kind_offer_signature_and_unknown_fields(self):
        for chain in ('bitcoin', 'solana'):
            exchange, _, keys = self.exchange(chain)
            path = exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['xds-owner'])
            original = json.loads(path.read_bytes())
            changes = [('role', 'foreign-owner'), ('kind', 'cancel'), ('offer_hash', '00' * 32),
                       ('body', {'offer_hash': '00' * 32}), ('signature', '00' * 64), ('unexpected', 1), ('version', True)]
            for name, value in changes:
                changed = dict(original); changed[name] = value; path.write_bytes(canonical(changed))
                with self.subTest(chain=chain, field=name), self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')
            path.write_bytes(canonical(original))
            self.assertIsNotNone(exchange.read('xds-owner', 'accept'))

    def test_different_offer_and_role_file_replay_is_rejected(self):
        exchange, offer, keys = self.exchange()
        path = exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['xds-owner'])
        raw = path.read_bytes()
        changed = copy.deepcopy(offer); changed['swap_id'] += '-other'
        replay = PublicExchange(self.directory, changed)
        replay._paths('xds-owner', 'accept')[0].write_bytes(raw)
        with self.assertRaises(ValueError): replay.read('xds-owner', 'accept')
        exchange._paths('foreign-owner', 'accept')[0].write_bytes(raw)
        with self.assertRaises(ValueError): exchange.read('foreign-owner', 'accept')

    def test_ecdsa_high_s_and_noncanonical_der_are_rejected(self):
        exchange, _, keys = self.exchange()
        path = exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['xds-owner'])
        envelope = json.loads(path.read_bytes())
        signature = bytes.fromhex(envelope['signature']); r, s = utils.decode_dss_signature(signature)
        self.assertLessEqual(s, N // 2)
        for bad in (utils.encode_dss_signature(r, N - s), signature + b'\0', b'\x30\0'):
            envelope['signature'] = bad.hex(); path.write_bytes(canonical(envelope))
            with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')

    def test_canonical_envelope_duplicate_json_empty_truncated_and_large_file(self):
        exchange, _, keys = self.exchange()
        path = exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['xds-owner'])
        raw = path.read_bytes()
        for bad in (raw + b'\n', b'{"version":1,' + raw[1:], b'', raw[:-1], b' ' * (MAX_BYTES + 1)):
            path.write_bytes(bad)
            with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')

    def test_partial_reservation_and_staging_never_become_absence_or_overwrite(self):
        for suffix in (1, 2):
            exchange, _, keys = self.exchange()
            partial = exchange._paths('xds-owner', 'accept')[suffix]
            partial.write_bytes(b'')
            with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')
            with self.assertRaises(ValueError): exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['xds-owner'])
            self.assertEqual(partial.read_bytes(), b'')

    def test_crash_before_atomic_publication_is_retained_and_fails_closed(self):
        exchange, _, keys = self.exchange()
        with patch('swap_runtime.owner_protocol.os.link', side_effect=OSError('fixture publication failure')):
            with self.assertRaises(ValueError): exchange.publish('xds-owner', 'accept', {'offer_hash': exchange.offer_hash}, keys['xds-owner'])
        final, reservation, pending = exchange._paths('xds-owner', 'accept')
        self.assertFalse(final.exists()); self.assertTrue(reservation.is_file()); self.assertTrue(pending.is_file())
        self.assertEqual(json.loads(pending.read_bytes())['offer_hash'], exchange.offer_hash)
        with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')

    def test_concurrent_distinct_funding_messages_cannot_replace_winner(self):
        exchange, offer, keys = self.exchange()
        barrier = threading.Barrier(2)
        bodies = [dict(plan={'public': i}, raw='0104', txid='ab' * 32) for i in (1, 2)]
        def writer(body):
            other = PublicExchange(self.directory, offer); barrier.wait()
            try:
                other.publish('foreign-owner', 'funding', body, keys['foreign-owner'])
                return body
            except ValueError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(writer, bodies))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(exchange.read('foreign-owner', 'funding'), winners[0])
        loser = next(body for body in bodies if body != winners[0])
        with self.assertRaises(ValueError): exchange.publish('foreign-owner', 'funding', loser, keys['foreign-owner'])
        self.assertEqual(exchange.read('foreign-owner', 'funding'), winners[0])

    def test_nonregular_file_and_directory_change_fail_closed(self):
        exchange, _, _ = self.exchange()
        exchange._paths('xds-owner', 'accept')[0].mkdir()
        with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')
        with self.assertRaises(ValueError): PublicExchange(self.directory / 'missing', configuration()[0])
        with patch.object(exchange, '_directory_stat', self.directory.parent.stat()):
            with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')

    def test_symlink_or_windows_reparse_file_is_rejected_before_open(self):
        exchange, _, _ = self.exchange()
        final = exchange._paths('xds-owner', 'accept')[0]; final.write_bytes(b'{}')
        # Reparse metadata is checked before opening, including on Windows where
        # creating symlinks normally requires a privilege unrelated to this test.
        with patch('swap_runtime.owner_protocol._reparse', side_effect=lambda info: not __import__('stat').S_ISDIR(info.st_mode)):
            with patch('swap_runtime.owner_protocol.os.open', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError): exchange.read('xds-owner', 'accept')

    def test_body_bounds_unknown_fields_and_private_shape_are_rejected(self):
        exchange, _, keys = self.exchange()
        for body in ({'offer_hash': exchange.offer_hash, 'secret': 'private'}, {'offer_hash': '00' * 32}):
            with self.assertRaises(ValueError): exchange.publish('xds-owner', 'accept', body, keys['xds-owner'])
        for body in ({'plan': {}, 'raw': 'AB', 'txid': 'ab' * 32}, {'plan': {}, 'raw': 'a', 'txid': 'ab' * 32},
                     {'plan': {}, 'raw': '01', 'txid': '../escape'}, {'plan': {}, 'raw': 'ab' * MAX_BYTES, 'txid': 'ab' * 32},
                     {'plan': {}, 'raw': '01', 'txid': 'ab' * 32, 'key': 'private'}):
            with self.assertRaises(ValueError): exchange.publish('xds-owner', 'funding', body, keys['xds-owner'])
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
