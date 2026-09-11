import base64
import copy
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from profile import LOADER, MINTS, TOKEN, decode_key, encode_key, make_profile, verify_accounts, verify_rpc


def account(owner, data, executable=False):
    return {'owner': owner, 'data': [base64.b64encode(data).decode(), 'base64'],
            'lamports': 1_000_000, 'executable': executable}


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.program_id = encode_key(bytes([37]) * 32)
        self.genesis = encode_key(bytes([38]) * 32)
        self.pd = encode_key(bytes([39]) * 32)
        self.authority = encode_key(bytes([40]) * 32)
        self.code = b'\x7fELF' + bytes(range(60))
        self.manifest = {'profile': make_profile('mainnet-usdc', self.program_id, self.genesis),
                         'artifact': {'bytes': len(self.code), 'sha256': hashlib.sha256(self.code).hexdigest()}}
        self.program = account(LOADER, struct.pack('<I', 2) + decode_key(self.pd), True)
        self.programdata = account(LOADER, struct.pack('<IQB', 3, 10, 0) + bytes(32) + self.code + bytes(128))
        mint = bytearray(82)
        mint[44:46] = b'\x06\x01'
        mint[46:50] = struct.pack('<I', 1)
        mint[50:82] = decode_key(self.authority)
        self.mint = account(TOKEN, bytes(mint))

    def verify(self, **kwargs):
        return verify_accounts(self.manifest, self.program, self.programdata, self.mint, **kwargs)

    def test_exact_usdc_profiles_and_explicit_local_profile(self):
        for network, mint in MINTS.items():
            self.assertEqual(make_profile(network, self.program_id, self.genesis)['mint'], mint)
            with self.assertRaises(ValueError):
                make_profile(network, self.program_id, self.genesis, self.pd)
        with self.assertRaises(ValueError):
            make_profile('local-synthetic', self.program_id, self.genesis)
        with self.assertRaises(ValueError):
            make_profile('local-synthetic', self.program_id, self.genesis, MINTS['mainnet-usdc'])
        self.assertEqual(make_profile('local-synthetic', self.program_id, self.genesis, self.pd)['mint'], self.pd)

    def test_base58_exact_canonical_width(self):
        for raw in (bytes(32), bytes(range(32)), bytes([255]) * 32):
            self.assertEqual(decode_key(encode_key(raw)), raw)
        for value in ('', '0' * 32, '1' * 33, 'z' * 44):
            with self.assertRaises(ValueError):
                decode_key(value)

    def test_immutable_elf_padding_and_issuer_freeze_authority_reported(self):
        receipt = self.verify()
        self.assertTrue(receipt['immutable'])
        self.assertEqual(receipt['mint_freeze_authority'], self.authority)
        self.assertEqual(receipt['programdata_address'], self.pd)

    def test_exact_authority_for_prefreeze_and_default_rejects_mutable(self):
        self.programdata = account(LOADER, struct.pack('<IQB', 3, 10, 1) + decode_key(self.authority) + self.code)
        with self.assertRaises(ValueError):
            self.verify()
        self.assertFalse(self.verify(expected_upgrade_authority=self.authority)['immutable'])
        with self.assertRaises(ValueError):
            self.verify(expected_upgrade_authority=self.pd)

    def test_wrong_code_extra_payload_truncated_and_wrong_loader_rejected(self):
        for payload in (self.code[:-1], self.code + b'\1', self.code[:-1] + b'\xff'):
            self.programdata = account(LOADER, struct.pack('<IQB', 3, 10, 0) + bytes(32) + payload)
            with self.assertRaises(ValueError):
                self.verify()
        self.setUp()
        self.program['owner'] = TOKEN
        with self.assertRaises(ValueError):
            self.verify()

    def test_wrong_mint_token2022_decimals_and_uninitialized_rejected(self):
        for key, value in (('mint', self.pd), ('decimals', 9), ('token_program', self.pd)):
            altered = copy.deepcopy(self.manifest)
            altered['profile'][key] = value
            with self.assertRaises(ValueError):
                verify_accounts(altered, self.program, self.programdata, self.mint)
        for offset, value in ((44, 9), (45, 0), (46, 2)):
            raw = bytearray(base64.b64decode(self.mint['data'][0])); raw[offset] = value
            with self.assertRaises(ValueError):
                verify_accounts(self.manifest, self.program, self.programdata, account(TOKEN, bytes(raw)))
        altered = copy.deepcopy(self.mint); altered['owner'] = self.pd
        with self.assertRaises(ValueError):
            verify_accounts(self.manifest, self.program, self.programdata, altered)

    def rpc(self, genesis=None, slot=20, program=None):
        def call(method, params):
            if method == 'getGenesisHash':
                return self.genesis if genesis is None else genesis
            if method == 'getAccountInfo':
                self.assertEqual(params, [self.program_id, {'encoding': 'base64', 'commitment': 'finalized'}])
                return {'context': {'slot': 15}, 'value': self.program}
            self.assertEqual(method, 'getMultipleAccounts')
            self.assertEqual(params[0], [self.program_id, self.pd, MINTS['mainnet-usdc']])
            self.assertEqual(params[1], {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': 15})
            return {'context': {'slot': slot}, 'value': [program or self.program, self.programdata, self.mint]}
        return call

    def test_coherent_rpc_chain_identity_and_finalized_context(self):
        self.assertEqual(verify_rpc(self.manifest, self.rpc())['context_slot'], 20)
        for rpc in (self.rpc(genesis=self.pd), self.rpc(slot=14),
                    self.rpc(program=account(LOADER, struct.pack('<I', 2) + decode_key(self.authority), True))):
            with self.assertRaises(ValueError):
                verify_rpc(self.manifest, rpc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
