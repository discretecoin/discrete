"""Execute the selected ELF with the 13 original CPI tests and profile guards.

XDS_SOLANA_BUILD selects a build output. All balances and mints are synthetic
LiteSVM fixtures, including a fixture placed at an official USDC mint address.
This does not contact Circle, RPC, devnet or mainnet.
"""
import importlib.util
import json
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = os.environ.get('XDS_SOLANA_BUILD')
if not BUILD:
    raise unittest.SkipTest('Set XDS_SOLANA_BUILD to a freshly built profile directory for VM qualification')
BUILD = Path(BUILD)
manifest = json.loads((BUILD / 'build-manifest.json').read_text())
import hashlib
if hashlib.sha256((BUILD / 'solana_escrow.so').read_bytes()).hexdigest() != manifest['artifact']['sha256']:
    raise AssertionError('Selected build artifact does not match manifest')
donor = ROOT.parent / 'lab/swap-vps-v05/sbf-v3/test_solana_vm.py'
spec = importlib.util.spec_from_file_location('frozen_vm_fixture', donor)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.ROOT = BUILD
base.PID = base.Pubkey.from_string(manifest['profile']['program_id'])
OriginalFixture = base.Fixture


class PublicMint:
    def __init__(self, key):
        self.key = key
    def pubkey(self):
        return self.key


class ProfileFixture(OriginalFixture):
    def __init__(self):
        super().__init__()
        selected_mint = base.Pubkey.from_string(manifest['profile']['mint'])
        if selected_mint == self.mint.pubkey():
            return
        # VM genesis/state setup only: relocate this synthetic mint and its token
        # account references. Actual transfers/freezes still execute SPL Token CPI.
        self.vm.set_account(selected_mint, self.vm.get_account(self.mint.pubkey()))
        for token in (self.vault, self.source, self.claim, self.refund):
            self.mutate(token, 0, bytes(selected_mint))
        self.mint = PublicMint(selected_mint)
        self.keys[2] = selected_mint


base.Fixture = ProfileFixture
SolanaVmTests = base.SolanaVmTests


class ProfileVmTests(unittest.TestCase):
    def test_destination_freeze_and_thaw_preserve_each_branch_for_retry(self):
        for refund in (False, True):
            with self.subTest(refund=refund):
                f = ProfileFixture()
                f.fund()
                destination = f.refund if refund else f.claim
                if refund:
                    f.vm.warp_to_slot(f.deadline)
                f.freeze(destination, True)
                f.send([f.ix(2 if refund else 1)], payer=f.relayer, ok=False)
                self.assertEqual(f.status(), 1)
                self.assertEqual(f.balance(f.vault), f.amount)
                f.freeze(destination, False)
                f.vm.expire_blockhash()
                f.send([f.ix(2 if refund else 1)], payer=f.relayer)
                self.assertEqual(f.status(), 3 if refund else 2)
                self.assertEqual(f.balance(destination), f.amount)

    def test_unsolicited_surplus_does_not_change_principal_or_allow_reconsumption(self):
        f = ProfileFixture()
        f.fund()
        donation = 123
        f.send([base.Instruction(base.TOKEN, b'\x0c' + base.u64(donation) + b'\x06', [
            base.Meta(f.source.pubkey(), False, True), base.Meta(f.mint.pubkey(), False, False),
            base.Meta(f.vault.pubkey(), False, True), base.Meta(f.payer.pubkey(), True, False)])])
        f.send([f.ix(1)], payer=f.relayer)
        self.assertEqual(f.balance(f.claim), f.amount)
        self.assertEqual(f.balance(f.vault), donation)
        f.vm.warp_to_slot(f.deadline)
        f.send([f.ix(2)], payer=f.relayer, ok=False)
        self.assertEqual(f.balance(f.vault), donation)

    def test_same_elf_at_different_program_address_rejected(self):
        f = ProfileFixture()
        alternate = base.Keypair().pubkey()
        f.vm.add_program_from_file(alternate, BUILD / 'solana_escrow.so')
        original = f.ix(0)
        result = f.send([base.Instruction(alternate, original.data, original.accounts)], [f.state], ok=False)
        self.assertIn('Custom(4098)', str(result))
        self.assertEqual(f.status(), 0)
        self.assertEqual(f.balance(f.source), 10_000_000)


if __name__ == '__main__':
    unittest.main(verbosity=2)
