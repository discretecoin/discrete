"""Local C/SBPFv0 versus Rust/SBPFv3 contract-equivalence checks.

Both VMs use identical synthetic keys and the unchanged original Fixture. Account
mutation is confined to this in-process VM and explicitly marked below. No RPC.
Compute units and logs may differ; complete persisted account data must agree.
"""
import hashlib
import pathlib
import unittest
from unittest.mock import patch

import test_solana_vm as base

ROOT = pathlib.Path(__file__).resolve().parent
BASELINE = ROOT.parent.parent / 'swap-localnet-v04'
EXPECTED = {
    BASELINE / 'solana_escrow.so': '91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89',
    ROOT / 'solana_escrow.so': '30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7',
}
REAL_KEYPAIR = base.Keypair
EXTRA = REAL_KEYPAIR.from_seed(bytes([48]) * 32).pubkey()


class FixedKeys:
    def __init__(self):
        self.index = 20

    def __call__(self):
        self.index += 1
        return REAL_KEYPAIR.from_seed(bytes([self.index]) * 32)

    from_seed = staticmethod(REAL_KEYPAIR.from_seed)


def fixture(directory):
    with patch.object(base, 'ROOT', directory), patch.object(base, 'Keypair', FixedKeys()):
        return base.Fixture()


def accounts(f):
    result = {}
    for name in ('state', 'vault', 'source', 'claim', 'refund', 'mint', 'payer', 'relayer'):
        key = getattr(f, name).pubkey()
        a = f.vm.get_account(key)
        result[name] = (str(key), a.lamports, str(a.owner), a.executable, a.rent_epoch, bytes(a.data))
    return result


def protected(f):
    return {k: v for k, v in accounts(f).items() if k not in ('payer', 'relayer')}


def expected_state(f, status):
    return (b'XDSV0001' + bytes([status, f.bump]) + bytes(6) + base.u64(f.amount)
            + base.u64(f.deadline) + base.sha(f.secret) + bytes(f.vault.pubkey())
            + bytes(f.mint.pubkey()) + bytes(f.claim.pubkey()) + bytes(f.refund.pubkey()))


def metas_changed(ix, index, *, writable=None, signer=None):
    metas = list(ix.accounts)
    old = metas[index]
    metas[index] = base.Meta(old.pubkey, old.is_signer if signer is None else signer,
                            old.is_writable if writable is None else writable)
    return base.Instruction(base.PID, ix.data, metas)


class DifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path, digest in EXPECTED.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise AssertionError(f'artifact identity mismatch: {path}')

    def pair(self):
        pair = [fixture(BASELINE), fixture(ROOT)]
        self.assertEqual(accounts(pair[0]), accounts(pair[1]))
        return pair

    def same(self, pair, action, custom=None):
        errors = []
        for f in pair:
            before = protected(f)
            result = action(f)
            if custom is not None:
                self.assertIsInstance(result, base.FailedTransactionMetadata)
                self.assertIn(f'InstructionErrorCustom({4096 + custom})', str(result.err()))
                self.assertEqual(protected(f), before, 'rejection changed protected accounts')
                errors.append(str(result.err()))
            else:
                self.assertNotIsInstance(result, base.FailedTransactionMetadata)
        if errors:
            self.assertEqual(errors[0], errors[1])
        self.assertEqual(accounts(pair[0]), accounts(pair[1]))

    def state(self, pair, status):
        for f in pair:
            self.assertEqual(f.vm.get_account(f.state.pubkey()).data, expected_state(f, status))

    def test_fund_claim_tombstone_and_next_transfer_full_accounts(self):
        pair = self.pair()
        self.same(pair, lambda f: f.fund())
        self.state(pair, 1)
        self.same(pair, lambda f: f.send([f.ix(1, b'\x01' + bytes(32))], payer=f.relayer, ok=False), 14)
        self.same(pair, lambda f: f.send([f.ix(1)], payer=f.relayer))
        self.state(pair, 2)
        self.same(pair, lambda f: f.send([base.Instruction(base.TOKEN, b'\x0c' + base.u64(f.amount) + b'\x06', [
            base.Meta(f.claim.pubkey(), False, True), base.Meta(f.mint.pubkey(), False, False),
            base.Meta(f.refund.pubkey(), False, True), base.Meta(f.relayer.pubkey(), True, False)])], payer=f.relayer))
        for f in pair:
            self.assertEqual(f.balance(f.claim), 0)
            self.assertEqual(f.balance(f.refund), f.amount)
            f.vm.expire_blockhash()
        self.same(pair, lambda f: f.send([f.ix(1)], payer=f.relayer, ok=False), 12)
        self.state(pair, 2)

    def test_refund_boundary_and_claim_after_deadline_full_state(self):
        for winner in (1, 2):
            with self.subTest(winner=winner):
                pair = self.pair()
                self.same(pair, lambda f: f.fund())
                for f in pair:
                    f.vm.warp_to_slot(f.deadline - 1)
                self.same(pair, lambda f: f.send([f.ix(2)], payer=f.relayer, ok=False), 15)
                for f in pair:
                    f.vm.warp_to_slot(f.deadline)
                    f.vm.expire_blockhash()
                self.same(pair, lambda f: f.send([f.ix(winner)], payer=f.relayer))
                self.state(pair, 2 if winner == 1 else 3)
                self.same(pair, lambda f: f.send([f.ix(3 - winner)], payer=f.relayer, ok=False), 12)

    def test_all_custom_error_boundaries_preserve_full_accounts(self):
        # Isolated fixture mutations model invalid inputs/state, not reachable
        # production operations. Each row starts with two fresh identical VMs.
        cases = [
            ('nine_accounts', 1, False, None, lambda f: f.ix(0, keys=f.keys[:-1])),
            ('eleven_accounts', 1, False, None, lambda f: f.ix(0, keys=f.keys + [EXTRA])),
            ('empty_instruction', 2, False, None, lambda f: f.ix(0, b'')),
            ('alias', 3, False, None, lambda f: f.ix(0, keys=f.keys[:4] + [f.keys[3]] + f.keys[5:])),
            ('state_readonly', 4, False, None, lambda f: metas_changed(f.ix(0), 0, writable=False)),
            ('mint_decimals', 5, False, lambda f: f.mutate(f.mint, 44, b'\x05'), lambda f: f.ix(0)),
            ('clock_id', 6, False, None, lambda f: f.ix(0, keys=f.keys[:9] + [base.Pubkey.default()])),
            ('authority_id', 7, False, None, lambda f: f.ix(0, keys=f.keys[:7] + [EXTRA] + f.keys[8:])),
            ('vault_delegate', 8, False, lambda f: f.mutate(f.vault, 72, b'\x01\0\0\0'), lambda f: f.ix(0)),
            ('source_delegate', 9, False, lambda f: f.mutate(f.source, 72, b'\x01\0\0\0'), lambda f: f.ix(0)),
            ('zero_amount', 10, False, None, lambda f: f.ix(0, b'\0' + base.u64(0) + base.u64(f.deadline) + base.sha(f.secret))),
            ('unknown_op', 11, True, None, lambda f: f.ix(1, b'\x03')),
            ('state_reserved', 12, True, lambda f: f.mutate(f.state, 10, b'\x01'), lambda f: f.ix(1)),
            ('claim_length', 13, True, None, lambda f: f.ix(1, b'\x01' + f.secret[:-1])),
            ('wrong_hash', 14, True, None, lambda f: f.ix(1, b'\x01' + bytes(32))),
            ('early_refund', 15, True, None, lambda f: f.ix(2)),
            ('destination_frozen', 16, True, lambda f: f.mutate(f.claim, 108, b'\x02'), lambda f: f.ix(1)),
            ('insufficient_vault', 17, True, lambda f: f.mutate(f.vault, 64, base.u64(0)), lambda f: f.ix(1)),
            ('destination_overflow', 18, True, lambda f: f.mutate(f.claim, 64, base.u64(2**64 - 1)), lambda f: f.ix(1)),
        ]
        for name, code, funded, mutation, instruction in cases:
            with self.subTest(name=name, custom=4096 + code):
                pair = self.pair()
                if funded:
                    self.same(pair, lambda f: f.fund())
                if mutation:
                    for f in pair:
                        mutation(f)
                self.same(pair, lambda f: f.send([instruction(f)], [] if funded else [f.state],
                                                payer=f.relayer if funded else f.payer, ok=False), code)

    def test_c_permitted_source_close_authority_and_destination_fields(self):
        for winner in (1, 2):
            with self.subTest(winner=winner):
                pair = self.pair()
                for f in pair:
                    # Synthetic valid token account fields: C only rejects the
                    # vault close authority and source delegate. It binds the
                    # destination address, not its internal token owner/delegate.
                    f.mutate(f.source, 129, b'\x01\0\0\0' + bytes(EXTRA))
                    for destination in (f.claim, f.refund):
                        f.mutate(destination, 32, bytes(EXTRA))
                        f.mutate(destination, 72, b'\x01\0\0\0' + bytes(EXTRA))
                        f.mutate(destination, 129, b'\x01\0\0\0' + bytes(EXTRA))
                self.same(pair, lambda f: f.fund())
                self.state(pair, 1)
                for f in pair:
                    f.vm.warp_to_slot(f.deadline)
                self.same(pair, lambda f: f.send([f.ix(winner)], payer=f.relayer))
                self.state(pair, 2 if winner == 1 else 3)
                for f in pair:
                    self.assertEqual(f.balance(f.claim if winner == 1 else f.refund), f.amount)


if __name__ == '__main__':
    unittest.main(verbosity=2)
