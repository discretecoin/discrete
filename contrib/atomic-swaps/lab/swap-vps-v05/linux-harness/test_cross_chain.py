"""Four local protocol executions across native XDS Core and BTC regtest / Solana SBF.
Tests are real local ledger transitions; chain timing/finality envelopes remain fixture policy.
"""
import json,os,pathlib,subprocess,time,unittest
from swap_journal import Admission,Journal,digest
import test_bitcoin_regtest as bitcoin_tests
from bitcoin_adapter import spend,sha
from test_solana_vm import Fixture
from runtime_paths import SWAP_CHAIN_TESTS,CREATE_NO_WINDOW
ROOT=pathlib.Path(__file__).resolve().parent

class CrossChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bitcoin_tests.BitcoinRegtest.setUpClass();cls.b=bitcoin_tests.BitcoinRegtest('test_refund_candidate_height_boundary')
    @classmethod
    def tearDownClass(cls):bitcoin_tests.BitcoinRegtest.tearDownClass()
    def core_leg(self,secret,foreign,refund=False):
        run=ROOT/'pair-runs'/str(time.time_ns());run.mkdir(parents=True)
        out=(run/'core.log').open('wb')
        p=subprocess.Popen([str(SWAP_CHAIN_TESTS),'--pair-session','pair'],cwd=run,
          stdin=subprocess.PIPE,stdout=out,stderr=out,text=True,creationflags=CREATE_NO_WINDOW)
        j=None
        try:
            p.stdin.write(sha(secret).hex()+'\n');p.stdin.flush()
            def receipt_file(name):
                deadline=time.monotonic()+30
                while not (run/name).exists():
                    if p.poll() is not None:raise AssertionError('Core pair exited: '+(run/'core.log').read_text(errors='replace'))
                    if time.monotonic()>deadline:raise TimeoutError('Core receipt: '+name)
                    time.sleep(.025)
                return json.loads((run/name).read_text())
            funding=receipt_file('pair.funded.json')
            self.assertGreaterEqual(funding['confirmations'],11)
            self.assertEqual(funding['hashlock'],sha(secret).hex())
            j=Journal(run/'journal.db',bytes([23])*32,True);j.register('pair',{'foreign':foreign,'xds':funding})
            artifact=b'REFUND' if refund else secret.hex().encode()
            admission=Admission(funding['confirmations'],60,120,120,600,True,True,True)
            kind='handoff-refund' if refund else 'xds-pair-claim'
            j.prepare('pair',kind,artifact,digest(artifact),not refund,admission)
            def send(raw,tid):
                self.assertEqual(j.exposed('pair'),not refund)
                p.stdin.write(raw.decode()+'\n');p.stdin.flush()
            j.broadcast('pair',kind,send,admission_supplier=lambda:admission)
            prepared=receipt_file('pair.prepared.json');signed=bytes.fromhex(prepared['wire'])
            kind='xds-refund' if refund else 'xds-claim'
            j.prepare('pair',kind,signed,prepared['txid'],not refund,admission)
            def commit(raw,tid):
                self.assertEqual(raw,signed);self.assertEqual(tid,prepared['txid'])
                p.stdin.write('COMMIT '+tid+'\n');p.stdin.flush()
            j.broadcast('pair',kind,commit,admission_supplier=lambda:admission);p.stdin.close()
            self.assertEqual(p.wait(timeout=30),0)
            receipt=json.loads((run/'pair.settled.json').read_text())
            self.assertEqual(receipt['txid'],prepared['txid']);j.reconcile('pair',kind,receipt['txid'],'confirmed')
            self.assertEqual(receipt['hashlock'],sha(secret).hex());self.assertEqual(receipt['net_atoms'],1000)
            self.assertEqual(receipt['fee_atoms'],1);self.assertEqual(receipt['mode'],'refund' if refund else 'claim')
            if refund:self.assertEqual(receipt['observed_preimage'],'')
            else:self.assertEqual(bytes.fromhex(receipt['observed_preimage']),secret)
            return receipt
        finally:
            if p.poll() is None:p.terminate();p.wait(timeout=5)
            if p.stdin and not p.stdin.closed:p.stdin.close()
            out.close()
            if j:j.close()
    def test_xds_bitcoin_success_preimage_observed_from_mined_xds_claim(self):
        b=self.b;f=b.fund(200);b.n.mine(5)
        receipt=self.core_leg(f[1],{'network':'bitcoin-regtest','txid':f[2],'vout':f[3]})
        observed=bytes.fromhex(receipt['observed_preimage'])
        raw,txid=spend(f[0],f[2],f[3],f[4],b.dest,b.a,observed)
        self.assertEqual(b.n.rpc('sendrawtransaction',raw),txid);b.n.mine()
        self.assertIsNotNone(b.n.rpc('gettxout',txid,0));self.assertIsNone(b.n.rpc('gettxout',f[2],f[3]))
    def test_xds_bitcoin_abandonment_returns_both_owners(self):
        b=self.b;f=b.fund(200);b.n.mine(5)
        self.core_leg(f[1],{'network':'bitcoin-regtest','txid':f[2],'vout':f[3]},True)
        if b.n.height()<f[0].refund_height:b.n.mine(f[0].refund_height-b.n.height())
        raw,txid=b.build(f,False);b.n.rpc('sendrawtransaction',raw);b.n.mine()
        self.assertIsNotNone(b.n.rpc('gettxout',txid,0));self.assertIsNone(b.n.rpc('gettxout',f[2],f[3]))
    def test_xds_solana_token_success_uses_observed_xds_preimage(self):
        f=Fixture();f.deadline=f.vm.get_clock().slot+100_000;f.fund()
        receipt=self.core_leg(f.secret,{'network':'solana-litesvm-test-mint','state':str(f.state.pubkey()),'vault':str(f.vault.pubkey())})
        f.send([f.ix(1,b'\x01'+bytes.fromhex(receipt['observed_preimage']))],payer=f.relayer)
        self.assertEqual(f.status(),2);self.assertEqual(f.balance(f.claim),f.amount);self.assertEqual(f.balance(f.vault),0)
    def test_xds_solana_token_abandonment_returns_both_owners(self):
        f=Fixture();f.deadline=f.vm.get_clock().slot+100_000;f.fund()
        self.core_leg(f.secret,{'network':'solana-litesvm-test-mint','state':str(f.state.pubkey()),'vault':str(f.vault.pubkey())},True)
        f.vm.warp_to_slot(f.deadline);f.send([f.ix(2)],payer=f.relayer)
        self.assertEqual(f.status(),3);self.assertEqual(f.balance(f.refund),f.amount);self.assertEqual(f.balance(f.vault),0)

if __name__=='__main__':unittest.main(verbosity=2)
