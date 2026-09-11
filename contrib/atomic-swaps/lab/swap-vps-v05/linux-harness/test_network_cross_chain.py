"""Foreign-first swaps: four real XDS daemons + wallet RPC and BTC regtest / local SBF.
All keys/assets are synthetic. Controlled block/slot budgets are not live-chain timing proof.
"""
import hashlib,json,pathlib,secrets,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT/'python-deps'))
import test_xds_wallet_network as xds_tests
import test_bitcoin_regtest as btc_tests
from bitcoin_adapter import Contract,pubkey,sha,spend
from test_solana_vm import Fixture,FailedTransactionMetadata,PID
from solders.transaction import Transaction

class NetworkCrossChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xds_tests.WalletNetwork.setUpClass();cls.x=xds_tests.WalletNetwork('runTest')
        try:
            btc_tests.BitcoinRegtest.setUpClass();cls.b=btc_tests.BitcoinRegtest('runTest')
            cls.b.n.rpc('createwallet','claimant')
            cls.claim_address=cls.b.n.rpc('getnewaddress',wallet='claimant')
            cls.claim_destination=bytes.fromhex(cls.b.n.rpc('getaddressinfo',cls.claim_address,wallet='claimant')['scriptPubKey'])
            if cls.claim_destination==cls.b.dest:raise AssertionError('independent BTC payouts required')
        except BaseException:xds_tests.WalletNetwork.tearDownClass();raise
    @classmethod
    def tearDownClass(cls):
        btc_tests.BitcoinRegtest.tearDownClass();xds_tests.WalletNetwork.tearDownClass()
    def register(self,c):
        self.x.journal.register(c['id'],{'xds':c['terms'],'foreign':c['foreign'],'fixture_only':True})
    def btc_funding(self):
        b=self.b;x=self.x;s=secrets.token_bytes(32);c=x.contract(s)
        x.alice.synced();c['alice_start_balance']=x.alice.balance()
        contract=Contract(sha(s),pubkey(b.a),pubkey(b.b),b.n.height()+200)
        script=contract.script();address=b.n.rpc('decodescript',script.hex())['segwit']['address']
        draft=b.n.rpc('createrawtransaction',[],{address:0.001})
        funded=b.n.rpc('fundrawtransaction',draft,{'lockUnspents':True},wallet=True)
        signed=b.n.rpc('signrawtransactionwithwallet',funded['hex'],wallet=True)
        self.assertTrue(signed['complete']);decoded=b.n.rpc('decoderawtransaction',signed['hex'])
        target=next(v for v in decoded['vout'] if v['scriptPubKey']['hex']=='0020'+sha(script).hex())
        c['foreign']={'network':'bitcoin-regtest','txid':decoded['txid'],'vout':target['n'],'script':script.hex(),'amount_sats':100000,
          'claim_payout_script':self.claim_destination.hex(),'refund_payout_script':b.dest.hex()}
        self.register(c);x.journal.prepare(c['id'],'foreign-fund',bytes.fromhex(signed['hex']),decoded['txid'])
        x.journal.broadcast(c['id'],'foreign-fund',lambda raw,tid:self.assertEqual(b.n.rpc('sendrawtransaction',raw.hex()),tid))
        b.n.mine(6);self.assertGreaterEqual(b.n.rpc('gettxout',decoded['txid'],target['n'])['confirmations'],6)
        x.journal.reconcile(c['id'],'foreign-fund',decoded['txid'],'confirmed')
        return c,(contract,s,decoded['txid'],target['n'],100000)
    def svm_funding(self):
        f=Fixture();f.secret=secrets.token_bytes(32);f.deadline=f.vm.get_clock().slot+100000
        c=self.x.contract(f.secret);tx=f.transaction([f.ix(0)],[f.state])
        self.x.alice.synced();c['alice_start_balance']=self.x.alice.balance()
        c['foreign']={'network':'owned-sbf-six-decimal-test-mint','program':str(PID),
          'state':str(f.state.pubkey()),'vault':str(f.vault.pubkey()),'mint':str(f.mint.pubkey()),'amount':f.amount,'deadline':f.deadline}
        self.register(c);j=self.x.journal
        j.prepare(c['id'],'foreign-fund',bytes(tx),str(tx.signatures[0]))
        self.svm_broadcast(c,'foreign-fund',f);self.assertEqual(f.status(),1);self.assertEqual(f.balance(f.vault),f.amount)
        j.reconcile(c['id'],'foreign-fund',str(tx.signatures[0]),'confirmed')
        return c,f
    def svm_broadcast(self,c,kind,f):
        def send(raw,tid):
            tx=Transaction.from_bytes(raw);self.assertEqual(str(tx.signatures[0]),tid)
            result=f.vm.send_transaction(tx);self.assertNotIsInstance(result,FailedTransactionMetadata)
        return self.x.journal.broadcast(c['id'],kind,send)
    def xds_funding(self,c):
        x=self.x;x.prepare_fund(c);x.relay(c,'xds-fund');x.mine(11)
        self.assertEqual(x.n.outpoint(c['fund']['tx_hash'])['confirmations'],11)
        x.journal.reconcile(c['id'],'xds-fund',c['fund']['tx_hash'],'confirmed')
    def observed_xds_claim(self,c):
        x=self.x;x.bob.synced();before=x.bob.balance();x.settle(c)
        xds_tests.wait_for(lambda:x.bob.balance()==before+1000,'actual wallet payout after cross-chain claim',60)
        txid=c['settlement']['tx_hash'];node=x.net.nodes[3]
        raw=node.call('/gettransactions',{'txs_hashes':[txid]})
        self.assertEqual(raw['status'],'OK');self.assertEqual(raw['txs_as_hex'],[c['settlement']['tx_as_hex']])
        r=node.call('/get_transaction_details_by_hash',{'hash':txid});d=r['transaction']
        self.assertTrue(d['inBlockchain']);self.assertEqual(d['hash'],txid);self.assertEqual(d['fee'],1)
        self.assertEqual(d['blockHash'],node.outpoint(txid)['block_hash']);self.assertEqual(d['txType'],5)
        input=d['inputs'][0];self.assertEqual(input['type'],'20');w=input['data']['input']
        self.assertEqual(w['prev_txid'],c['fund']['tx_hash']);self.assertEqual(w['prev_out_index'],0);self.assertEqual(w['branch'],1)
        observed=bytes.fromhex(w['secret']);self.assertEqual(sha(observed).hex(),c['terms']['hashlock'])
        (x.net.directory/(c['id']+'.public-claim.json')).write_text(json.dumps({'raw':raw,'details':r}),encoding='utf-8')
        return observed
    def test_btc_success_uses_public_mined_xds_witness(self):
        c,f=self.btc_funding();self.xds_funding(c);observed=self.observed_xds_claim(c)
        claimant_before=self.b.n.rpc('getbalance',wallet='claimant')
        raw,tid=spend(f[0],f[2],f[3],f[4],self.claim_destination,self.b.a,observed)
        j=self.x.journal;j.prepare(c['id'],'foreign-claim',bytes.fromhex(raw),tid,True)
        j.broadcast(c['id'],'foreign-claim',lambda wire,txid:self.assertEqual(self.b.n.rpc('sendrawtransaction',wire.hex()),txid))
        self.b.n.mine();self.assertIsNone(self.b.n.rpc('gettxout',f[2],f[3]));self.assertIsNotNone(self.b.n.rpc('gettxout',tid,0))
        self.assertEqual(self.b.n.rpc('gettxout',tid,0)['scriptPubKey']['hex'],self.claim_destination.hex())
        received=self.b.n.rpc('gettransaction',tid,wallet='claimant')
        self.assertGreaterEqual(received['confirmations'],1)
        self.assertEqual(received['amount'],btc_tests.Decimal('0.00099000'))
        self.assertEqual(self.b.n.rpc('getbalance',wallet='claimant')-claimant_before,received['amount'])
        j.reconcile(c['id'],'foreign-claim',tid,'confirmed')
    def test_btc_abandonment_refunds_both_original_owners(self):
        c,f=self.btc_funding();self.xds_funding(c);self.x.mine(c['terms']['refund_height']-self.x.n.info()['height'])
        self.x.settle(c,True);self.b.n.mine(f[0].refund_height-self.b.n.height())
        self.x.alice.synced();self.assertEqual(self.x.alice.balance(),c['alice_start_balance']-2)
        raw,tid=self.b.build(f,False);j=self.x.journal;j.prepare(c['id'],'foreign-refund',bytes.fromhex(raw),tid)
        j.broadcast(c['id'],'foreign-refund',lambda wire,txid:self.assertEqual(self.b.n.rpc('sendrawtransaction',wire.hex()),txid))
        self.b.n.mine();self.assertIsNotNone(self.b.n.rpc('gettxout',tid,0));self.assertFalse(j.exposed(c['id']))
        self.assertEqual(self.b.n.rpc('gettxout',tid,0)['scriptPubKey']['hex'],self.b.dest.hex())
        received=self.b.n.rpc('gettransaction',tid,wallet=True)
        self.assertGreaterEqual(received['confirmations'],1);self.assertEqual(received['amount'],btc_tests.Decimal('0.00099000'))
    def test_sbf_token_success_uses_public_mined_xds_witness(self):
        c,f=self.svm_funding();self.xds_funding(c);observed=self.observed_xds_claim(c)
        tx=f.transaction([f.ix(1,b'\x01'+observed)],payer=f.relayer)
        self.x.journal.prepare(c['id'],'foreign-claim',bytes(tx),str(tx.signatures[0]),True)
        self.svm_broadcast(c,'foreign-claim',f);self.assertEqual(f.status(),2);self.assertEqual(f.balance(f.claim),f.amount)
        self.assertEqual(f.balance(f.vault),0)
    def test_sbf_token_abandonment_refunds_both_original_owners(self):
        c,f=self.svm_funding();self.xds_funding(c);self.x.mine(c['terms']['refund_height']-self.x.n.info()['height'])
        self.x.settle(c,True);f.vm.warp_to_slot(f.deadline);tx=f.transaction([f.ix(2)],payer=f.relayer)
        self.x.alice.synced();self.assertEqual(self.x.alice.balance(),c['alice_start_balance']-2)
        self.x.journal.prepare(c['id'],'foreign-refund',bytes(tx),str(tx.signatures[0]))
        self.svm_broadcast(c,'foreign-refund',f);self.assertEqual(f.status(),3);self.assertEqual(f.balance(f.refund),f.amount)
        self.assertEqual(f.balance(f.vault),0);self.assertFalse(self.x.journal.exposed(c['id']))

if __name__=='__main__':unittest.main(verbosity=2)
