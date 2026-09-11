"""Real owned four-process XDS network and encrypted wallet RPC; synthetic funds only.
Admission budgets below are controlled block-count fixture policy, not a production SLA.
"""
import hashlib,json,pathlib,secrets,shutil,sys,time,unittest
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'python-deps'))
from xds_localnet import Network,wait_for,http
from swap_journal import Admission,Journal

class WalletNetwork(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net=Network();cls.n=cls.net.nodes[0];cls.treasury=bytes.fromhex('99'*32)
        try:
            cls.alice_seed=bytes.fromhex('31'*32)
            cls.n.mine(1,cls.alice_seed);cls.n.mine(15,cls.treasury);cls.net.same_tip()
            cls.alice=cls.net.wallet('alice',cls.alice_seed)
            cls.bob=cls.net.wallet('bob',bytes.fromhex('32'*32),1)
            wait_for(lambda:cls.alice.balance()>7000,'scanned mature Alice coinbase',90)
            cls.alice.call('store')
            cls.old_backup=cls.net.directory/'alice-before-swaps.wallet'
            shutil.copyfile(cls.alice.path,cls.old_backup)
            cls.journal=Journal(cls.net.directory/'coordinator.db',bytes.fromhex('41'*32),True)
            print('network_run='+str(cls.net.directory),flush=True)
        except BaseException:cls.net.close();raise
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'journal'):cls.journal.close()
        cls.net.close()
    def mine(self,count=1):
        self.n.mine(count,self.treasury);return self.net.same_tip()
    def contract(self,secret=None,delay=32):
        secret=secret or secrets.token_bytes(32);rho_a=secrets.token_bytes(32);rho_b=secrets.token_bytes(32)
        a=self.alice.role(rho_a);b=self.bob.role(rho_b)
        self.assertEqual(a['genesis_hash'],b['genesis_hash'])
        terms={'principal_atoms':1001,'refund_height':self.n.info()['height']+delay,
          'hashlock':hashlib.sha256(secret).hexdigest(),'nonce':secrets.token_hex(32),
          'claim_commitment':b['commitment'],'refund_rho':rho_a.hex(),'genesis_hash':a['genesis_hash']}
        return {'terms':terms,'secret':secret,'rho_a':rho_a,'rho_b':rho_b,'a':a,'b':b,'id':terms['nonce']}
    def prepare_fund(self,c):
        p=wait_for(lambda:self.alice.call('swap_prepare_funding',c['terms']),'wallet funding preparation',45)
        self.assertEqual(p['fee_atoms'],1);self.assertEqual(p['principal_atoms'],1001)
        c['fund']=p
        self.journal.register(c['id'],{'xds':c['terms'],'foreign':c.get('foreign'),'fixture_only':True})
        self.journal.prepare(c['id'],'xds-fund',bytes.fromhex(p['tx_as_hex']),p['tx_hash'])
        return p
    def relay(self,c,kind,admission=None,lost_response=False):
        def send(raw,tid):
            self.assertEqual(self.journal.intent(c['id'],kind)['stage'],'attempt-started')
            r=self.n.submit_exact(raw.hex(),tid)
            self.assertTrue(r['accepted_locally'])
            if lost_response:raise TimeoutError('deliberately lost response after local acceptance')
            return r
        return self.journal.broadcast(c['id'],kind,send,admission_supplier=admission)
    def fund(self,secret=None,delay=32):
        c=self.contract(secret,delay);self.prepare_fund(c);self.relay(c,'xds-fund');self.mine()
        for n in self.net.nodes:
            o=n.outpoint(c['fund']['tx_hash']);self.assertTrue(o['in_chain']);self.assertFalse(o['spent'])
            self.assertEqual(o['amount_atoms'],1001);self.assertEqual(o['tx_as_hex'],c['fund']['tx_as_hex'])
        self.journal.reconcile(c['id'],'xds-fund',c['fund']['tx_hash'],'confirmed')
        return c
    def admission(self,c):
        o=self.n.outpoint(c['fund']['tx_hash'])
        return Admission(o['confirmations'],2,c['terms']['refund_height']-o['height'],2,100,
          o['in_chain'] and o['spent_known'] and not o['spent'] and not o['spent_in_pool'],True,True)
    def spend_params(self,c,refund=False):
        return {'funding_txid':c['fund']['tx_hash'],'output_index':0,'branch':2 if refund else 1,
          'rho':c['rho_a' if refund else 'rho_b'].hex(),'secret':'' if refund else c['secret'].hex(),
          'genesis_hash':c['terms']['genesis_hash']}
    def prepare_spend(self,c,refund=False):
        w=self.alice if refund else self.bob
        p=w.call('swap_prepare_spend',self.spend_params(c,refund));self.assertEqual(p['fee_atoms'],1)
        self.assertEqual(p['principal_atoms'],1001)
        kind='xds-refund' if refund else 'xds-claim'
        self.journal.prepare(c['id'],kind,bytes.fromhex(p['tx_as_hex']),p['tx_hash'],not refund)
        c['settlement']=p;return p
    def settle(self,c,refund=False):
        self.prepare_spend(c,refund);kind='xds-refund' if refund else 'xds-claim'
        self.relay(c,kind,lambda:self.admission(c));self.mine()
        self.journal.reconcile(c['id'],kind,c['settlement']['tx_hash'],'confirmed')
        for n in self.net.nodes:self.assertTrue(n.outpoint(c['fund']['tx_hash'])['spent'])
        return c['settlement']
    def test_01_claim_scans_then_existing_ordinary_transfer(self):
        before=self.bob.balance();c=self.fund();self.mine(10)
        self.assertEqual(self.admission(c).confirmations,11)
        self.settle(c)
        wait_for(lambda:self.bob.balance()==before+1000,'claimed payout scanned',60)
        self.mine(3)
        ordinary=self.bob.call('transfer',{'destinations':[{'address':c['a']['address'],'amount':900}],
          'fee':1,'unlock_height':0,'payment_id':'','extra':''})
        self.mine()
        wait_for(lambda:self.bob.balance()==before+99,'ordinary transfer change scanned',60)
        self.assertTrue(self.n.outpoint(ordinary['tx_hash'])['in_chain'])
    def test_02_refund_wrong_secret_role_network_and_height(self):
        before=self.alice.balance();c=self.fund(delay=18)
        p=self.spend_params(c)
        for changes in ({'secret':'00'*32},{'rho':'00'*32},{'genesis_hash':'00'*32}):
            with self.assertRaises(RuntimeError):self.bob.call('swap_prepare_spend',p|changes)
        with self.assertRaises(RuntimeError):self.alice.call('swap_prepare_spend',self.spend_params(c,True))
        self.mine(c['terms']['refund_height']-self.n.info()['height'])
        self.settle(c,True)
        wait_for(lambda:self.alice.balance()==before-2,'refunded payout scanned',60)
        self.assertFalse(self.journal.exposed(c['id']))
    def test_03_lost_response_exact_retry_and_pending_conflict(self):
        c=self.contract();p=self.prepare_fund(c)
        competing=self.contract();q=self.prepare_fund(competing)
        with self.assertRaises(TimeoutError):self.relay(c,'xds-fund',lost_response=True)
        self.assertEqual(self.journal.intent(c['id'],'xds-fund')['status'],'unknown')
        duplicate=self.n.submit_exact(p['tx_as_hex'],p['tx_hash'])
        self.assertTrue(self.n.outpoint(p['tx_hash'])['in_pool'])
        with self.assertRaisesRegex(RuntimeError,'Failed to process tx'):self.n.submit(q['tx_as_hex'])
        self.assertFalse(self.n.outpoint(q['tx_hash'])['found'])
        self.mine(11);self.settle(c)
        self.assertEqual(self.journal.intent(c['id'],'xds-fund')['payload'].hex(),p['tx_as_hex'])
        self.assertTrue(duplicate['accepted_locally'])
    def test_04_partition_competing_branches_rejoin_and_restart(self):
        shared=self.net.same_tip();self.net.partition([[0,1],[2,3]])
        try:
            left=self.n.mine(2,self.treasury)[-1]
            right=self.net.nodes[2].mine(3,bytes.fromhex('98'*32))[-1]
            self.net.same_tip([0,1],left);self.net.same_tip([2,3],right)
            self.assertNotEqual(left,right)
        finally:self.net.reconnect()
        joined=self.net.same_tip(expected=right);self.assertEqual(joined['height'],shared['height']+3)
        self.net.nodes[3].stop(kill=True);self.net.nodes[3].start()
        wait_for(self.net.nodes[3].ready,'node after abrupt stop')
        self.net.same_tip(expected=right)
        self.mine()
    def test_05_wallet_saved_backup_and_seed_restore(self):
        self.alice.synced()
        expected=wait_for(lambda:self.alice.balance(),'Alice observed balance',60)
        rho=bytes.fromhex('43'*32);role=self.alice.role(rho)
        self.assertTrue(self.alice.call('store')['stored'])
        backup=self.net.directory/'alice-saved.wallet';shutil.copyfile(self.alice.path,backup)
        self.alice.stop();self.alice.start()
        wait_for(lambda:self.alice.balance()==expected,'encrypted wallet reopen scan',60)
        self.assertEqual(self.alice.role(rho),role)
        restored=self.net.wallet('alice-from-seed',self.alice_seed,2)
        wait_for(lambda:restored.balance()==expected,'seed restore rescanned balance',90)
        self.assertEqual(restored.role(rho),role)
        self.alice.stop();shutil.copyfile(backup,self.alice.path);self.alice.start()
        wait_for(lambda:self.alice.balance()==expected,'saved wallet backup reopen scan',60)
        self.alice.stop();shutil.copyfile(self.old_backup,self.alice.path);self.alice.start()
        self.alice.synced()
        self.assertEqual(self.alice.balance(),expected)
        self.assertEqual(self.alice.role(rho),role)
    def test_06_first_exposure_admission_and_rpc_request_guards(self):
        c=self.fund();self.prepare_spend(c)
        with self.assertRaises(ValueError):self.relay(c,'xds-claim',lambda:self.admission(c))
        self.assertFalse(self.journal.exposed(c['id']))
        self.assertEqual(self.journal.intent(c['id'],'xds-claim')['stage'],'prepared')
        for headers in ({'Origin':'https://example.invalid'},{'Content-Type':'text/plain'},
                        {'Content-Type':'application/jsonx'}):
            with self.assertRaises(RuntimeError):self.bob.call('swap_role',{'rho':'11'*32},headers=headers)
        with self.assertRaises(RuntimeError):
            http(self.bob.rpc,'/json_rpc',{'jsonrpc':'2.0','id':1,'method':'swap_role','params':{'rho':'11'*32}})
        self.mine(10);self.relay(c,'xds-claim',lambda:self.admission(c));self.mine()
        self.assertTrue(self.journal.exposed(c['id']))

    def test_07_live_funding_reorg_gates_secret_then_exact_funding_retry(self):
        c=self.contract();self.prepare_fund(c);self.net.same_tip()
        self.net.partition([[0,1],[2,3]])
        try:
            self.relay(c,'xds-fund');left=self.n.mine(1,self.treasury)[-1]
            self.net.same_tip([0,1],left)
            self.assertTrue(self.n.outpoint(c['fund']['tx_hash'])['in_chain'])
            self.prepare_spend(c)
            with self.assertRaises(ValueError):self.relay(c,'xds-claim',lambda:self.admission(c))
            right=self.net.nodes[2].mine(2,bytes.fromhex('97'*32))[-1]
            self.net.same_tip([2,3],right)
            self.assertFalse(self.net.nodes[2].outpoint(c['fund']['tx_hash'])['in_chain'])
        finally:self.net.reconnect()
        self.net.same_tip(expected=right)
        self.assertFalse(self.n.outpoint(c['fund']['tx_hash'])['in_chain'])
        self.journal.reconcile(c['id'],'xds-fund',c['fund']['tx_hash'],'unknown')
        self.assertFalse(self.journal.exposed(c['id']))
        self.relay(c,'xds-fund');self.mine(11)
        self.assertGreaterEqual(self.n.outpoint(c['fund']['tx_hash'])['confirmations'],11)
        # The claim prepared on the removed branch remains the same signed contract spend.
        self.relay(c,'xds-claim',lambda:self.admission(c));self.mine()
        self.assertTrue(self.n.outpoint(c['fund']['tx_hash'])['spent'])

    def test_08_live_claim_reorg_keeps_exposure_and_exact_settlement(self):
        c=self.fund();self.mine(10);self.prepare_spend(c)
        original=self.journal.intent(c['id'],'xds-claim')['payload']
        self.net.partition([[0,1],[2,3]])
        try:
            self.relay(c,'xds-claim',lambda:self.admission(c));left=self.n.mine(1,self.treasury)[-1]
            self.net.same_tip([0,1],left);self.assertTrue(self.n.outpoint(c['fund']['tx_hash'])['spent'])
            self.journal.reconcile(c['id'],'xds-claim',c['settlement']['tx_hash'],'confirmed')
            right=self.net.nodes[2].mine(2,bytes.fromhex('96'*32))[-1];self.net.same_tip([2,3],right)
            self.assertFalse(self.net.nodes[2].outpoint(c['fund']['tx_hash'])['spent'])
        finally:self.net.reconnect()
        self.net.same_tip(expected=right)
        self.assertFalse(self.n.outpoint(c['fund']['tx_hash'])['spent'])
        self.journal.reconcile(c['id'],'xds-claim',c['settlement']['tx_hash'],'unknown')
        self.assertTrue(self.journal.exposed(c['id']))
        self.relay(c,'xds-claim');self.mine()
        self.assertEqual(self.journal.intent(c['id'],'xds-claim')['payload'],original)
        for n in self.net.nodes:self.assertTrue(n.outpoint(c['fund']['tx_hash'])['spent'])

if __name__=='__main__':unittest.main(verbosity=2)
