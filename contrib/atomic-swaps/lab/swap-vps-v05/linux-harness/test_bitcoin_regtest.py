"""Real Bitcoin Core 31.1 script/mempool/chain tests; exclusively isolated regtest."""
import base64, json, os, pathlib, socket, subprocess, time, unittest, urllib.request
from unittest.mock import patch
from decimal import Decimal
from cryptography.hazmat.primitives.asymmetric import ec
from bitcoin_adapter import Contract, spend, pubkey, sha
from xds_localnet import OPENER
from runtime_paths import BITCOIND,CREATE_NO_WINDOW

ROOT=pathlib.Path(__file__).resolve().parent

class Node:
    def __init__(self):
        self.dir=ROOT/'bitcoin-runs'/str(time.time_ns());self.dir.mkdir(parents=True)
        with socket.socket() as s: s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
        self.start()
    def start(self):
        self.log=(self.dir/'process.log').open('ab')
        self.p=subprocess.Popen([str(BITCOIND),'-regtest',
          '-datadir='+str(self.dir),'-server=1','-listen=0','-dnsseed=0','-discover=0','-connect=0',
          '-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1','-rpcport='+str(self.port),'-fallbackfee=0.0002'],
          stdout=self.log,stderr=self.log,creationflags=CREATE_NO_WINDOW)
        for _ in range(200):
            try:
                self.auth=(self.dir/'regtest/.cookie').read_text().strip();self.rpc('getblockchaininfo');return
            except Exception:
                if self.p.poll() is not None: raise RuntimeError('regtest exited; inspect process.log')
                time.sleep(.05)
        self.stop();raise RuntimeError('regtest startup timeout')
    def rpc(self,method,*params,wallet=False):
        wallet_name=wallet if isinstance(wallet,str) else 'swaptest'
        if wallet and wallet_name not in ('swaptest','claimant'):raise ValueError('owned fixture wallet only')
        request=urllib.request.Request(f'http://127.0.0.1:{self.port}/'+('wallet/'+wallet_name if wallet else ''),
          data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),
          headers={'Authorization':'Basic '+base64.b64encode(self.auth.encode()).decode(),'Content-Type':'application/json'})
        try: raw=OPENER.open(request,timeout=15).read()
        except urllib.error.HTTPError as e: raw=e.read()
        result=json.loads(raw,parse_float=Decimal)
        if result.get('error'): raise RuntimeError(str(result['error']))
        return result['result']
    def stop(self):
        if self.p.poll() is None:
            try:self.rpc('stop')
            except Exception:pass
            try:self.p.wait(timeout=15)
            except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
        self.log.close()
    def mine(self,n=1):return self.rpc('generatetoaddress',n,self.address)
    def height(self):return self.rpc('getblockcount')

class BitcoinRegtest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n=Node();cls.n.rpc('createwallet','swaptest');cls.n.address=cls.n.rpc('getnewaddress',wallet=True)
        cls.n.mine(110);cls.a=ec.derive_private_key(12345,ec.SECP256K1());cls.b=ec.derive_private_key(67890,ec.SECP256K1())
        cls.dest=bytes.fromhex(cls.n.rpc('getaddressinfo',cls.n.address,wallet=True)['scriptPubKey'])
    @classmethod
    def tearDownClass(cls):cls.n.stop()
    def fund(self,refund_delay=5):
        secret=os.urandom(32);c=Contract(sha(secret),pubkey(self.a),pubkey(self.b),self.n.height()+refund_delay)
        return self.fund_contract(c,secret)
    def fund_contract(self,c,secret):
        script=c.script();decoded=self.n.rpc('decodescript',script.hex());address=decoded['segwit']['address']
        txid=self.n.rpc('sendtoaddress',address,0.001,wallet=True);self.n.mine()
        tx=self.n.rpc('gettransaction',txid,wallet=True);v=self.n.rpc('decoderawtransaction',tx['hex'])
        target=next(x for x in v['vout'] if x['scriptPubKey']['hex']==('0020'+sha(script).hex()))
        return c,secret,txid,target['n'],100_000
    def build(self,f,claim=True,**kw):
        c,s,txid,vout,amt=f
        return spend(c,txid,vout,amt,self.dest,self.a if claim else self.b,s if claim else None,**kw)
    def accepted(self,raw):return self.n.rpc('testmempoolaccept',[raw])[0]
    def test_claim_exact_amount_and_ordinary_next_wallet_spend(self):
        f=self.fund();raw,expected=self.build(f);self.assertTrue(self.accepted(raw)['allowed'])
        self.assertEqual(self.n.rpc('sendrawtransaction',raw),expected);self.n.mine()
        output=self.n.rpc('gettxout',expected,0);self.assertEqual(output['value'],Decimal('0.00099000'))
        self.assertIsNone(self.n.rpc('gettxout',f[2],f[3]))
        # Wallet owns the actual destination and recognizes confirmed received value.
        self.assertGreaterEqual(self.n.rpc('gettransaction',expected,wallet=True)['confirmations'],1)
        next_raw=self.n.rpc('createrawtransaction',[{'txid':expected,'vout':0}],{self.n.address:0.00098})
        signed=self.n.rpc('signrawtransactionwithwallet',next_raw,wallet=True)
        self.assertTrue(signed['complete']);next_id=self.n.rpc('sendrawtransaction',signed['hex']);self.n.mine()
        self.assertIsNotNone(self.n.rpc('gettxout',next_id,0));self.assertIsNone(self.n.rpc('gettxout',expected,0))
    def test_refund_candidate_height_boundary(self):
        f=self.fund();raw,_=self.build(f,False);self.assertFalse(self.accepted(raw)['allowed'])
        self.n.mine(f[0].refund_height-1-self.n.height());self.assertEqual(self.n.height(),f[0].refund_height-1)
        self.assertFalse(self.accepted(raw)['allowed']) # candidate H cannot include nLockTime H
        self.n.mine();self.assertTrue(self.accepted(raw)['allowed']) # candidate H+1
        self.n.rpc('sendrawtransaction',raw);self.n.mine()
    def test_secret_length_hash_and_destination_tamper(self):
        f=self.fund();raw,_=self.build(f);b=bytes.fromhex(raw)
        self.assertIn(f[1],b)
        wrong=b.replace(f[1],b'\x42'*32);self.assertFalse(self.accepted(wrong.hex())['allowed'])
        # Mutate a signed output amount, preserving parseability.
        wrong=bytearray(b);wrong[49]^=1;self.assertFalse(self.accepted(wrong.hex())['allowed'])
        c,s,t,v,a=f
        with self.assertRaises(ValueError):spend(c,t,v,a,self.dest,self.a,s[:-1])
        with self.assertRaises(ValueError):spend(c,t,v,a,self.dest,self.b,s)
        # Deliberately simulate a signer declaring A's public key but signing with B.
        # This fault exists only in the test; Core must reject the actual wrong-key signature/witness.
        class WrongSigner:
            def public_key(inner):return self.a.public_key()
            def sign(inner,digest,algorithm):return self.b.sign(digest,algorithm)
        wrong_key,_=spend(c,t,v,a,self.dest,WrongSigner(),s)
        rejected=self.accepted(wrong_key)
        self.assertFalse(rejected['allowed']);self.assertIn('script',rejected.get('reject-reason','').lower())
        self.assertTrue(self.accepted(raw)['allowed'])
    def test_refund_requires_locktime_and_nonfinal_sequence(self):
        f=self.fund();self.n.mine(f[0].refund_height-self.n.height())
        for kw in ({'sequence':0xffffffff},{'locktime':0}):
            raw,_=self.build(f,False,**kw);self.assertFalse(self.accepted(raw)['allowed'])
        self.assertTrue(self.accepted(self.build(f,False)[0])['allowed'])
    def test_interpreter_size_guard_rejects_matching_31_byte_preimage(self):
        secret=os.urandom(31);padded=secret+b'\0';expected=sha(secret)
        def short_spend(contract):
            f=self.fund_contract(contract,secret)
            # Bypass only the builder's secret-hash preflight; retain its actual script and BIP143 signature.
            # Witness length then changes independently; BIP143 does not sign witness stack items.
            with patch('bitcoin_adapter.sha',side_effect=lambda b:expected if b==padded else sha(b)):
                raw,_=spend(contract,f[2],f[3],f[4],self.dest,self.a,padded)
            blob=bytes.fromhex(raw);old=b'\x20'+padded;self.assertEqual(blob.count(old),1)
            return blob.replace(old,b'\x1f'+secret).hex()
        contract=Contract(expected,pubkey(self.a),pubkey(self.b),self.n.height()+20)
        rejected=self.accepted(short_spend(contract));self.assertFalse(rejected['allowed'])
        self.assertIn('script',rejected.get('reject-reason','').lower())
        class WithoutSizeCheck(Contract):
            def script(inner):return b'\x63'+super().script()[5:]
        control=WithoutSizeCheck(expected,pubkey(self.a),pubkey(self.b),self.n.height()+20)
        self.assertTrue(self.accepted(short_spend(control))['allowed'])
    def test_claim_remains_valid_after_refund_deadline(self):
        f=self.fund();self.n.mine(f[0].refund_height+1-self.n.height());raw,_=self.build(f)
        self.assertTrue(self.accepted(raw)['allowed']);self.n.rpc('sendrawtransaction',raw);self.n.mine()
        self.assertFalse(self.accepted(self.build(f,False)[0])['allowed'])
    def test_refund_wins_conflict_and_restart(self):
        f=self.fund();self.n.mine(f[0].refund_height-self.n.height());refund,txid=self.build(f,False)
        self.n.rpc('sendrawtransaction',refund);self.n.mine();self.assertFalse(self.accepted(self.build(f)[0])['allowed'])
        self.n.stop();self.n.start();self.n.rpc('loadwallet','swaptest')
        self.assertIsNotNone(self.n.rpc('gettxout',txid,0));self.assertIsNone(self.n.rpc('gettxout',f[2],f[3]))
    def test_reorg_reaccepts_claim_and_duplicate_broadcast(self):
        f=self.fund();raw,txid=self.build(f);self.assertEqual(self.n.rpc('sendrawtransaction',raw),txid)
        self.assertEqual(self.n.rpc('sendrawtransaction',raw),txid)
        block=self.n.mine()[0];self.n.rpc('invalidateblock',block)
        self.assertIn(txid,self.n.rpc('getrawmempool'))
        # A fresh coinbase destination guarantees a distinct replacement block even within the same second.
        self.n.rpc('generatetoaddress',1,self.n.rpc('getnewaddress',wallet=True))
        self.assertIsNotNone(self.n.rpc('gettxout',txid,0))

if __name__=='__main__':unittest.main(verbosity=2)
