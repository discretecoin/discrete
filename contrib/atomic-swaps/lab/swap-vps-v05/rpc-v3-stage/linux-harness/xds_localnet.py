"""Owned loopback daemon/wallet processes and controllable TCP links; synthetic coins only."""
import base64,hashlib,json,pathlib,secrets,select,socket,socketserver,subprocess,threading,time,urllib.request,urllib.error
from runtime_paths import DAEMON,WALLET,CREATE_NO_WINDOW
ROOT=pathlib.Path(__file__).resolve().parent
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('local RPC redirect refused')
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def wait_for(probe,label,timeout=45):
    deadline=time.monotonic()+timeout;last=None
    while time.monotonic()<deadline:
        try:
            result=probe()
            if result:return result
        except (OSError,ValueError,RuntimeError) as e:last=e
        time.sleep(.15)
    raise TimeoutError(f'{label}: {last}')

def http(port_number,path,params,auth=None,timeout=60,headers=None):
    h={'Content-Type':'application/json'}
    if auth:h['Authorization']='Basic '+base64.b64encode(auth.encode()).decode()
    h.update(headers or {})
    req=urllib.request.Request(f'http://127.0.0.1:{port_number}{path}',data=json.dumps(params).encode(),headers=h)
    try:
        with OPENER.open(req,timeout=timeout) as r:raw=r.read()
    except urllib.error.HTTPError as e:raw=e.read();raise RuntimeError(f'HTTP {e.code}: {raw[:300]!r}') from e
    return json.loads(raw)

class Link:
    """A private TCP relay. Disabling it tears down established streams as well as new dials."""
    def __init__(self,target):
        self.target=target;self.enabled=True;self.lock=threading.Lock();self.streams=set();owner=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream=None
                try:
                    with owner.lock:
                        if not owner.enabled:return
                        upstream=socket.create_connection(('127.0.0.1',owner.target),timeout=1)
                        pair=(self.request,upstream);owner.streams.update(pair)
                    while True:
                        readable,_,_=select.select(pair,[],[],.2)
                        for incoming in readable:
                            data=incoming.recv(65536)
                            if not data:return
                            (upstream if incoming is self.request else self.request).sendall(data)
                except OSError:pass
                finally:
                    with owner.lock:
                        owner.streams.discard(self.request)
                        if upstream:owner.streams.discard(upstream)
                    if upstream:upstream.close()
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=False
            daemon_threads=True
        self.server=Server(('127.0.0.1',0),Handler);self.port=self.server.server_address[1]
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.1},daemon=True);self.thread.start()
    def set_enabled(self,enabled):
        with self.lock:
            self.enabled=enabled
            if not enabled:
                for s in tuple(self.streams):
                    try:s.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
    def close(self):
        self.set_enabled(False);self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)

class Node:
    def __init__(self,directory):
        self.directory=directory;directory.mkdir();self.p2p=port();self.rpc=port();self.process=None;self.peers=[];self.log=None
    def start(self,peers=None):
        if peers is not None:self.peers=peers
        if self.process and self.process.poll() is None:raise RuntimeError('node already running')
        args=[str(DAEMON),'--testnet','--swap-lab','--without-checkpoints','--no-console',
          '--data-dir',str(self.directory),'--p2p-bind-ip','127.0.0.1','--p2p-bind-port',str(self.p2p),
          '--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(self.rpc),'--allow-local-ip',
          '--log-file',str(self.directory/'daemon.log'),'--log-level','1']
        for peer in self.peers:args+=['--add-exclusive-node',f'127.0.0.1:{peer}']
        self.log=(self.directory/'process.log').open('ab')
        self.process=subprocess.Popen(args,cwd=self.directory,stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,
          creationflags=CREATE_NO_WINDOW)
    def ready(self):
        if self.process.poll() is not None:raise RuntimeError(f'node exited {self.directory}')
        return self.info()
    def call(self,path,params=None,**kwargs):return http(self.rpc,path,params or {},**kwargs)
    def info(self):return self.call('/getinfo')
    def mine(self,count,seed,expected_tip=None):
        results=[]
        while count:
            n=min(count,32);p={'blocks':n,'miner_seed':seed.hex(),'expected_tip':expected_tip or self.info()['top_block_hash']}
            r=self.call('/swap_lab_mine',p)
            if r.get('status')!='OK':raise RuntimeError(f'mine failed: {r}')
            if len(r['hashes'])!=n:raise RuntimeError('partial mine was not explicit')
            results+=r['hashes'];count-=n;expected_tip=r['top_hash']
        return results
    def outpoint(self,txid,index=0,spend_tag=''):
        return self.call('/swap_lab_outpoint',{'txid':txid,'index':index,'spend_tag':spend_tag})
    def submit(self,wire):return self.call('/sendrawtransaction',{'tx_as_hex':wire})
    def submit_exact(self,wire,txid):
        # A duplicate may return "Not relayed". Only exact local pool/chain readback
        # can turn that response (or a lost response) into a known accepted artifact.
        response=None;failure=None
        try:response=self.submit(wire)
        except (OSError,ValueError,RuntimeError) as e:failure=e
        state=self.outpoint(txid)
        if state['found'] and (state['in_pool'] or state['in_chain']) and state['tx_as_hex']==wire:
            return {'accepted_locally':True,'in_chain':state['in_chain'],'response':response}
        if failure:raise failure
        raise RuntimeError(f'exact submitted artifact not observed: {response}')
    def stop(self,kill=False):
        if not self.process:return
        if self.process.poll() is None:
            if kill:self.process.kill()
            else:
                try:self.call('/stop_daemon',timeout=5)
                except Exception:pass
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        if self.log:self.log.close();self.log=None

class Network:
    def __init__(self,count=4):
        self.directory=ROOT/'network-runs'/str(time.time_ns());self.directory.mkdir(parents=True)
        self.nodes=[Node(self.directory/f'node-{i}') for i in range(count)];self.links={};self.wallets=[]
        try:
            for i in range(count):
                for j in range(count):
                    if i!=j:self.links[i,j]=Link(self.nodes[j].p2p)
            for i,node in enumerate(self.nodes):node.start([self.links[i,j].port for j in range(count) if i!=j])
            for node in self.nodes:wait_for(node.ready,'node startup')
            self.same_tip()
        except BaseException:self.close();raise
    def partition(self,groups):
        group={n:k for k,g in enumerate(groups) for n in g}
        if set(group)!=set(range(len(self.nodes))):raise ValueError('partition must cover every node')
        for (i,j),link in self.links.items():link.set_enabled(group[i]==group[j])
    def reconnect(self):
        for link in self.links.values():link.set_enabled(True)
    def same_tip(self,indices=None,expected=None):
        nodes=self.nodes if indices is None else [self.nodes[i] for i in indices]
        def check():
            infos=[n.info() for n in nodes]
            if len({i['top_block_hash'] for i in infos})!=1:return False
            if expected is not None and infos[0]['top_block_hash']!=expected:return False
            return infos[0]
        return wait_for(check,'same chain tip',60)
    def wallet(self,name,seed,node=0,restore=False):
        w=Wallet(self.directory/name,self.nodes[node],seed,restore);self.wallets.append(w);return w
    def close(self):
        for w in self.wallets:w.stop()
        for n in self.nodes:n.stop()
        for link in self.links.values():link.close()

class Wallet:
    def __init__(self,directory,node,seed,restore=False):
        directory.mkdir();self.directory=directory;self.node=node;self.seed=seed
        self.path=directory/'account.wallet';self.rpc=port();self.password=secrets.token_hex(16)
        self.auth='lab:'+secrets.token_hex(24);self.process=None;self.log=None
        args=[str(WALLET),'--testnet','--swap-lab','--daemon-address',f'http://127.0.0.1:{node.rpc}',
          '--wallet-file',str(self.path),'--password',self.password,'--restore','--spend-key',seed.hex(),
          '--view-key',hashlib.sha3_256(seed).hexdigest(),'--log-file',str(directory/'create.log')]
        with (directory/'create-process.log').open('wb') as output:
            result=subprocess.run(args,cwd=directory,input=b'exit\n',stdout=output,stderr=output,
              timeout=60,creationflags=CREATE_NO_WINDOW)
        if result.returncode!=0 or not self.path.exists():raise RuntimeError(f'wallet creation failed: {directory}')
        try:self.start()
        except BaseException:self.stop(kill=True);raise
    def start(self):
        if self.process and self.process.poll() is None:raise RuntimeError('wallet already running')
        user,password=self.auth.split(':',1)
        args=[str(WALLET),'--testnet','--swap-lab','--daemon-address',f'http://127.0.0.1:{self.node.rpc}',
          '--wallet-file',str(self.path),'--password',self.password,'--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(self.rpc),
          '--rpc-user',user,'--rpc-password',password,'--log-file',str(self.directory/'wallet.log')]
        self.log=(self.directory/'rpc-process.log').open('ab')
        self.process=subprocess.Popen(args,cwd=self.directory,stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,
          creationflags=CREATE_NO_WINDOW)
        wait_for(lambda:self.call('get_height'),'wallet RPC startup')
    def call(self,method,params=None,**kwargs):
        r=http(self.rpc,'/json_rpc',{'jsonrpc':'2.0','id':1,'method':method,'params':params or {}},auth=self.auth,**kwargs)
        if 'error' in r:raise RuntimeError(str(r['error']))
        return r['result']
    def node_height_seen(self):
        target=self.node.info()['height']
        return wait_for(lambda:self.call('get_height').get('height',0)>=target-1,'wallet observed daemon height',60)
    def balance(self):return self.call('get_balance')['available_balance']
    def synced(self):
        target=self.node.info()['height']-1
        return wait_for(lambda:self.call('swap_scan_height')['height']>=target,'actual wallet scan cursor',90)
    def role(self,rho):return self.call('swap_role',{'rho':rho.hex()})
    def stop(self,kill=False):
        if not self.process:return
        if self.process.poll() is None:
            if kill:self.process.kill()
            else:
                try:self.call('stop_wallet',timeout=5)
                except Exception:pass
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        if self.log:self.log.close();self.log=None
