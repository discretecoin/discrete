"""Owned startup/access/lifecycle checks; run only after the owner's final-build signal.

All client sockets target literal loopback. Documentation-only peer/seed strings are
negative startup inputs, never client dial targets. Source preflight below verifies the
reviewed rejection order before any binary is started; build identity is recorded.
Fresh process directories/logs are retained. Cleanup uses only owned Popen handles.
"""
import hashlib,http.server,json,os,pathlib,subprocess,threading,time,unittest
from unittest.mock import patch
import xds_localnet as lab
from runtime_paths import CORE,CREATE_NO_WINDOW

ROOT=pathlib.Path(__file__).resolve().parent

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def require_reviewed_guard_order():
    """Safety preflight, not evidence that source text alone proves binary behavior."""
    daemon=(CORE/'src/Daemon/Daemon.cpp').read_text(encoding='utf-8')
    peers=(CORE/'src/P2p/NetNode.cpp').read_text(encoding='utf-8')
    wallet=(CORE/'src/Wallet/WalletRpcServer.cpp').read_text(encoding='utf-8')
    simple=(CORE/'src/SimpleWallet/SimpleWallet.cpp').read_text(encoding='utf-8')
    if daemon.index('if (swap_lab && !testnet_mode)')>=daemon.index('p2psrv.init(netNodeConfig)'):
        raise RuntimeError('daemon testnet guard order requires source re-review')
    if daemon.index('netNodeConfig.getBindIp() != "127.0.0.1"')>=daemon.index('p2psrv.init(netNodeConfig)'):
        raise RuntimeError('daemon bind guard order requires source re-review')
    section=peers[peers.index('bool NodeServer::init(const NetNodeConfig& config)'):]
    peer_checks=('config.getPeers()', 'config.getExclusiveNodes()', 'config.getPriorityNodes()',
      'config.getSeedNodes()', 'config.getSeedNodeStrings()')
    if any(section.index(text)>=section.index('handleConfig(config)') for text in peer_checks):
        raise RuntimeError('peer/seed rejection must precede configuration, resolver and listener')
    if section.index('handleConfig(config)')>=section.index('m_listener = System::TcpListener'):
        raise RuntimeError('P2P initialization order requires source re-review')
    if 'if (!m_swapLab && !append_net_address(m_seed_nodes, seed))' not in peers or \
       'if (m_swapLab && Common::ipAddressToString(na.ip) != "127.0.0.1") return false;' not in peers:
        raise RuntimeError('independent lab DNS/outbound guards are absent; do not run negative peer inputs')
    section=wallet[wallet.index('bool wallet_rpc_server::init('):wallet.index('void wallet_rpc_server::getServerConf')]
    if section.index('m_currency.swapLab()')>=section.index('m_httpServer =') or \
       'm_rpcUser.empty() || m_rpcPassword.empty() || m_enable_ssl' not in section:
        raise RuntimeError('wallet lab startup guard requires source re-review')
    if simple.index('if (swapLab && !command_line::get_arg(vm, arg_testnet))')>=simple.index('if (command_line::has_arg(vm, Tools::wallet_rpc_server::arg_rpc_bind_port))'):
        raise RuntimeError('SimpleWallet testnet guard order requires source re-review')

class LocalHttp:
    """Short-lived loopback-only probe server for opener policy; never redirects externally."""
    def __init__(self,redirect=None):
        self.hits=[];owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length','0')))
                owner.hits.append(self.path)
                if redirect is not None:
                    self.send_response(302);self.send_header('Location',redirect);self.end_headers()
                else:
                    body=b'{"status":"OK"}';self.send_response(200)
                    self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
                    self.end_headers();self.wfile.write(body)
            def log_message(self,*_):pass
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.port=self.server.server_port
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.05},daemon=True)
    def __enter__(self):self.thread.start();return self
    def __exit__(self,*_):self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)

class LocalnetBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_reviewed_guard_order()
        if not lab.DAEMON.is_file() or not lab.WALLET.is_file():raise RuntimeError('owner-qualified final binaries are required')
        cls.directory=ROOT/'boundary-runs'/str(time.time_ns());cls.directory.mkdir(parents=True)
        paths=['core/src/Daemon/Daemon.cpp','core/src/P2p/NetNode.cpp',
          'core/src/Wallet/WalletRpcServer.cpp','core/src/SimpleWallet/SimpleWallet.cpp',
          'xds_localnet.py','test_localnet_boundaries.py']
        evidence={'source_guard_review':'startup rejection before resolver/listener; binaries tested below',
          'files':{p:sha(CORE/p[5:] if p.startswith('core/') else ROOT/p) for p in paths},'binaries':{str(p):sha(p) for p in (lab.DAEMON,lab.WALLET)}}
        (cls.directory/'source-and-binary-identities.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
        cls.network=None
        try:
            cls.network=lab.Network(1)
            cls.wallet=cls.network.wallet('boundary-wallet',hashlib.sha256(b'v04-boundary-synthetic-wallet').digest())
            (cls.directory/'owned-network.json').write_text(json.dumps({'directory':str(cls.network.directory),
              'node_pid':cls.network.nodes[0].process.pid,'wallet_pid':cls.wallet.process.pid},indent=2)+'\n',encoding='utf-8')
        except BaseException:
            if cls.network is not None:cls.network.close()
            raise
    @classmethod
    def tearDownClass(cls):
        if cls.network is not None:cls.network.close()
    def fresh(self,label):
        directory=self.directory/label;directory.mkdir();return directory
    def rejected(self,binary,args,directory,message,timeout=20):
        log=directory/'process.log'
        with log.open('wb') as output:
            process=subprocess.Popen([str(binary),*args],cwd=directory,stdin=subprocess.DEVNULL,
              stdout=output,stderr=output,creationflags=CREATE_NO_WINDOW)
            try:
                try:code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:self.fail(f'unsafe startup did not reject within {timeout}s: {directory}')
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)
        text=log.read_text(errors='replace')
        self.assertNotEqual(code,0,text[-3000:]);self.assertIn(message,text)
        self.assertNotIn('Net service bound on',text)
        self.assertNotIn('Starting wallet RPC server on',text)
        (directory/'result.json').write_text(json.dumps({'exit_code':code,'rejection':message,'pid':process.pid})+'\n',encoding='utf-8')
    def daemon_rejection(self,label,options=None,testnet=True,message='--swap-lab requires RPC/P2P binds'):
        directory=self.fresh(label);data=directory/'data';data.mkdir()
        values={'--data-dir':str(data),'--p2p-bind-ip':'127.0.0.1','--p2p-bind-port':str(lab.port()),
          '--rpc-bind-ip':'127.0.0.1','--rpc-bind-port':str(lab.port()),'--log-file':str(directory/'daemon.log')}
        values.update(options or {})
        args=['--swap-lab','--without-checkpoints','--no-console']+(['--testnet'] if testnet else [])
        for key,value in values.items():
            if value is not None:args.extend([key,str(value)])
        self.rejected(lab.DAEMON,args,directory,message)
    def wallet_rejection(self,label,options=None,testnet=True,message='Swap lab wallet RPC requires literal loopback'):
        directory=self.fresh(label);w=self.wallet;user,password=w.auth.split(':',1)
        values={'--daemon-address':f'http://127.0.0.1:{w.node.rpc}','--wallet-file':str(w.path),
          '--password':w.password,'--rpc-bind-ip':'127.0.0.1','--rpc-bind-port':str(lab.port()),
          '--rpc-user':user,'--rpc-password':password,'--log-file':str(directory/'wallet.log')}
        values.update(options or {})
        args=['--swap-lab']+(['--testnet'] if testnet else [])
        for key,value in values.items():
            if value is True:args.append(key)
            elif value is not None:args.extend([key,str(value)])
        w.stop()
        try:self.rejected(lab.WALLET,args,directory,message,timeout=30)
        finally:w.start()
    def test_daemon_swap_lab_requires_testnet(self):
        self.daemon_rejection('daemon-without-testnet',testnet=False,message='--swap-lab requires --testnet')
    def test_daemon_rejects_nonloopback_rpc_and_p2p_binds(self):
        for key in ('--rpc-bind-ip','--p2p-bind-ip'):
            with self.subTest(option=key):self.daemon_rejection('daemon-'+key[2:],{key:'0.0.0.0'})
    def test_daemon_rejects_nonlocal_configured_peer_before_listener(self):
        # RFC 5737 documentation address: validation input only. The independent outbound
        # guard checked in preflight also refuses it; no test client attempts a dial.
        self.daemon_rejection('daemon-nonlocal-peer',{'--add-exclusive-node':'198.51.100.17:18777'},
          message='Failed to initialize p2p server.')
    def test_daemon_rejects_hostname_seed_before_resolver(self):
        self.daemon_rejection('daemon-hostname-seed',{'--seed-node':'must-not-resolve.invalid:18777'},
          message='Failed to initialize p2p server.')
        text=(self.directory/'daemon-hostname-seed/process.log').read_text(errors='replace')
        self.assertNotIn('Failed to resolve host name',text)
    def test_wallet_swap_lab_requires_testnet(self):
        self.wallet_rejection('wallet-without-testnet',testnet=False,message='--swap-lab requires --testnet')
    def test_wallet_rejects_missing_either_or_both_credentials(self):
        cases={'none':{'--rpc-user':None,'--rpc-password':None},
          'no-user':{'--rpc-user':None},'no-password':{'--rpc-password':None}}
        for label,options in cases.items():
            with self.subTest(credentials=label):self.wallet_rejection('wallet-auth-'+label,options)
    def test_wallet_rejects_nonloopback_listener_and_ssl(self):
        self.wallet_rejection('wallet-external-bind',{'--rpc-bind-ip':'0.0.0.0'})
        self.wallet_rejection('wallet-ssl',{'--rpc-bind-ssl-enable':True})
    def test_wallet_auth_origin_and_content_type_gate(self):
        w=self.wallet;params={'rho':'11'*32}
        self.assertEqual(len(w.call('swap_role',params)['commitment']),64)
        with self.assertRaisesRegex(RuntimeError,'HTTP 401'):
            lab.http(w.rpc,'/json_rpc',{'jsonrpc':'2.0','id':1,'method':'swap_role','params':params})
        for headers in ({'Origin':'https://browser.invalid'},{'Content-Type':'text/plain'}):
            with self.subTest(headers=list(headers)):
                with self.assertRaisesRegex(RuntimeError,'Swap RPC requires a direct JSON POST'):
                    w.call('swap_role',params,headers=headers)
        self.assertEqual(len(w.call('swap_role',params)['commitment']),64)
    def test_daemon_origin_and_content_type_gate(self):
        n=self.network.nodes[0];params={'txid':'00'*32,'index':0,'spend_tag':''}
        before=n.info()['top_block_hash'];normal=n.call('/swap_lab_outpoint',params)
        self.assertEqual(normal['status'],'OK');self.assertFalse(normal['found'])
        for headers in ({'Origin':'https://browser.invalid'},{'Content-Type':'text/plain'}):
            with self.subTest(headers=list(headers)):
                with self.assertRaisesRegex(RuntimeError,'HTTP 404'):n.call('/swap_lab_outpoint',params,headers=headers)
        self.assertEqual(n.info()['top_block_hash'],before)
    def test_duplicate_start_preserves_owned_process_handles(self):
        for owner in (self.network.nodes[0],self.wallet):
            original=owner.process
            try:
                with self.assertRaisesRegex(RuntimeError,'already running'):owner.start()
                self.assertIs(owner.process,original);self.assertIsNone(original.poll())
            finally:
                # If the guard regresses, do not leak the original owned process.
                if owner.process is not original and original.poll() is None:original.kill();original.wait(timeout=5)
    def test_wallet_constructor_failure_cleans_its_unregistered_process(self):
        real_popen=subprocess.Popen;real_wait=lab.wait_for;created=[]
        def tracked_popen(*args,**kwargs):
            process=real_popen(*args,**kwargs)
            command=args[0] if args else kwargs.get('args',[])
            if '--rpc-bind-port' in command and str(lab.WALLET)==str(command[0]):created.append(process)
            return process
        def forced_wait(probe,label,*args,**kwargs):
            if label=='wallet RPC startup':raise TimeoutError('forced owned-wallet startup failure')
            return real_wait(probe,label,*args,**kwargs)
        count=len(self.network.wallets)
        try:
            with patch.object(lab.subprocess,'Popen',tracked_popen),patch.object(lab,'wait_for',forced_wait):
                with self.assertRaisesRegex(TimeoutError,'forced owned-wallet'):
                    self.network.wallet('forced-start-failure',hashlib.sha256(b'v04-boundary-failed-wallet').digest())
            self.assertEqual(len(created),1);self.assertIsNotNone(created[0].poll())
            self.assertEqual(len(self.network.wallets),count)
            (self.directory/'failed-wallet-cleanup.json').write_text(json.dumps({'pid':created[0].pid,
              'exit_code':created[0].returncode,'registered_wallet_count':count})+'\n',encoding='utf-8')
        finally:
            for process in created:
                if process.poll() is None:process.kill();process.wait(timeout=5)
    def test_http_opener_ignores_proxy_and_refuses_loopback_redirect(self):
        with LocalHttp() as trap,LocalHttp() as target:
            with patch.dict(os.environ,{'http_proxy':f'http://127.0.0.1:{trap.port}',
              'HTTP_PROXY':f'http://127.0.0.1:{trap.port}','no_proxy':'','NO_PROXY':''}):
                self.assertEqual(lab.http(target.port,'/direct',{})['status'],'OK')
            self.assertEqual(target.hits,['/direct']);self.assertEqual(trap.hits,[])
            with LocalHttp(redirect=f'http://127.0.0.1:{trap.port}/redirected') as source:
                with self.assertRaisesRegex(RuntimeError,'local RPC redirect refused'):lab.http(source.port,'/redirect',{})
            self.assertEqual(trap.hits,[])

if __name__=='__main__':unittest.main(verbosity=2)
