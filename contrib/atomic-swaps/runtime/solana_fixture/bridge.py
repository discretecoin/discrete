"""Owned fixture RPC and provisioning, with an optional explicit stdio transport.

The transport command is trusted operator configuration and is never received
from an offer/mailbox. Keys stay in the private client directory; setup sends
only public owner addresses to the synthetic minter. No arbitrary Python imports.
"""
import base64
from decimal import Decimal
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

from solders.hash import Hash
from solders.instruction import AccountMeta as Meta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams, TransferParams, create_account, transfer
from solders.transaction import Transaction
from swap_runtime.common import canonical, hex_bytes, integer, strict_json
from swap_runtime.rpc import LocalRpc
from swap_runtime.solana import profile
from .support import (MAX_PACKET, private_directory, public_ready, read_json,
                      read_key, validate_manifest, write_json, write_keys)

ALLOWED = frozenset({'getGenesisHash', 'getAccountInfo', 'getMultipleAccounts', 'getLatestBlockhash',
    'getFeeForMessage', 'getBalance', 'getSlot', 'getSignatureStatuses', 'getTransaction',
    'sendTransaction', 'isBlockhashValid', 'getTokenAccountBalance', 'getMinimumBalanceForRentExemption'})
TOKEN = Pubkey.from_string(profile.TOKEN)


def reply_wire(value, depth=0):
    """Forward RPC JSON numbers exactly, including unused token UI decimals."""
    if depth > 32:
        raise ValueError('Fixture response nesting exceeds bound')
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError('Finite fixture RPC number required')
        return str(value).encode('ascii')
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError('String RPC object keys required')
        return b'{' + b','.join(canonical(key) + b':' + reply_wire(value[key], depth + 1) for key in sorted(value)) + b'}'
    if type(value) is list:
        return b'[' + b','.join(reply_wire(item, depth + 1) for item in value) + b']'
    return canonical(value)


def wait_for(check, timeout=150):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.5)
    raise TimeoutError('Synthetic fixture wait expired')


def finalized(rpc, txid):
    value = rpc('getSignatureStatuses', [[txid], {'searchTransactionHistory': True}])['value'][0]
    if value and value['confirmationStatus'] == 'finalized':
        if value['err'] is not None:
            raise ValueError('Synthetic setup transaction failed')
        return value
    return None


def setup(rpc, manifest, minter, owner, claimant, hashlock_hex, delay_slots):
    """Provision ordinary assets only. Owner engine owns escrow account creation."""
    lock = hex_bytes(hashlock_hex, 32, 'public hashlock')
    integer(delay_slots, 'synthetic delay', 200, 2500)
    owner, claimant = Pubkey.from_string(owner), Pubkey.from_string(claimant)
    if owner == claimant or not owner.is_on_curve() or not claimant.is_on_curve():
        raise ValueError('Independent ordinary owner addresses required')
    profile.verify_rpc(manifest, rpc)
    mint = Pubkey.from_string(manifest['profile']['mint'])
    source = Keypair()
    rent = rpc('getMinimumBalanceForRentExemption', [165])
    instructions = [create_account(CreateAccountParams(from_pubkey=minter.pubkey(), to_pubkey=source.pubkey(),
        lamports=rent, space=165, owner=TOKEN)),
        Instruction(TOKEN, b'\x12' + bytes(owner), [Meta(source.pubkey(), False, True), Meta(mint, False, False)]),
        Instruction(TOKEN, b'\x0e' + (10_000_000).to_bytes(8, 'little') + b'\x06',
            [Meta(mint, False, True), Meta(source.pubkey(), False, True), Meta(minter.pubkey(), True, False)]),
        transfer(TransferParams(from_pubkey=minter.pubkey(), to_pubkey=owner, lamports=1_000_000_000)),
        transfer(TransferParams(from_pubkey=minter.pubkey(), to_pubkey=claimant, lamports=1_000_000_000))]
    blockhash = Hash.from_string(rpc('getLatestBlockhash', [{'commitment': 'finalized'}])['value']['blockhash'])
    tx = Transaction([minter, source], Message(instructions, minter.pubkey()), blockhash)
    txid = str(tx.signatures[0])
    ack = rpc('sendTransaction', [base64.b64encode(bytes(tx)).decode(),
        {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0}])
    if ack != txid:
        raise ValueError('Synthetic setup RPC changed the signed identity')
    wait_for(lambda: finalized(rpc, txid))
    terms = dict(manifest=manifest, owner=str(owner), source=str(source.pubkey()),
        claim_owner=str(claimant), claim_payer=str(claimant), refund_owner=str(owner), refund_payer=str(owner),
        amount=1234567, hashlock=lock.hex(), deadline_slot=rpc('getSlot', [{'commitment': 'processed'}]) + delay_slots,
        min_context_slot=0, max_finality_lag_slots=128, min_funding_window_slots=140,
        max_funding_fee_lamports=25000, max_rent_lamports=20000000, owner_reserve_lamports=10000)
    return dict(terms=terms, setup_txid=txid,
        source_balance=int(rpc('getTokenAccountBalance', [str(source.pubkey()), {'commitment': 'finalized'}])['value']['amount']),
        owner_balance_lamports=rpc('getBalance', [str(owner), {'commitment': 'finalized'}])['value'],
        claim_balance_lamports=rpc('getBalance', [str(claimant), {'commitment': 'finalized'}])['value'])


class LocalBridge:
    def __init__(self, run):
        self.run = private_directory(run)
        config = read_json(self.run / 'local.json')
        if type(config) is not dict or set(config) != {'version', 'endpoint'} or config['version'] != 1:
            raise ValueError('Exact local fixture configuration required')
        self.transport = LocalRpc(config['endpoint'])
        self.ready = public_ready(read_json(self.run / 'ready.json'))
        self.manifest = self.ready['manifest']
        self.owner_key = read_key(self.run, 'owner')
        self.claim_key = read_key(self.run, 'claim')
        self.minter = read_key(self.run, 'minter')
        if len({str(x.pubkey()) for x in (self.owner_key, self.claim_key, self.minter)}) != 3:
            raise ValueError('Independent fixture keys required')
        profile.verify_rpc(self.manifest, self.rpc)

    def rpc(self, method, params):
        if method not in ALLOWED or type(params) is not list:
            raise ValueError('Fixture RPC method rejected')
        if method == 'sendTransaction' and self.transport('getGenesisHash', []) != self.manifest['profile']['genesis_hash']:
            raise ValueError('Fixture genesis changed before transmission')
        return self.transport(method, params)

    def setup(self, hashlock_hex, delay_slots):
        return self.setup_public(str(self.owner_key.pubkey()), str(self.claim_key.pubkey()), hashlock_hex, delay_slots)

    def setup_public(self, owner, claimant, hashlock_hex, delay_slots):
        return setup(self.rpc, self.manifest, self.minter, owner, claimant, hashlock_hex, delay_slots)

    def close(self):
        pass  # Connections are per request. Never stop somebody else's validator.


def command_argv(value):
    if (type(value) is not list or not 1 <= len(value) <= 64
            or any(type(x) is not str or not x or len(x) > 4096 or '\x00' in x or '\n' in x or '\r' in x for x in value)):
        raise ValueError('Explicit bounded transport argv required')
    return value


class StdioTransport:
    """Public framed transport; no shell, environment credentials or source import."""
    def __init__(self, command):
        command_argv(command)
        self.lock, self.responses = threading.Lock(), queue.Queue(maxsize=1)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, bufsize=0)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(MAX_PACKET + 1)
                if not line or len(line) > MAX_PACKET or not line.endswith(b'\n'):
                    self.responses.put(None)
                    return
                self.responses.put(strict_json(line, parse_float=Decimal))
        except Exception:
            self.responses.put(None)

    def request(self, body):
        with self.lock:
            wire = canonical(body) + b'\n'
            if len(wire) > 1024 * 1024:
                raise ValueError('Fixture request exceeds bound')
            try:
                self.process.stdin.write(wire)
                self.process.stdin.flush()
                result = self.responses.get(timeout=180 if body.get('action') == 'setup' else 45)
            except Exception:
                self.close()
                raise ValueError('Fixture transport failed') from None
            if type(result) is not dict or set(result) != {'result'}:
                raise ValueError('Fixture response rejected')
            return result['result']

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()


class RemoteBridge:
    def __init__(self, run):
        self.run = private_directory(run)
        config = read_json(self.run / 'client.json')
        if type(config) is not dict or set(config) != {'version', 'command', 'ready'} or config['version'] != 1:
            raise ValueError('Exact explicit client configuration required')
        self.ready = public_ready(config['ready'])
        self.manifest = self.ready['manifest']
        self.owner_key, self.claim_key = read_key(self.run, 'owner'), read_key(self.run, 'claim')
        if self.owner_key.pubkey() == self.claim_key.pubkey():
            raise ValueError('Independent fixture owner keys required')
        self.transport = StdioTransport(config['command'])
        try:
            if self.transport.request({'action': 'info'}) != self.ready:
                raise ValueError('Fixture run identity changed')
            profile.verify_rpc(self.manifest, self.rpc)
        except BaseException:
            self.close()
            raise

    def rpc(self, method, params):
        if method not in ALLOWED or type(params) is not list:
            raise ValueError('Fixture RPC method rejected')
        return self.transport.request(dict(action='rpc', method=method, params=params))

    def setup(self, hashlock_hex, delay_slots):
        return self.transport.request(dict(action='setup', owner=str(self.owner_key.pubkey()),
            claim_owner=str(self.claim_key.pubkey()), hashlock=hashlock_hex, delay_slots=delay_slots))

    def close(self):
        self.transport.close()


def init_client(run, command):
    command_argv(command)
    transport = StdioTransport(command)
    try:
        ready = public_ready(transport.request({'action': 'info'}))
    finally:
        transport.close()
    run = private_directory(run, create=True)
    write_keys(run, ('owner', 'claim'))
    write_json(run / 'client.json', dict(version=1, command=command, ready=ready))
    return ready


def create_bridge(run_dir=None):
    value = run_dir if run_dir is not None else os.environ.get('OWNER_SOLANA_RUN_DIR')
    if not value:
        raise ValueError('Explicit OWNER_SOLANA_RUN_DIR required')
    run = private_directory(value)
    if (run / 'client.json').exists() and (run / 'local.json').exists():
        raise ValueError('Ambiguous fixture transport configuration')
    return RemoteBridge(run) if (run / 'client.json').exists() else LocalBridge(run)


def serve(run, incoming, outgoing):
    local = LocalBridge(run)
    try:
        while True:
            line = incoming.readline(1024 * 1024 + 1)
            if not line:
                return
            try:
                if len(line) > 1024 * 1024 or not line.endswith(b'\n'):
                    raise ValueError('Bounded fixture frame required')
                request = strict_json(line)
                action = request.get('action')
                if action == 'info' and set(request) == {'action'}:
                    result = local.ready
                elif action == 'rpc' and set(request) == {'action', 'method', 'params'}:
                    result = local.rpc(request['method'], request['params'])
                elif action == 'setup' and set(request) == {'action', 'owner', 'claim_owner', 'hashlock', 'delay_slots'}:
                    result = local.setup_public(request['owner'], request['claim_owner'], request['hashlock'], request['delay_slots'])
                else:
                    raise ValueError('Fixture request rejected')
                wire = reply_wire({'result': result}) + b'\n'
                if len(wire) > MAX_PACKET:
                    raise ValueError('Fixture response exceeds bound')
            except Exception:
                wire = b'{"error":"fixture request failed"}\n'
            outgoing.write(wire)
            outgoing.flush()
            if len(line) > 1024 * 1024 or not line.endswith(b'\n'):
                return  # Do not reinterpret the tail of an oversized frame.
    finally:
        local.close()
