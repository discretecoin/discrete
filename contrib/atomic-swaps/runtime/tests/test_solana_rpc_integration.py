"""Opt-in private-validator qualification; never imported as a test-network action.

Run only inside a fresh private network namespace with an explicit empty run
directory. Generates synthetic keys, starts a loopback validator, and writes a
public build request. An operator supplies a matching reviewed build/package in
run/input. It then performs normal initial program deployment, authority removal,
and exact runtime-adapter claim/refund checks. No preloaded program or real USDC.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from solders.instruction import AccountMeta as Meta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams, create_account
from solders.sysvar import CLOCK
from solders.transaction import Transaction
from solders.hash import Hash

TOKEN = Pubkey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
ENDPOINT = 'http://127.0.0.1:18899'


def write_json(path, value):
    with path.open('xb') as stream:
        stream.write((json.dumps(value, indent=2) + '\n').encode())


def rpc(method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(ENDPOINT, body, {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if result.get('error') or 'result' not in result:
        raise RuntimeError('Private RPC rejected ' + method)
    return result['result']


def wait_for(check, timeout=150):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(1)
    raise TimeoutError('Bounded private qualification wait expired')


def confirmed(txid):
    result = rpc('getSignatureStatuses', [[txid], {'searchTransactionHistory': True}])['value'][0]
    if result and result['confirmationStatus'] == 'finalized':
        if result['err'] is not None:
            raise RuntimeError('Synthetic transaction finalized with an error')
        return result
    return None


def send(ixs, payer, signers=()):
    blockhash = Hash.from_string(rpc('getLatestBlockhash', [{'commitment': 'finalized'}])['value']['blockhash'])
    tx = Transaction([payer, *signers], Message(ixs, payer.pubkey()), blockhash)
    txid = str(tx.signatures[0])
    ack = rpc('sendTransaction', [base64.b64encode(bytes(tx)).decode(),
                                 {'encoding': 'base64', 'skipPreflight': True, 'maxRetries': 0}])
    if ack != txid:
        raise RuntimeError('Private RPC returned a different signed identity')
    wait_for(lambda: confirmed(txid))
    return txid


def create(key, size, owner, payer):
    rent = rpc('getMinimumBalanceForRentExemption', [size])
    return create_account(CreateAccountParams(from_pubkey=payer.pubkey(), to_pubkey=key.pubkey(),
                                             lamports=rent, space=size, owner=owner))


def token_balance(key):
    return int(rpc('getTokenAccountBalance', [str(key), {'commitment': 'finalized'}])['value']['amount'])


def settlement_case(adapter_type, manifest, mint, payer, refund=False):
    program = Pubkey.from_string(manifest['profile']['program_id'])
    state, vault, source, claim, owner_refund = [Keypair() for _ in range(5)]
    authority, _ = Pubkey.find_program_address([b'xds-swap-v1', bytes(state.pubkey())], program)
    amount = 1_234_567
    for token, owner in ((source, payer.pubkey()), (vault, authority), (claim, payer.pubkey()), (owner_refund, payer.pubkey())):
        send([create(token, 165, TOKEN, payer), Instruction(TOKEN, b'\x12' + bytes(owner),
              [Meta(token.pubkey(), False, True), Meta(mint.pubkey(), False, False)])], payer, [token])
    send([Instruction(TOKEN, b'\x0e' + (10_000_000).to_bytes(8, 'little') + b'\x06',
          [Meta(mint.pubkey(), False, True), Meta(source.pubkey(), False, True), Meta(payer.pubkey(), True, False)])], payer)
    send([create(state, 192, program, payer)], payer, [state])
    keys = [state.pubkey(), vault.pubkey(), mint.pubkey(), claim.pubkey(), owner_refund.pubkey(),
            source.pubkey(), payer.pubkey(), authority, TOKEN, CLOCK]
    secret = os.urandom(32)
    deadline = rpc('getSlot', [{'commitment': 'processed'}]) + 150
    fund_data = b'\0' + amount.to_bytes(8, 'little') + deadline.to_bytes(8, 'little') + hashlib.sha256(secret).digest()
    funding_txid = send([Instruction(program, fund_data, [Meta(k, i in (0, 6), i in (0, 1, 3, 4, 5)) for i, k in enumerate(keys)])], payer, [state])
    terms = {name: str(keys[i]) for i, name in enumerate(('state', 'vault', 'mint', 'claim', 'refund', 'source', 'depositor', 'authority'))}
    terms.update(manifest=manifest, payer=str(payer.pubkey()), amount=amount, hashlock=hashlib.sha256(secret).hexdigest(),
                 deadline_slot=deadline, min_context_slot=0, max_finality_lag_slots=128)
    adapter = adapter_type(rpc, terms)
    observation = adapter.observe()
    if observation['status'] != 'unspent' or not observation['fees_ready']:
        raise RuntimeError('Actual RPC did not establish funded escrow and fee readiness')
    kind = 'foreign-refund' if refund else 'foreign-claim'
    if refund:
        try:
            adapter.prepare(kind, payer)
        except ValueError:
            pass
        else:
            raise AssertionError('Early refund preparation unexpectedly accepted')
        wait_for(lambda: adapter.observe()['refund_eligible'], timeout=240)
    raw, txid = adapter.prepare(kind, payer, None if refund else secret)
    adapter.send(kind, raw, txid)
    receipt = wait_for(lambda: (result if (result := adapter.receipt(kind, raw, txid))['status'] == 'confirmed' else None))
    destination = owner_refund if refund else claim
    if token_balance(destination.pubkey()) != amount or token_balance(vault.pubkey()) != 0:
        raise AssertionError('Principal conservation differs from exact settlement')
    try:
        adapter.send(kind, raw, txid)
    except ValueError:
        pass
    else:
        raise AssertionError('Consumed escrow was sent a second time')
    return {'kind': kind, 'funding_txid': funding_txid, 'settlement_txid': txid, 'receipt': receipt,
            'state': str(state.pubkey()), 'amount': amount, 'destination_balance': amount, 'vault_balance': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--solana-bin', type=Path, required=True)
    args = parser.parse_args()
    run = args.run_dir.resolve()
    if not run.is_dir() or (run / 'private').exists() or (run / 'ledger').exists():
        parser.error('Use an existing fresh run directory without keys or ledger')
    private = run / 'private'; private.mkdir(mode=0o700)
    evidence = run / 'evidence'; evidence.mkdir()
    (run / 'input').mkdir()
    keys = {}
    for name in ('program', 'mint', 'payer', 'authority'):
        key = Keypair(); keys[name] = key
        path = private / (name + '-keypair.json')
        write_json(path, list(bytes(key))); path.chmod(0o600)
    command = [str(args.solana_bin / 'solana-test-validator'), '--ledger', str(run / 'ledger'),
               '--bind-address', '127.0.0.1', '--rpc-port', '18899', '--faucet-port', '19900',
               '--gossip-port', '18001', '--dynamic-port-range', '18002-18100', '--limit-ledger-size', '50000',
               '--rpc-pubsub-queue-capacity-items', '1000', '--rpc-pubsub-queue-capacity-bytes', '16777216',
               '--rpc-pubsub-worker-threads', '1', '--rpc-pubsub-notification-threads', '1', '--log']
    log = (evidence / 'validator.log').open('xb')
    validator = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    try:
        def ready():
            if validator.poll() is not None:
                raise RuntimeError('Private validator exited before readiness')
            try:
                return rpc('getGenesisHash', [])
            except (OSError, RuntimeError):
                return None
        genesis = wait_for(ready, timeout=120)
        request = {'network': 'local-synthetic', 'genesis_hash': genesis,
                   'program_id': str(keys['program'].pubkey()), 'mint': str(keys['mint'].pubkey())}
        write_json(evidence / 'build-request.json', request)
        print(json.dumps({'phase': 'awaiting-profile-build', **request}), flush=True)
        wait_for(lambda: (run / 'input/READY').is_file(), timeout=600)
        package = run / 'input/package/contrib/atomic-swaps'
        sys.path.insert(0, str(package / 'runtime'))
        from swap_runtime.solana import SolanaAdapter, profile
        manifest = json.loads((run / 'input/build-manifest.json').read_text())
        elf = run / 'input/solana_escrow.so'
        expected_profile = profile.make_profile(request['network'], request['program_id'], request['genesis_hash'], request['mint'])
        if manifest['profile'] != expected_profile or hashlib.sha256(elf.read_bytes()).hexdigest() != manifest['artifact']['sha256']:
            raise AssertionError('Incoming profile/artifact does not match this fresh private program')
        airdrop = rpc('requestAirdrop', [str(keys['payer'].pubkey()), 100_000_000_000])
        wait_for(lambda: confirmed(airdrop))
        mint, payer = keys['mint'], keys['payer']
        send([create(mint, 82, TOKEN, payer), Instruction(TOKEN, b'\x14\x06' + bytes(payer.pubkey()) + b'\x01' + bytes(payer.pubkey()),
              [Meta(mint.pubkey(), False, True)])], payer, [mint])
        cli = [str(args.solana_bin / 'solana'), '--url', ENDPOINT, '--commitment', 'finalized',
               '--keypair', str(private / 'payer-keypair.json')]
        deploy = cli + ['program', 'deploy', str(elf), '--program-id', str(private / 'program-keypair.json'),
                        '--upgrade-authority', str(private / 'authority-keypair.json')]
        with (evidence / 'initial-deploy.log').open('xb') as stream:
            subprocess.run(deploy, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=240)
        mutable = profile.verify_rpc(manifest, rpc, expected_upgrade_authority=str(keys['authority'].pubkey()))
        try:
            profile.verify_rpc(manifest, rpc)
        except ValueError:
            pass
        else:
            raise AssertionError('Mutable program passed immutable admission')
        freeze = cli + ['program', 'set-upgrade-authority', str(keys['program'].pubkey()),
                        '--upgrade-authority', str(private / 'authority-keypair.json'), '--final']
        with (evidence / 'freeze.log').open('xb') as stream:
            subprocess.run(freeze, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=120)
        immutable = profile.verify_rpc(manifest, rpc)
        cases = [settlement_case(SolanaAdapter, manifest, mint, payer, refund) for refund in (False, True)]
        receipt = {'status': 'PASS', 'request': request, 'artifact': manifest['artifact'],
                   'mutable_observation': mutable, 'immutable_observation': immutable, 'cases': cases,
                   'scope': 'Private fresh Agave ledger with synthetic mint, normal initial deploy and real local RPC/CPI; no Circle USDC or public network'}
        write_json(evidence / 'qualification-receipt.json', receipt)
        print(json.dumps({'phase': 'complete', 'status': 'PASS', 'program_id': request['program_id']}), flush=True)
    finally:
        if validator.poll() is None:
            validator.terminate()
            try:
                validator.wait(timeout=30)
            except subprocess.TimeoutExpired:
                validator.kill(); validator.wait(timeout=15)
        log.close()


if __name__ == '__main__':
    main()
