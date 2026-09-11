"""Explicit foreground supervisor for one fresh or resumed private Agave ledger."""
import base64
import hashlib
import os
from pathlib import Path
import signal
import struct
import subprocess
import time

from solders.pubkey import Pubkey
from solders.rent import Rent
from swap_runtime.common import SessionLock, canonical, integer, new_private_file
from swap_runtime.rpc import LocalRpc
from swap_runtime.solana import profile
from .bridge import wait_for
from .support import (AGAVE_VERSION, ARTIFACT, ELF_SHA256, VALIDATOR_SHA256, artifact_manifest,
    isolated_network, local_manifest, private_directory, public_ready, read_json,
    read_key, regular, write_json, write_keys)


def validate_validator(path, expected_hash):
    path = regular(Path(path).absolute())
    if (type(expected_hash) is not str or len(expected_hash) != 64
            or any(x not in '0123456789abcdef' for x in expected_hash)):
        raise ValueError('Expected validator SHA256 required')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_hash or expected_hash != VALIDATOR_SHA256:
        raise ValueError('Validator differs from operator-pinned binary hash')
    try:
        version = subprocess.run([str(path), '--version'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=15).stdout.decode().strip()
    except Exception:
        raise ValueError('Cannot verify validator version') from None
    if version != AGAVE_VERSION:
        raise ValueError('Exact Agave 4.2.2 build required')
    return path


def mint_account(address, minter):
    # Legacy SPL Mint layout; no Circle assets or Token-2022 extensions.
    data = struct.pack('<I', 1) + bytes(minter) + struct.pack('<QBBI', 0, 6, 1, 1) + bytes(minter)
    if len(data) != 82:
        raise AssertionError('Mint layout differs')
    return {'pubkey': address, 'account': {'lamports': 10_000_000,
        'data': [base64.b64encode(data).decode(), 'base64'], 'owner': profile.TOKEN,
        'executable': False, 'rentEpoch': 0, 'space': 82}}


def program_accounts():
    """Exact immutable genesis state, not Agave's Some(default-pubkey) shortcut."""
    manifest = artifact_manifest()
    program = Pubkey.from_string(manifest['profile']['program_id'])
    loader = Pubkey.from_string(profile.LOADER)
    programdata, _ = Pubkey.find_program_address([bytes(program)], loader)
    elf = (ARTIFACT / 'solana_escrow.so').read_bytes()
    program_bytes = struct.pack('<I', 2) + bytes(programdata)
    # Metadata occupies 45 bytes even when the serialized Option is None.
    # The ELF begins at the fixed loader offset, never immediately after None.
    data_bytes = struct.pack('<IQB', 3, 0, 0) + bytes(32) + elf
    def dump(address, data, executable):
        return {'pubkey': str(address), 'account': {'lamports': Rent.default().minimum_balance(len(data)),
            'data': [base64.b64encode(data).decode(), 'base64'], 'owner': profile.LOADER,
            'executable': executable, 'rentEpoch': 0, 'space': len(data)}}
    return dump(program, program_bytes, True), dump(programdata, data_bytes, False)


def validator_command(binary, run, minter, fresh):
    command = [str(binary), '--config', str(run / 'cli.yml'), '--ledger', str(run / 'ledger'),
        '--bind-address', '127.0.0.1', '--rpc-port', '18899', '--faucet-port', '19900',
        '--gossip-port', '18001', '--dynamic-port-range', '18002-18100',
        '--limit-ledger-size', '50000', '--rpc-pubsub-queue-capacity-items', '1000',
        '--rpc-pubsub-queue-capacity-bytes', '16777216', '--rpc-pubsub-worker-threads', '1',
        '--rpc-pubsub-notification-threads', '1', '--log']
    if fresh:
        p = artifact_manifest()['profile']
        program, programdata = program_accounts()
        command += ['--mint', str(minter), '--account', p['mint'], str(run / 'mint-account.json'),
            '--account', program['pubkey'], str(run / 'program-account.json'),
            '--account', programdata['pubkey'], str(run / 'programdata-account.json')]
    return command


def run_validator(run, binary, expected_hash, maximum_seconds=1800, resume=False, on_ready=None):
    """No reset, no deployment, no external URLs, no background orphan process."""
    isolated_network()
    integer(maximum_seconds, 'fixture lifetime', 60, 3600)
    binary = validate_validator(binary, expected_hash)
    artifact_manifest()
    run = private_directory(run, create=not resume)
    lock = SessionLock(run / 'supervisor')
    validator = None
    log = None
    previous = {}
    stop = False
    try:
        if resume:
            ready = public_ready(read_json(run / 'ready.json'))
            if ready['validator_sha256'] != expected_hash:
                raise ValueError('Resume requires the same validator binary')
            if not (run / 'ledger/genesis.bin').is_file():
                raise ValueError('Resume requires the retained initialized ledger')
            minter = read_key(run, 'minter')
            expected_genesis = ready['manifest']['profile']['genesis_hash']
        else:
            keys = write_keys(run, ('minter', 'owner', 'claim'))
            minter = keys['minter']
            p = artifact_manifest()['profile']
            write_json(run / 'mint-account.json', mint_account(p['mint'], minter.pubkey()))
            program, programdata = program_accounts()
            write_json(run / 'program-account.json', program)
            write_json(run / 'programdata-account.json', programdata)
            write_json(run / 'local.json', dict(version=1, endpoint='http://127.0.0.1:18899'))
            new_private_file(run / 'cli.yml', b'json_rpc_url: "http://127.0.0.1:18899"\n'
                b'websocket_url: ""\nkeypair_path: "unused-fixture-key"\naddress_labels: {}\ncommitment: "confirmed"\n')
            expected_genesis = None
        started = time.time_ns()
        log = (run / ('validator-' + str(started) + '.log')).open('xb')
        # Agave writes private identity/faucet keys beneath ledger; inherit 0077.
        validator = subprocess.Popen(validator_command(binary, run, minter.pubkey(), not resume),
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, umask=0o077)

        def stop_signal(_signum, _frame):
            nonlocal stop
            stop = True

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, stop_signal)
        rpc = LocalRpc('http://127.0.0.1:18899', timeout=5)

        def initialized():
            if stop or validator.poll() is not None:
                raise ValueError('Validator stopped before readiness')
            try:
                genesis = rpc('getGenesisHash', [])
                manifest = local_manifest(genesis)
                proof = profile.verify_rpc(manifest, rpc)
                return (manifest, proof)
            except (OSError, ValueError):
                return None

        manifest, proof = wait_for(initialized, timeout=180)
        if expected_genesis is not None and manifest['profile']['genesis_hash'] != expected_genesis:
            raise ValueError('Retained ledger genesis changed')
        record = dict(version=1, kind='synthetic-agave-fixture', manifest=manifest,
            validator_sha256=expected_hash, validator_version=AGAVE_VERSION, genesis_loading=True)
        if resume:
            if record != ready:
                raise ValueError('Resumed fixture differs from retained identity')
        else:
            write_json(run / 'ready.json', record)
        write_json(run / ('start-' + str(started) + '.json'), dict(ready=record, proof=proof,
            pid=validator.pid, artifact_sha256=ELF_SHA256, resumed=resume))
        if on_ready:
            on_ready(record)
        deadline = time.monotonic() + maximum_seconds
        while not stop and time.monotonic() < deadline:
            if validator.poll() is not None:
                raise ValueError('Owned validator exited during fixture run')
            time.sleep(0.25)
        return record
    finally:
        if validator is not None:
            if validator.poll() is None:
                validator.terminate()
                try:
                    validator.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    validator.kill()
                    validator.wait(timeout=10)
            write_json(run / ('stop-' + str(started) + '.json'), dict(pid=validator.pid,
                returncode=validator.returncode, ledger_retained=True))
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if log is not None:
            log.close()
        lock.close()
