"""Explicit single-action CLI. Private material is read only from private files."""
import argparse
import json
import os

from .common import SessionLock, canonical, hex_bytes, new_private_file, private_read, strict_json
from .journal import Journal
from .rpc import LocalRpc
from .session import Session


def _json(path):
    return strict_json(private_read(path, 1024 * 1024))


def _key(path):
    raw = private_read(path, 100).strip()
    return hex_bytes(raw.decode('ascii'), 32, 'journal key')


def _transport(config, name, required=True):
    record = config.get(name)
    if record is None and not required:
        return None
    if type(record) is not dict or not {'url'} <= set(record) or not set(record) <= {'url', 'credential_file', 'timeout'}:
        raise ValueError('Invalid RPC profile: ' + name)
    credential = None
    if record.get('credential_file'):
        credential = private_read(record['credential_file'], 4096).decode('utf8').strip()
    return LocalRpc(record['url'], credential, record.get('timeout', 15))


def _signer(session, kind, path):
    if path is None:
        raise ValueError('Private signing credential file required')
    raw = private_read(path, 4096).strip()
    if kind.startswith('xds-'):
        return hex_bytes(raw.decode('ascii'), 32, 'native role rho')
    if session.config['foreign_chain'] == 'bitcoin':
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec.derive_private_key(int.from_bytes(hex_bytes(raw.decode('ascii'), 32, 'Bitcoin private key'), 'big'), ec.SECP256K1())
    from solders.keypair import Keypair
    values = json.loads(raw)
    if type(values) is not list or len(values) != 64 or any(type(v) is not int or not 0 <= v <= 255 for v in values):
        raise ValueError('Solana CLI 64-byte keypair file required')
    return Keypair.from_bytes(bytes(values))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Owned-node atomic swap settlement reference runtime')
    parser.add_argument('action', choices=('keygen', 'init', 'observe', 'prepare', 'broadcast', 'reconcile',
                                          'witness', 'renew', 'backup', 'restore'))
    parser.add_argument('--journal')
    parser.add_argument('--journal-key', required=True)
    parser.add_argument('--swap-id')
    parser.add_argument('--rpc-config')
    parser.add_argument('--config')
    parser.add_argument('--kind', choices=('xds-claim', 'xds-refund', 'foreign-claim', 'foreign-refund'))
    parser.add_argument('--key-file')
    parser.add_argument('--secret-file')
    parser.add_argument('--public-xds-txid')
    parser.add_argument('--snapshot')
    args = parser.parse_args(argv)
    try:
        if args.action == 'keygen':
            new_private_file(args.journal_key, os.urandom(32).hex().encode() + b'\n')
            result = {'journal_key_created': True}
        else:
            key = _key(args.journal_key)
            if not args.journal:
                raise ValueError('Journal path required')
            if args.action == 'restore':
                if not args.snapshot:
                    raise ValueError('Snapshot path required')
                with_lock = SessionLock(args.journal)
                try:
                    journal = Journal.restore(args.snapshot, args.journal, key)
                    journal.close()
                finally:
                    with_lock.close()
                result = {'recovery_required': True, 'new_journal_created': True}
            else:
                if not args.swap_id or not args.rpc_config:
                    raise ValueError('Swap identity and private RPC configuration required')
                rpc = _json(args.rpc_config)
                if type(rpc) is not dict or not {'xds_daemon', 'foreign'} <= set(rpc) or not set(rpc) <= {'xds_daemon', 'xds_wallet', 'foreign'}:
                    raise ValueError('Invalid RPC configuration')
                daemon = _transport(rpc, 'xds_daemon')
                foreign = _transport(rpc, 'foreign')
                wallet = _transport(rpc, 'xds_wallet', False)
                config = _json(args.config) if args.action == 'init' and args.config else None
                if args.action == 'init' and config is None:
                    raise ValueError('Private fixed-terms configuration file required')
                with Session(args.journal, key, args.swap_id, daemon.daemon, foreign,
                             wallet=wallet.wallet if wallet else None, config=config) as session:
                    if args.action == 'init':
                        result = {'session_created': True, 'swap_id': args.swap_id, 'role': session.config['role']}
                    elif args.action == 'observe':
                        _, result = session.observe()
                        # Native observation includes funding wire, never claim material.
                        result |= {'possibly_exposed': session.journal.exposed(session.id),
                                   'public_exposure_observed': session._public_proof(),
                                   'recovery_required': session.journal.recovery_required()}
                    elif args.action == 'backup':
                        if not args.snapshot:
                            raise ValueError('New snapshot path required')
                        session.snapshot(args.snapshot)
                        result = {'snapshot_created': True}
                    elif args.action in ('prepare', 'renew'):
                        signer = _signer(session, args.kind or '', args.key_file)
                        if args.action == 'renew':
                            if args.secret_file or args.public_xds_txid:
                                raise ValueError('Renewal uses the existing encrypted intent only')
                            result = session.renew_solana(args.kind, signer)
                        else:
                            secret = hex_bytes(private_read(args.secret_file, 100).decode('ascii').strip(), 32, 'secret') if args.secret_file else None
                            result = session.prepare(args.kind, signer, secret, args.public_xds_txid)
                    elif args.action == 'witness':
                        result = session.reobserve_public_xds(args.kind, args.public_xds_txid)
                    else:
                        result = getattr(session, args.action)(args.kind)
        print(canonical(result).decode())
        return 0
    except Exception:
        # Crypto/RPC libraries may include wire data in exceptions. Never print
        # those values or a traceback from this interface; journal state persists.
        print('{"error":"Action refused or outcome unknown; inspect the private configuration and reconcile before retrying."}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
