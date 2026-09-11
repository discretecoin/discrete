"""Explicit owner lifecycle commands; private material enters through files only.

Run ``python -m swap_runtime.owner_cli --help`` for examples. This separate entry
point preserves the existing settlement CLI. ``init`` records an agreement and
credentials; funding happens only when the owner state machine is advanced by
``step`` or a bounded ``run``. Status and backup never call step. Restore has no
RPC transport and cannot submit funding or settlement from this interface.
"""

import argparse
import math
from pathlib import Path
import re
import time
from urllib.parse import quote

from .common import canonical, hex_bytes, private_read, strict_json
from .rpc import LocalRpc


ERROR = {'error': 'Owner action refused or outcome unknown; reopen the saved state before retrying.'}
PRIVATE_FIELDS = frozenset(('secret', 'preimage', 'xds_rho', 'foreign_key', 'credentials',
    'solana_accounts', 'raw', 'raw_hex', 'payload', 'wire', 'signed_wire', 'private_key',
    'keypair', 'seed', 'mnemonic', 'rpc_body', 'authorization', 'secret_key', 'secret_bytes',
    'raw_bytes', 'signed_transaction', 'transaction_hex'))
PRIVATE_NAMES = frozenset(re.sub('[^a-z0-9]', '', field) for field in PRIVATE_FIELDS)
EXAMPLES = '''Examples (credentials and owner.key must be private files):
  python -m swap_runtime keygen --journal-key owner.key
  python -m swap_runtime.owner_cli init --directory alice --owner-key owner.key \
    --offer offer.json --role foreign-owner --credentials alice-private.json \
    --rpc-config rpc.json --exchange-dir exchange --backup-dir backups
  python -m swap_runtime.owner_cli step --directory alice --owner-key owner.key --rpc-config rpc.json
  python -m swap_runtime.owner_cli run --directory alice --owner-key owner.key --rpc-config rpc.json \
    --max-steps 120 --poll-seconds 5
  python -m swap_runtime.owner_cli status --directory alice --owner-key owner.key --rpc-config rpc.json
  python -m swap_runtime.owner_cli backup --directory alice --owner-key owner.key --rpc-config rpc.json \
    --snapshot backups/alice-manual.bin
  python -m swap_runtime.owner_cli restore --directory alice-recovered --owner-key owner.key \
    --snapshot backups/alice-manual.bin
  python -m swap_runtime.owner_cli cancel --directory alice --owner-key owner.key --rpc-config rpc.json

RPC JSON has xds_daemon, foreign, optional xds_wallet and foreign_wallet records.
Each record has url, optional credential_file and timeout. foreign_wallet also
requires wallet_name (a loaded Bitcoin Core wallet); only literal loopback HTTP
endpoints are accepted. Native wallet uses /json_rpc; Bitcoin wallet uses its
explicit /wallet/<wallet_name> endpoint. Network and signer secrets are separate
private files. Credentials are accepted only by init and are never printed.
'''


class _Arguments(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unknown arguments/values, which may include
        # accidentally supplied key material. Keep the refusal independent of it.
        raise ValueError('Invalid owner command arguments')


def _owner():
    from .lifecycle import Owner
    return Owner


def _json(path, maximum=1024*1024):
    return strict_json(private_read(path, maximum))


def _key(path):
    return hex_bytes(private_read(path, 100).decode('ascii').strip(), 32, 'owner key')


def _credentials(path, offer, role):
    if type(offer) is not dict or offer.get('foreign_chain') not in ('bitcoin', 'solana'):
        raise ValueError('Agreement must identify the foreign chain')
    values = _json(path, 16384)
    required = {'xds_rho', 'foreign_key'} | ({'secret'} if role == 'foreign-owner' else set())
    allowed = required | ({'solana_accounts'} if offer['foreign_chain'] == 'solana' else set())
    if type(values) is not dict or not required <= set(values) or not set(values) <= allowed:
        raise ValueError('Exact private owner credentials required')
    hex_bytes(values['xds_rho'], 32, 'native rho')
    hex_bytes(values['foreign_key'], 32 if offer['foreign_chain'] == 'bitcoin' else 64, 'foreign key')
    if 'secret' in values:
        hex_bytes(values['secret'], 32, 'hashlock secret')
    if 'solana_accounts' in values:
        accounts = values['solana_accounts']
        if type(accounts) is not dict or set(accounts) != {'state', 'vault', 'refund'}:
            raise ValueError('Exact private Solana account keypairs required')
        for name in accounts:
            hex_bytes(accounts[name], 64, 'Solana account keypair')
    return values


def _rpc_record(record, bitcoin_wallet=False):
    fields = {'url', 'credential_file', 'timeout'} | ({'wallet_name'} if bitcoin_wallet else set())
    if type(record) is not dict or not {'url'} <= set(record) or not set(record) <= fields:
        raise ValueError('Exact RPC profile required')
    credentials = None
    if 'credential_file' in record:
        credentials = private_read(record['credential_file'], 4096).decode('utf8').strip()
    rpc = LocalRpc(record['url'], credentials, record.get('timeout', 15))
    if not bitcoin_wallet:
        return rpc
    name = record.get('wallet_name')
    if type(name) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', name) is None:
        raise ValueError('Explicit bounded Bitcoin wallet name required')
    return lambda method, params: rpc._json_rpc('/wallet/'+quote(name, safe=''), method, params)


def _transports(path):
    config = _json(path)
    fields = {'xds_daemon', 'xds_wallet', 'foreign', 'foreign_wallet'}
    if type(config) is not dict or not {'xds_daemon', 'foreign'} <= set(config) or not set(config) <= fields:
        raise ValueError('Exact owner RPC configuration required')
    daemon = _rpc_record(config['xds_daemon'])
    foreign = _rpc_record(config['foreign'])
    wallet = _rpc_record(config['xds_wallet']) if 'xds_wallet' in config else None
    foreign_wallet = _rpc_record(config['foreign_wallet'], True) if 'foreign_wallet' in config else None
    return daemon.daemon, foreign, wallet.wallet if wallet else None, foreign_wallet


def _emit(result):
    def check(value, depth=0):
        if depth > 12:
            raise ValueError('Owner result depth exceeds bound')
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str or re.sub('[^a-z0-9]', '', key.lower()) in PRIVATE_NAMES:
                    raise ValueError('Private field refused in owner output')
                check(item, depth+1)
        elif type(value) is list:
            if len(value) > 10000:
                raise ValueError('Owner output list exceeds bound')
            for item in value:
                check(item, depth+1)
        elif type(value) not in (str, int, float, bool, type(None)):
            raise ValueError('JSON owner metadata required')
    if type(result) is not dict:
        raise ValueError('Owner result must be metadata mapping')
    check(result)
    raw = canonical(result)
    if len(raw) > 131072:
        raise ValueError('Owner metadata exceeds output bound')
    print(raw.decode(), flush=True)


def _parser():
    parser = _Arguments(description='Owned-node atomic swaps: one-owner lifecycle',
                        epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter,
                        allow_abbrev=False)
    parser.add_argument('action', choices=('init', 'step', 'run', 'status', 'backup', 'restore', 'cancel'))
    parser.add_argument('--directory', required=True)
    parser.add_argument('--owner-key', required=True, help='private file containing the 32-byte encryption key as hex')
    parser.add_argument('--rpc-config', help='private loopback endpoint and credential-file configuration')
    parser.add_argument('--exchange-dir')
    parser.add_argument('--backup-dir')
    parser.add_argument('--offer', help='private agreed offer JSON, init only')
    parser.add_argument('--role', choices=('xds-owner', 'foreign-owner'), help='init only')
    parser.add_argument('--credentials', help='private signing/secret JSON, init only')
    parser.add_argument('--snapshot', help='new backup destination or restore input')
    parser.add_argument('--anchor-profile', help='private pinned external checkpoint profile outside owner storage')
    parser.add_argument('--offline-protective', action='store_true', help='restore only: emergency recovery without an available anchor')
    parser.add_argument('--max-steps', type=int, default=1, help='run bound: 1..10000 (default 1)')
    parser.add_argument('--poll-seconds', type=float, default=5, help='run interval: 0.1..60 (default 5)')
    return parser


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        if not 1 <= args.max_steps <= 10000 or not math.isfinite(args.poll_seconds) or not 0.1 <= args.poll_seconds <= 60:
            raise ValueError('Finite bounded owner run required')
        if args.action != 'run' and (args.max_steps != 1 or args.poll_seconds != 5):
            raise ValueError('Run options are only accepted by run')
        if args.action != 'init' and any((args.offer, args.role, args.credentials)):
            raise ValueError('Private initialization options cannot be used to replace existing owner state')
        if args.action not in ('backup', 'restore') and args.snapshot:
            raise ValueError('Snapshot argument is only for backup or restore')
        if args.offline_protective and (args.action != 'restore' or args.anchor_profile):
            raise ValueError('Offline protective mode is only an explicit unanchored restore')
        key = _key(args.owner_key)
        owner_type = _owner()
        anchor_options = {}
        if args.anchor_profile:
            profile = Path(args.anchor_profile).resolve()
            owner_directory = Path(args.directory).resolve()
            if profile == owner_directory or owner_directory in profile.parents:
                raise ValueError('Checkpoint profile must be outside the owner storage rollback domain')
            from .anchor import client_from_profile
            from .anchored_owner import AnchoredOwner
            owner_type = AnchoredOwner
            anchor_options['anchor_client'] = client_from_profile(profile)
        elif (Path(args.directory) / 'anchor-binding.json').exists():
            raise ValueError('Existing anchored owner requires its external profile')
        if args.action == 'restore':
            if not args.snapshot or any((args.rpc_config, args.exchange_dir, args.backup_dir)):
                raise ValueError('Restore requires only snapshot, new directory and private owner key')
            if args.offline_protective:
                from .anchored_owner import AnchoredOwner
                _emit(AnchoredOwner.restore_offline(args.snapshot, args.directory, key))
            else:
                _emit(owner_type.restore(args.snapshot, args.directory, key, **anchor_options))
            return 0
        if not args.rpc_config:
            raise ValueError('Explicit private RPC configuration required')
        options = dict(anchor_options)
        if args.exchange_dir is not None:
            options['exchange_dir'] = args.exchange_dir
        if args.backup_dir is not None:
            options['backup_dir'] = args.backup_dir
        if args.action == 'init':
            if not all((args.offer, args.role, args.credentials, args.exchange_dir, args.backup_dir)):
                raise ValueError('Init requires agreement, role, credentials, exchange and backup directories')
            offer = _json(args.offer)
            options.update(offer=offer, role=args.role, credentials=_credentials(args.credentials, offer, args.role))
            options['durable_funding'] = True
        if args.action == 'backup' and not args.snapshot:
            raise ValueError('New snapshot destination required')
        daemon, foreign, wallet, foreign_wallet = _transports(args.rpc_config)
        with owner_type(args.directory, key, daemon, foreign, wallet=wallet,
                        foreign_wallet=foreign_wallet, **options) as owner:
            if args.action == 'backup':
                path = owner.backup(args.snapshot)
                _emit({'snapshot_created': True, 'snapshot': str(path)})
            elif args.action in ('status', 'init'):
                _emit(owner.status())
            elif args.action == 'run':
                for index in range(args.max_steps):
                    _emit(owner.step())
                    if index+1 < args.max_steps:
                        time.sleep(args.poll_seconds)
            else:
                _emit(getattr(owner, args.action)())
        return 0
    except (Exception, KeyboardInterrupt):
        # Neither cryptographic/RPC exceptions nor invalid argv are safe to echo.
        print(canonical(ERROR).decode(), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
