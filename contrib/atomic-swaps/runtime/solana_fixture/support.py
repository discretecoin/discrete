"""Pinned artifact and private test-run files; no production configuration."""
import copy
import hashlib
import os
from pathlib import Path
import socket
import stat

from solders.keypair import Keypair
from swap_runtime.common import canonical, new_private_file, private_read, strict_json
from swap_runtime.solana import profile

ARTIFACT = Path(__file__).resolve().parents[1] / 'tests/fixtures/solana-v06'
ELF_SHA256 = '561e0b7ad5e4be59a3056482ea94370064d201f45a378964d0fdb9f0ff76a901'
MANIFEST_SHA256 = '3280a82ad13cd2671b558f001678615ced7fee1b8dbfae820071f87836f7bd7f'
AGAVE_VERSION = 'solana-test-validator 4.2.2 (src:c9c6f328; feat:21b0d33a, client:Agave)'
VALIDATOR_SHA256 = 'd723f3a99fa3f5b3df6841fc04ac0d8b5302837689d43a07222aa2125b6713d1'
MAX_PACKET = 8 * 1024 * 1024


def regular(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Regular fixture file required')
    return path


def private_directory(path, create=False):
    path = Path(path).absolute()
    # Reject a linked path component before following it. Run files are trusted
    # operator configuration, never a public mailbox or another user's directory.
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('Linked fixture directory rejected')
    if create:
        path.mkdir(mode=0o700)  # Exclusive; never reset an existing ledger.
    if not path.is_dir():
        raise ValueError('Existing fixture directory required')
    if os.name != 'nt' and (path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid()):
        raise ValueError('Fixture directory must be private and owned by this user')
    return path


def read_json(path):
    return strict_json(private_read(regular(path), MAX_PACKET))


def write_json(path, value):
    new_private_file(path, canonical(value) + b'\n')


def write_keys(run, names):
    keys = {}
    for name in names:
        key = Keypair()
        write_json(run / (name + '.json'), list(bytes(key)))
        keys[name] = key
    return keys


def read_key(run, name):
    try:
        value = read_json(run / (name + '.json'))
        if type(value) is not list or len(value) != 64 or any(type(x) is not int or not 0 <= x < 256 for x in value):
            raise ValueError()
        return Keypair.from_bytes(bytes(value))
    except Exception:
        raise ValueError('Invalid private fixture key file') from None


def artifact_manifest(directory=ARTIFACT):
    directory = Path(directory)
    raw = regular(directory / 'build-manifest.json').read_bytes()
    elf = regular(directory / 'solana_escrow.so').read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256 or hashlib.sha256(elf).hexdigest() != ELF_SHA256:
        raise ValueError('Committed synthetic fixture artifact differs from pinned bytes')
    manifest = strict_json(raw)
    profile.validate_profile(manifest['profile'])
    if manifest['profile']['network'] != 'local-synthetic' or manifest['artifact']['bytes'] != len(elf):
        raise ValueError('Synthetic fixture manifest required')
    return manifest


def local_manifest(genesis_hash):
    manifest = copy.deepcopy(artifact_manifest())
    p = manifest['profile']
    manifest['profile'] = profile.make_profile('local-synthetic', p['program_id'], genesis_hash, p['mint'])
    return manifest


def validate_manifest(manifest):
    try:
        expected = local_manifest(manifest['profile']['genesis_hash'])
    except (TypeError, KeyError, ValueError):
        raise ValueError('Invalid synthetic fixture manifest') from None
    if manifest != expected:
        raise ValueError('Fixture manifest may change only the local genesis hash')
    return manifest


def isolated_network():
    # Agave 4.2.2's faucet binds 0.0.0.0 even with --bind-address.
    # Require a namespace containing only loopback, not a public host firewall.
    if os.name != 'posix' or not Path('/proc/self/ns/net').is_file():
        raise ValueError('Linux network namespace required for the validator')
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise ValueError('Validator namespace must contain only loopback')
    flags = int(Path('/sys/class/net/lo/flags').read_text().strip(), 16)
    if not flags & 1:
        raise ValueError('Namespace loopback must be up')


def public_ready(value):
    required = {'version', 'kind', 'manifest', 'validator_sha256', 'validator_version', 'genesis_loading'}
    if type(value) is not dict or set(value) != required or value['version'] != 1 or value['kind'] != 'synthetic-agave-fixture':
        raise ValueError('Exact fixture readiness record required')
    validate_manifest(value['manifest'])
    digest = value['validator_sha256']
    if type(digest) is not str or len(digest) != 64 or any(x not in '0123456789abcdef' for x in digest):
        raise ValueError('Pinned validator hash required')
    if (value['validator_version'] != AGAVE_VERSION or digest != VALIDATOR_SHA256
            or value['genesis_loading'] is not True):
        raise ValueError('Pinned synthetic genesis fixture required')
    return value
