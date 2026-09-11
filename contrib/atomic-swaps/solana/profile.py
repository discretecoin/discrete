"""Immutable escrow build profiles and fail-closed, read-only deployment checks.

The caller must obtain the build manifest through its trusted release channel.
RPC responses are observations, not a cryptographic proof of chain finality.
"""
import base64
import hashlib
import struct

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111'
MINTS = {
    'mainnet-usdc': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    'devnet-usdc': '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
}


def decode_key(value):
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        raise ValueError('Expected a base58 32-byte public key or genesis hash')
    n = 0
    for ch in value:
        if ch not in ALPHABET:
            raise ValueError('Invalid base58 character')
        n = n * 58 + ALPHABET.index(ch)
    data = b'\0' * (len(value) - len(value.lstrip('1')))
    data += n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if len(data) != 32:
        raise ValueError('Expected exactly 32 bytes')
    return data


def encode_key(data):
    n = int.from_bytes(data, 'big')
    value = ''
    while n:
        n, digit = divmod(n, 58)
        value = ALPHABET[digit] + value
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + value


def make_profile(network, program_id, genesis_hash, local_mint=None):
    if network == 'local-synthetic':
        if not local_mint or local_mint in MINTS.values():
            raise ValueError('Local profile requires an explicit non-USDC synthetic mint')
        mint = local_mint
    elif network in MINTS and local_mint is None:
        mint = MINTS[network]
    else:
        raise ValueError('Choose mainnet-usdc, devnet-usdc or local-synthetic')
    for value in (program_id, genesis_hash, mint):
        decode_key(value)
    if program_id in (mint, TOKEN, LOADER, '11111111111111111111111111111111'):
        raise ValueError('Invalid escrow program identity')
    return {'schema': 1, 'network': network, 'genesis_hash': genesis_hash,
            'program_id': program_id, 'mint': mint, 'token_program': TOKEN,
            'decimals': 6, 'state_bytes': 192, 'pda_seed': 'xds-swap-v1'}


def validate_profile(profile):
    expected = make_profile(profile['network'], profile['program_id'], profile['genesis_hash'],
                            profile['mint'] if profile['network'] == 'local-synthetic' else None)
    if profile != expected:
        raise ValueError('Profile fields do not match the supported fixed protocol')
    return profile


def account_data(account, owner, executable, size=None):
    if not isinstance(account, dict) or account.get('owner') != owner or account.get('executable') is not executable:
        raise ValueError('Account owner/executable mismatch or missing account')
    if type(account.get('lamports')) is not int or account['lamports'] <= 0:
        raise ValueError('Account must exist with a positive lamport balance')
    encoded = account.get('data')
    if not isinstance(encoded, list) or len(encoded) != 2 or encoded[1] != 'base64':
        raise ValueError('Expected complete base64 account data')
    data = base64.b64decode(encoded[0], validate=True)
    if size is not None and len(data) != size:
        raise ValueError('Unexpected account size')
    return data


def programdata_address(program_account):
    data = account_data(program_account, LOADER, True, 36)
    if struct.unpack_from('<I', data)[0] != 2:
        raise ValueError('Expected upgradeable loader Program state')
    return encode_key(data[4:36])


def verify_accounts(manifest, program_account, programdata_account, mint_account,
                    *, expected_upgrade_authority=None):
    profile = validate_profile(manifest['profile'])
    pd_address = programdata_address(program_account)
    data = account_data(programdata_account, LOADER, False)
    if len(data) < 45 or struct.unpack_from('<I', data)[0] != 3 or data[12] not in (0, 1):
        raise ValueError('Invalid ProgramData metadata')
    authority = encode_key(data[13:45]) if data[12] == 1 else None
    if expected_upgrade_authority is not None:
        decode_key(expected_upgrade_authority)
    if authority != expected_upgrade_authority:
        raise ValueError('Program upgrade authority differs from the required authority; immutable required by default')
    size = manifest['artifact']['bytes']
    digest = manifest['artifact']['sha256']
    if type(size) is not int or not 64 <= size <= 10 * 1024 * 1024:
        raise ValueError('Invalid manifest executable length')
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('Invalid manifest executable digest')
    code = data[45:45 + size]
    if len(code) != size or code[:4] != b'\x7fELF' or hashlib.sha256(code).hexdigest() != digest or any(data[45 + size:]):
        raise ValueError('Deployed executable differs from the pinned ELF (or nonzero allocation padding)')
    mint = account_data(mint_account, TOKEN, False, 82)
    if mint[44] != 6 or mint[45] != 1 or struct.unpack_from('<I', mint, 0)[0] not in (0, 1) or struct.unpack_from('<I', mint, 46)[0] not in (0, 1):
        raise ValueError('Mint is not an initialized six-decimal legacy SPL mint')
    freeze_authority = encode_key(mint[50:82]) if struct.unpack_from('<I', mint, 46)[0] == 1 else None
    return {'program_id': profile['program_id'], 'programdata_address': pd_address,
            'mint': profile['mint'], 'artifact_sha256': digest,
            'immutable': authority is None, 'upgrade_authority': authority,
            'mint_freeze_authority': freeze_authority,
            'last_deployed_slot': struct.unpack_from('<Q', data, 4)[0]}


def verify_rpc(manifest, rpc, *, expected_upgrade_authority=None):
    """rpc(method, params) returns JSON-RPC `result`, raising on transport/RPC errors.

    The second call retrieves Program, ProgramData and mint in the same finalized
    bank. Clients must call this against independently selected trusted endpoints.
    """
    profile = validate_profile(manifest['profile'])
    if rpc('getGenesisHash', []) != profile['genesis_hash']:
        raise ValueError('RPC genesis does not match the explicit build profile')
    options = {'encoding': 'base64', 'commitment': 'finalized'}
    first = rpc('getAccountInfo', [profile['program_id'], options])
    pd_address = programdata_address(first['value'])
    min_slot = first['context']['slot']
    if type(min_slot) is not int or min_slot < 0:
        raise ValueError('Invalid initial account context slot')
    coherent = rpc('getMultipleAccounts', [[profile['program_id'], pd_address, profile['mint']],
                                          {**options, 'minContextSlot': min_slot}])
    slot = coherent['context']['slot']
    if type(slot) is not int or slot < min_slot or len(coherent['value']) != 3:
        raise ValueError('Invalid/stale account observation')
    program, programdata, mint = coherent['value']
    if programdata_address(program) != pd_address:
        raise ValueError('ProgramData linkage changed between observations')
    result = verify_accounts(manifest, program, programdata, mint,
                             expected_upgrade_authority=expected_upgrade_authority)
    if result['last_deployed_slot'] > slot:
        raise ValueError('Deployment slot exceeds account observation slot')
    return {**result, 'genesis_hash': profile['genesis_hash'], 'commitment': 'finalized',
            'context_slot': slot, 'scope': 'RPC observation; not an independent proof of finality'}
