"""Executable/layout selection only; no change to the frozen test protocols."""
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent


def select_paths(root=ROOT, environ=None, platform=None):
    environ = os.environ if environ is None else environ
    platform = os.name if platform is None else platform
    root = pathlib.Path(root).resolve()

    def selected(name, default):
        if name in environ:
            value = environ[name]
            if not value.strip():
                raise ValueError(name + ' must not be empty')
            path = pathlib.Path(value).expanduser()
            return (path if path.is_absolute() else root / path).resolve()
        return pathlib.Path(default).resolve()

    build = selected('SWAP_BUILD_DIR', root / 'b')
    suffix = '.exe' if platform == 'nt' else ''
    src = build / 'src' / 'Release' if platform == 'nt' else build / 'src'
    tests = build / 'tests' / 'Release' if platform == 'nt' else build / 'tests'
    return {
        'core': selected('SWAP_CORE_DIR', root / 'core'),
        'build': build,
        'daemon': selected('XDS_DAEMON', src / ('discreted' + suffix)),
        'wallet': selected('XDS_WALLET', src / ('simplewallet' + suffix)),
        'swap_tests': selected('XDS_SWAP_CHAIN_TESTS', tests / ('SwapChainTests' + suffix)),
        'bitcoind': selected('BITCOIND', root / 'external-tools/bitcoin-31.1/bin' / ('bitcoind' + suffix)),
    }


PATHS = select_paths()
CORE = PATHS['core']
BUILD = PATHS['build']
DAEMON = PATHS['daemon']
WALLET = PATHS['wallet']
SWAP_CHAIN_TESTS = PATHS['swap_tests']
BITCOIND = PATHS['bitcoind']
CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def artifact_key(path):
    path = pathlib.Path(path).resolve()
    if path.is_relative_to(CORE):
        return 'core/' + path.relative_to(CORE).as_posix()
    if path.is_relative_to(ROOT):
        return path.relative_to(ROOT).as_posix()
    return path.as_posix()


def executable_inventory():
    paths = {DAEMON, WALLET, SWAP_CHAIN_TESTS, BITCOIND, ROOT / 'solana_escrow.so'}
    for build in (BUILD, ROOT / 'a'):
        for component in ('src', 'tests'):
            directory = build / component / 'Release' if os.name == 'nt' else build / component
            for path in directory.glob('*'):
                if path.is_file() and (path.suffix.lower() == '.exe' if os.name == 'nt' else os.access(path, os.X_OK)):
                    paths.add(path)
    return sorted(paths, key=str)
