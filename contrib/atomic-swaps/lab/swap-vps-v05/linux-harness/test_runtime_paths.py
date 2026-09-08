"""Pure path/process-option selection checks; no daemon, wallet or RPC execution."""
import importlib.util
import os
import pathlib
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import runtime_paths as paths


class RuntimePaths(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(__file__).resolve().parent

    def test_native_posix_defaults(self):
        selected = paths.select_paths(self.root, {}, 'posix')
        self.assertEqual(selected['daemon'], self.root / 'b/src/discreted')
        self.assertEqual(selected['wallet'], self.root / 'b/src/simplewallet')
        self.assertEqual(selected['swap_tests'], self.root / 'b/tests/SwapChainTests')
        self.assertEqual(selected['bitcoind'], self.root / 'external-tools/bitcoin-31.1/bin/bitcoind')
        self.assertEqual(selected['core'], self.root / 'core')

    def test_windows_defaults_preserve_v04_layout(self):
        selected = paths.select_paths(self.root, {}, 'nt')
        self.assertEqual(selected['daemon'], self.root / 'b/src/Release/discreted.exe')
        self.assertEqual(selected['wallet'], self.root / 'b/src/Release/simplewallet.exe')
        self.assertEqual(selected['swap_tests'], self.root / 'b/tests/Release/SwapChainTests.exe')
        self.assertEqual(selected['bitcoind'], self.root / 'external-tools/bitcoin-31.1/bin/bitcoind.exe')

    def test_relative_build_and_core_override_are_harness_relative(self):
        selected = paths.select_paths(self.root, {'SWAP_BUILD_DIR': 'native-build', 'SWAP_CORE_DIR': '../core'}, 'posix')
        self.assertEqual(selected['daemon'], self.root / 'native-build/src/discreted')
        self.assertEqual(selected['core'], (self.root / '../core').resolve())

    def test_explicit_executable_override_wins_on_both_platforms(self):
        env = {'SWAP_BUILD_DIR': 'ignored-build', 'XDS_DAEMON': 'bin/my-daemon',
               'XDS_WALLET': str(self.root / 'wallet-tool'), 'XDS_SWAP_CHAIN_TESTS': 'checks/swap',
               'BITCOIND': str(self.root / 'bitcoin-tool')}
        for platform in ('nt', 'posix'):
            selected = paths.select_paths(self.root, env, platform)
            self.assertEqual(selected['daemon'], self.root / 'bin/my-daemon')
            self.assertEqual(selected['wallet'], self.root / 'wallet-tool')
            self.assertEqual(selected['swap_tests'], self.root / 'checks/swap')
            self.assertEqual(selected['bitcoind'], self.root / 'bitcoin-tool')

    def test_empty_config_never_silently_falls_back(self):
        for name in ('SWAP_CORE_DIR', 'SWAP_BUILD_DIR', 'XDS_DAEMON', 'XDS_WALLET', 'XDS_SWAP_CHAIN_TESTS', 'BITCOIND'):
            for value in ('', ' '):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, name):
                    paths.select_paths(self.root, {name: value}, 'posix')

    def test_normal_environment_selection_matches_explicit_function(self):
        self.assertEqual(paths.PATHS, paths.select_paths(self.root, os.environ, os.name))
        self.assertEqual(paths.CREATE_NO_WINDOW, getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    def test_missing_windows_process_flag_maps_to_zero(self):
        spec = importlib.util.spec_from_file_location('runtime_paths_no_windows', pathlib.Path(paths.__file__))
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'subprocess': types.SimpleNamespace()}):
            spec.loader.exec_module(module)
        self.assertEqual(module.CREATE_NO_WINDOW, 0)

    def test_external_core_and_executable_paths_have_manifest_keys(self):
        external = self.root.parent / 'separate-core'
        with patch.object(paths, 'CORE', external):
            self.assertEqual(paths.artifact_key(external / 'src/Daemon/Daemon.cpp'), 'core/src/Daemon/Daemon.cpp')
            self.assertEqual(paths.artifact_key(self.root / 'xds_localnet.py'), 'xds_localnet.py')
            binary = self.root.parent / 'separate-build/discreted'
            self.assertEqual(paths.artifact_key(binary), binary.as_posix())

    def test_inventory_always_includes_selected_executables(self):
        inventory = paths.executable_inventory()
        for path in (paths.DAEMON, paths.WALLET, paths.SWAP_CHAIN_TESTS, paths.BITCOIND):
            self.assertIn(path, inventory)
        self.assertIn(paths.ROOT / 'solana_escrow.so', inventory)


if __name__ == '__main__':
    unittest.main(verbosity=2)
