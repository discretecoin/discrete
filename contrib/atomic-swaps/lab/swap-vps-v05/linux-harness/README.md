# V05 copies of the frozen V04 harness for Linux

Source baseline: V04 Core `1e947a8e66ec963e8e634b14fec29343ef7d8822`, branch
`[local branch]`, clean at the local source check. The original V04
files and Core are unchanged. `baseline-manifest.json` records SHA256 of the 18
copied source/artifact files; `portability.patch` describes every copied-source
edit. `portability-manifest.json` binds the final copied/configuration files.

Only path selection, Windows process flags and matching evidence-path discovery
change. Test assertions, timeout values, subprocess cleanup, amounts, fees,
confirmation counts, key/seed fixtures, network membership, claim/refund and
partition/rejoin behavior remain the V04 definitions. This package implements no
consensus or activation change and starts no public network. Do not overwrite
the frozen V04 directory with Linux builds or new run artifacts.

## Layout and executable selection

Defaults are relative to this harness directory:

| Item | Linux/default native layout | Windows/default V04 layout | Override |
|---|---|---|---|
| Core source checkout | `core/` | `core/` | `SWAP_CORE_DIR` |
| Build tree | `b/` | `b/` | `SWAP_BUILD_DIR` |
| XDS daemon | `b/src/discreted` | `b/src/Release/discreted.exe` | `XDS_DAEMON` |
| Wallet | `b/src/simplewallet` | `b/src/Release/simplewallet.exe` | `XDS_WALLET` |
| Pair driver | `b/tests/SwapChainTests` | `b/tests/Release/SwapChainTests.exe` | `XDS_SWAP_CHAIN_TESTS` |
| Bitcoin Core 31.1 | `external-tools/bitcoin-31.1/bin/bitcoind` | same plus `.exe` | `BITCOIND` |

Explicit executable overrides take precedence over the build directory. Relative
overrides are anchored to the harness directory, not the caller's working
directory. Use actual executable paths; overrides do not search `PATH`.
Empty variables are errors. Set them before starting Python; modules snapshot
the selection at import. The Linux default corresponds to a single-config
CMake build; for multi-config/custom output locations use explicit overrides.
CMake sources: `core/src/CMakeLists.txt:220–221` select `discreted` and
`simplewallet`; `core/tests/CMakeLists.txt:287–292` defines `SwapChainTests`.

For a separately unpacked/built checkpoint, a parent-owned Linux shell can set:

```bash
export SWAP_CORE_DIR=/absolute/path/to/checkpoint-core
export SWAP_BUILD_DIR=/absolute/path/to/native-build
export BITCOIND=/absolute/path/to/bitcoin-31.1/bin/bitcoind
```

`run_evidence.py` still needs a Git checkout for Core identity and tracked-file
enumeration. An archive without Git metadata does not satisfy that runner.
An external Core checkout gets stable `core/` source labels; external binaries
get absolute labels. The receipt additionally records selected runtime paths.
Native executable inventory covers executable files in build `src/` and
`tests/`, plus explicitly selected binaries and the escrow SBF. Windows keeps
its `Release/*.exe` discovery. The old Windows `a/` directory is still considered
when present; no ASan profile is generated or qualified by this port.

## Dependencies and same-test execution

Require Python 3.9+ for the path API (the target Debian 12 normally supplies 3.11;
the actual VPS Python is a parent runtime check). Python code uses standard
library plus `cryptography` and `solders`/LiteSVM. V04's recorded vendored package
versions were `solders 0.29.0`, `jsonalias 0.1.1`, `typing_extensions 4.16.0`.
The V04 inventory did not pin the ambient cryptography version; record and
qualify the selected Linux version instead of inventing a matching baseline.
Do not copy Windows Python native modules into a Linux `python-deps/` directory;
install compatible Linux packages in a dedicated environment. The existing
optional `python-deps` import path remains unchanged.

The copied SBF is the exact V04 artifact, SHA256
`91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89`.
`solana-build.json` records its original source/compiler identity. This preserves
the existing LiteSVM tests; it is not a Linux compiler reproduction or a real
Solana validator/RPC run, and the mint is not Circle-issued USDC.

After the parent has built/qualified the selected native artifacts and installed
dependencies, use fresh names from this directory:

```bash
python3 -B -m unittest -v test_runtime_paths
python3 -B -u run_evidence.py linux-network python3 -B -u -m unittest -v test_xds_wallet_network test_network_cross_chain
python3 -B -u run_evidence.py linux-boundaries python3 -B -u -m unittest -v test_localnet_boundaries
python3 -B -u run_evidence.py linux-adapters python3 -B -u -m unittest -v test_bitcoin_regtest test_solana_vm test_swap_journal test_solana_journal test_journal_recovery
python3 -B -u run_evidence.py linux-pair python3 -B -u -m unittest -v test_cross_chain
```

Do not run unrestricted `unittest discover`: it would execute all imported
integration tests and start owned processes. The boundary suite keeps the
existing source guard-order preflight before its process tests. CTest remains
a separate native build qualification, using the actual selected build path;
no Windows `S:` mapping or `.cmd` helper is required on Linux.

## Port and process notes

- Each XDS node independently selects a free `127.0.0.1` P2P port and RPC port.
  A four-node network has eight such listeners and twelve loopback TCP relays
  (one for every directed pair). Every wallet RPC selects another loopback port.
  Partitioning toggles those existing relays; no firewall rule changes are used.
- Bitcoin fixtures select a random loopback RPC port, use a fresh private
  `regtest` data directory/cookie, and keep `-listen=0 -dnsseed=0 -discover=0
  -connect=0`. They do not use the dedicated persistent RPC port 18443.
- All these random ports stay on the VPS and are operated through SSH exec.
  No `PermitOpen` or public ingress expansion is required. The persistent
  8899/8900/18443/29331 tunnel allowlist is a separate service interface.
- Existing `port()` releases its temporary reservation before the daemon binds;
  a local allocation race remains possible. No allocator/locking change was
  bundled into this path port. Port assignment and all wait deadlines are unchanged.
- Six process creation sites now use the Windows no-window flag only where that
  constant exists; POSIX receives zero. Commands still use argument arrays with
  no shell. `select`, loopback sockets, threads, pipes, pathlib, sqlite and
  `sys.executable` child tests have no remaining hardcoded Windows launch path.
- Cleanup still uses only owned Popen handles, RPC stop, bounded wait and the
  existing terminate/kill fallbacks. POSIX terminate is SIGTERM and kill is
  SIGKILL; the old Windows forced-termination result does not prove identical
  Linux shutdown timing or crash-recovery outcomes. No process groups or
  shutdown semantics were changed.
- Existing bounded readiness/scan/receipt timeouts may fail on 1 vCPU/1 GiB under
  contention. Keep original timing for the first measured run; do not quietly
  extend timeouts, lower proof difficulty, fees or maturity to claim parity.
  Building/running the real Solana validator and memory/storage feasibility are
  separate parent work, not established by these copies.

## Qualification boundary

Local source/path tests and Python syntax inspection cover this portability
delta only. Native Linux compilation/linking, selected library versions,
executable permissions, real process startup/teardown, actual chain behavior,
the full integration matrix, Linux sanitizers and resource limits require
separate Linux evidence. The parent owns deployment and project-state updates.
