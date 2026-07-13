# Discrete network identity

Final, frozen network-identity constants. Most live in `src/CryptoNoteConfig.h`;
the P2P network id lives in `src/P2p/P2pNetworks.h`.

## Names / units

| Item | Value | Where |
|------|-------|-------|
| Coin name | `Discrete` | `CRYPTONOTE_NAME` |
| Ticker | `XDS` | `CRYPTONOTE_TICKER` |
| Decimals | 2 (1 XDS = 100 atoms) | `CRYPTONOTE_DISPLAY_DECIMAL_POINT` |
| Emission ceiling | 21,000,000 XDS | `EMISSION_CURVE_TARGET` |

## Addresses

| Item | Value |
|------|-------|
| Extended-Bech32m HRP — mainnet | **`disc`** (`kPqBech32HrpMainnet` in `include/PqAddress.h`) |
| Extended-Bech32m HRP — testnet | **`tdisc`** (`kPqBech32HrpTestnet`) |
| Network-prefix field (in payload) | `0x3445db` (`CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX`) |

The sole PQ-address encoding uses the Bech32m alphabet and checksum constant, but its
~5,043-character length exceeds BIP-173/BIP-350's 90-character profile. It is therefore
an extended Bech32m-derived transport, not a standard Bitcoin Bech32m address and not a
single-frame QR payload. Addresses are self-identifying
by network: mainnet renders as `disc1…`, testnet as `tdisc1…`, so a testnet
address can't be mistaken for mainnet. The HRP is chosen at encode time from the
wallet's network (`pqBech32Hrp(currency.isTestnet())`); decode accepts either
known HRP. The `0x3445db` network-prefix is still carried inside the cemented
address payload and covered by the checksum, but it is no longer surfaced as
leading text. Round-trip and HRP behaviour are covered by
`tests/test_pq_seed_address.cpp`.

## P2P network id (GUID)

`P2p/P2pNetworks.h` → `CRYPTONOTE_NETWORK`:

```
f53566d4-4d36-350e-5251-04c338fad823
```

A fresh random 16-byte GUID, distinct from Karbo's, so the two networks cannot
cross-connect — the handshake rejects peers whose network id differs (the daemon
logs `Network: f53566d4-4d36-350e-5251-04c338fad823` at startup). Previously this
was derived at compile time from the genesis string via a deprecated boost
name-generator; it is now an explicit, auditable constant. **Frozen** — changing
it forks the P2P network.

## Ports

Short (4-digit) contiguous block:

| Service | Port | Constant |
|---------|-----:|----------|
| P2P | 9330 | `P2P_DEFAULT_PORT` |
| RPC | 9331 | `RPC_DEFAULT_PORT` |
| RPC (SSL) | 9332 | `RPC_DEFAULT_SSL_PORT` |
| Wallet RPC | 9333 | `WALLET_RPC_DEFAULT_PORT` |
| Wallet RPC (SSL) | 9334 | `WALLET_RPC_DEFAULT_SSL_PORT` |
| Gate RPC | 9335 | `GATE_RPC_DEFAULT_PORT` |
| Gate RPC (SSL) | 9336 | `GATE_RPC_DEFAULT_SSL_PORT` |

## P2P stat trusted key

`P2P_STAT_TRUSTED_PUB_KEY` is set to all-zero (32 bytes). It is **unused** — no
code reads it, and the optional stat-reporting feature it would gate is not wired.
If that feature is ever enabled, generate a keypair, put the public key here, and
keep the secret offline.

## Seed nodes

`SEED_NODES` (placeholders pending DNS; the daemon tolerates unreachable seeds):

```
seed1.discrete.cash:9330
seed2.discrete.cash:9330
```

## Genesis

The genesis coinbase (`GENESIS_COINBASE_TX_HEX`) and the network id are
independent constants now. See [GENESIS.md](GENESIS.md). Mainnet genesis block
hash: `3101b248ac612883c47b93fa6a4d9d34020ee2f7541ad17e73c42088748a5219`.
