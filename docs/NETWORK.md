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
| Base58 public-address prefix | `0x3445db` → human-readable **`disc`** |
| Bech32m HRP (PQ, opt-in) | `disc` (`kPqBech32Hrp` in `include/PqAddress.h`) |

Base58 is the default PQ-address encoding. The prefix was verified: generated
classical addresses render as `discv…` and the prefix round-trips through
encode/decode (`tests/test_pq_seed_address.cpp`). PQ addresses use the same
prefix but, being ~3 KB payloads, do not show `disc` as leading text.

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
hash: `a77e3f242f03f8ebe1d6bc4b50873fe157f4c2c95d9ff4207107991439c399ee`.
