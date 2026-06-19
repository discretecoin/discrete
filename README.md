# Discrete

**Discrete is a post-quantum-only cryptocurrency** — a CryptoNote-family chain in
which *every block and every transaction is post-quantum from genesis*. There is
no legacy elliptic-curve (ECC) chain, no ring signatures, and no migration
"bridge": the quantum-resistant scheme is the only scheme the network has ever
spoken.

> Status: pre-launch. Consensus parameters, genesis, and network identity are
> being finalized (see `docs/DISCRETE-COMPLETION-PLAN.md`). The PQ crypto core and
> wallet stack are implemented and test-covered.

## What "post-quantum" means here

| Role | Primitive | Standard |
|---|---|---|
| Wallet **view** key / key exchange | ML-KEM-768 | FIPS 203 |
| Wallet **spend** key / signatures | ML-DSA-65 | FIPS 204 |
| Block signatures (identity-bound mining) | ML-DSA-65 | FIPS 204 |
| Key/commitment derivations | SHA3-256 + HKDF-SHA3-256 | FIPS 202 / RFC 5869 |
| Per-output payload encryption | ChaCha20-Poly1305 (IETF) | RFC 8439 |
| Proof-of-work | yespower | — |

Each identity has a long-term **ML-DSA-65 spend key** (spend authority) and an
**ML-KEM-768 view key** (scanning / payment detection); a PQ address publishes
both. Only the holder of the spend secret can spend — the sender, who runs the
KEM encapsulation, cannot (see `docs/PQ-OWNERSHIP-FIX.md` for why this matters and
how the naive KEM-derived-spend-key design is broken). Mining is **identity-bound**:
the coinbase reward can only be spent by the same ML-DSA key that signed the block,
so pooling hash power requires sharing a spend secret.

The consensus-frozen wire format, domain-separation tags, and blob sizes are
documented in `docs/PQ-WIRE-FROZEN.md` and pinned by `tests/test_pq_domains.cpp`.

## Building (Windows / Visual Studio 2022, x64)

Discrete vendors [liboqs](https://github.com/open-quantum-safe/liboqs) (ML-KEM /
ML-DSA) and the other dependencies under `external/`. You need Visual Studio 2022
(Desktop C++), CMake, and Boost.

Configure once:

```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=ON -DOQS_BUILD_ONLY_LIB=ON
```

Build the binaries (Release):

```
cmake --build build --config Release --target Daemon SimpleWallet PaymentGateService
```

This produces, under `build/src/Release/`:

| Binary | Target | Purpose |
|---|---|---|
| `discreted.exe` | `Daemon` | full node / miner |
| `simplewallet.exe` | `SimpleWallet` | CLI wallet (full PQ support) |
| `walletd.exe` | `PaymentGateService` | JSON-RPC wallet service (PaymentGate) |
| `greenwallet.exe` | `GreenWallet` | alternative CLI wallet |

> Tests must be built and run with `--config Release` — the Debug config has a
> Boost/gtest CRT mismatch.

### Running the test suite

```
ctest --test-dir build -C Release -R Pq --output-on-failure
```

The `Pq*` suites cover the PQ crypto primitives, derivations, wire format,
validation, scanning, and chain integration.

## PQ wallet quickstart (`simplewallet`)

Start a node, then open or generate a wallet with `simplewallet`. The PQ
identity is derived from the same 25-word mnemonic that backs the wallet — there
is no second seed to store.

Everything is post-quantum by default, so the commands carry no `pq_` prefix.

| Command | Description |
|---|---|
| `address [bech32]` | Show this wallet's address (base58, or bech32m/QR) |
| `balance` | Show the balance |
| `transfer <address> <amount>` | Send funds to an address or account number |
| `register` | Register a free account number (anti-spam PoW, no fee) |
| `register_paid` | Register an account number with a fee |
| `account` | Show this wallet's account number |
| `sign_message "<msg>"` | Sign a message with the wallet's ML-DSA spend key |
| `verify_message "<msg>" <address> <sig>` | Verify an ML-DSA message signature |

Mine to your own PQ identity with the daemon's `start_mining` (the reward is
bound to the mining identity — see identity-bound mining above):

```
start_mining <wallet-file> [threads=1] [--mining-password-file <path>]
```

The spend secret is never passed on the command line — it is the one root secret
the whole PQ mining identity is derived from. The daemon reads it (read-only,
without modifying the file) from the encrypted wallet container, and takes the
password out of band: a no-echo console prompt, a piped stdin, or a `0600`
`--mining-password-file` for unattended/systemd starts. Legacy wallet files must
be opened once in `simplewallet`/`greenwallet` to upgrade them to the current
format before they can be used for mining.

## License

Distributed under the terms of the GNU Lesser General Public License v3. Discrete
is derived from Karbowanec / CryptoNote; see the per-file headers.
