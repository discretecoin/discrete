# Discrete

**Discrete is a post-quantum-only cryptocurrency** — a CryptoNote-family chain in
which *every block and every transaction is post-quantum from genesis*. There is
no legacy elliptic-curve (ECC) chain, no ring signatures, and no migration
"bridge": the quantum-resistant scheme is the only scheme the network has ever
spoken.

## What "post-quantum" means here

| Role | Primitive | Standard |
|---|---|---|
| Wallet **view** key / key exchange | ML-KEM-768 | FIPS 203 |
| Wallet **spend** key / signatures | ML-DSA-65 | FIPS 204 |
| Block signatures (identity-bound mining) | ML-DSA-65 | FIPS 204 |
| Key/commitment derivations | SHA3-256 + HKDF-SHA3-256 | FIPS 202 / RFC 5869 |
| Per-output payload encryption | ChaCha20-Poly1305 (IETF) | RFC 8439 |
| Proof-of-work | DiscretePower: SHAKE-256 + ML-DSA-65 + signature-tape yespower-discrete core | FIPS 202 / FIPS 204 |

Each identity has a long-term **ML-DSA-65 spend key** (spend authority) and an
**ML-KEM-768 view key** (scanning / payment detection); an address publishes
both. Only the holder of the spend secret can spend — the sender, who runs the
KEM encapsulation, cannot. See the [PQ ownership and authorization model](https://docs.discrete.cash/#/reference/pq-ownership-model)
for the complete construction. Mining is **identity-bound**:
the coinbase reward can only be spent by the same ML-DSA key that signed the block,
so pooling hash power requires sharing a spend secret.

Mining uses **DiscretePower**, in which every candidate is signed by the reward
identity's ML-DSA-65 key and that raw 3,312-byte signature tape is injected
throughout a modified yespower (`yespower-discrete`) memory-hard core. It is
identity-bound and delegation-hostile — a remote worker needs the whole
per-candidate tape, not a short digest — but it is **not** a proof that
purpose-built custodial pools are impossible. See the
[DiscretePower specification](https://docs.discrete.cash/#/consensus/pow).

The block ID is distinct from the PoW hash. It commits to the exact ML-DSA-65
block signature through a 32-byte SHAKE-256 witness, so randomized signatures
over one candidate are separate proof-bearing block IDs and cannot alias in
deduplication, checkpoints, or explorer lookups.

The candidate wire format, domain-separation tags, and blob sizes are
documented in the [PQ wire-format reference](https://docs.discrete.cash/#/consensus/pq-wire-format)
and pinned by `tests/test_pq_domains.cpp`.
For exchange and service wallet operation, including the two `walletd` deposit
modes and the recommended H-I-A-T-C workflow, see the
[walletd exchange integration guide](https://docs.discrete.cash/#/wallets/walletd-exchange-guide).

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

## Wallet quickstart (`simplewallet`)

Start a node, then open or generate a wallet with `simplewallet`. The wallet's
spend and view keys are derived from a single 25-word mnemonic — there is no
second seed to store.

Everything is post-quantum by default, so the commands carry no `pq_` prefix.
Interactive command history is kept only in memory: use the up/down arrow keys
to browse it. It is discarded when `simplewallet` exits and is never written to
disk.

| Command | Description |
|---|---|
| `address` | Show this wallet's address (bech32m; `disc1…` on mainnet) |
| `balance` | Show the balance |
| `transfer <address> <amount>` | Send funds to an address or account number |
| `register` | Register a free account number (anti-spam PoW, no fee) |
| `register_paid` | Register an account number with a fee |
| `account` | Show this wallet's account number |
| `sign_message "<msg>"` | Sign a message with the wallet's ML-DSA spend key |
| `verify_message "<msg>" <address> <sig>` | Verify an ML-DSA message signature |

Mine to your own identity with the daemon's `start_mining` (the reward is
bound to the mining identity — see identity-bound mining above):

```
start_mining <wallet-file> [threads=1] [--mining-password-file <path>]
```

The spend secret is never passed on the command line — it is the one root secret
the whole mining identity is derived from. The daemon reads it (read-only,
without modifying the file) from the encrypted wallet container, and takes the
password out of band: a no-echo console prompt, a piped stdin, or a `0600`
`--mining-password-file` for unattended/systemd starts. Legacy wallet files must
be opened once in `simplewallet`/`greenwallet` to upgrade them to the current
format before they can be used for mining.

## License

Distributed under the terms of the GNU Lesser General Public License v3. Discrete
is derived from Karbowanec / CryptoNote; see the per-file headers.
