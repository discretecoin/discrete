# Wallet scope & support matrix (Discrete)

Discrete ships three wallet front-ends. All three are **supported for post-quantum
(PQ) use**; `simplewallet` is the reference/primary CLI.

| Front-end | Binary | Role | PQ support |
|---|---|---|---|
| simplewallet | `simplewallet.exe` | Reference CLI | Full (canonical) |
| greenwallet | `greenwallet.exe` | Alternative interactive CLI (zedwallet-style) | Full parity |
| walletd | `walletd.exe` | JSON-RPC service (PaymentGate) for exchanges/services | Address, balance, free registration, status (see `docs/WALLETD-PQ.md`) |

## Decision: greenwallet IS supported for Discrete PQ

`greenwallet` implements the same PQ command family as `simplewallet`, all wired
to the same `WalletGreen` / `PqTransactionBuilder` core (no half-wired stubs):

| Command | simplewallet | greenwallet |
|---|---|---|
| `pq_address` | ✅ | ✅ |
| `pq_balance` | ✅ | ✅ |
| `pq_transfer` | ✅ | ✅ (builds + relays a real `TX_PQ`) |
| `pq_register` (free, anti-spam PoW) | ✅ | ✅ |
| `pq_register_paid` | ⚠️ (see below) | ⚠️ (see below) |
| `pq_account` | ✅ | ✅ |
| `sign_message` / `verify_message` | ✅ ML-DSA (PQ) | ✅ ML-DSA (PQ) |

`sign_message`/`verify_message` in **both** CLIs use the post-quantum scheme
(ML-DSA-65 over the wallet's spend key; `CryptoNoteFormatUtils::signMessagePq` /
`verifyMessagePq`). `verify_message` takes a PQ address.

### Known cross-cutting limitations (not greenwallet-specific)

- **`pq_register_paid`** routes through the classical fee-paying transfer path.
  In Discrete only `TX_PQ` is accepted by consensus, so the free, PoW-based
  `pq_register` is the recommended (and fully PQ-native) registration path. Paid
  registration over a `TX_PQ` carrying the registration tag is future work shared
  by all front-ends.
- **walletd** has no PQ-send path yet, so it exposes free `registerAccount` but
  returns `not_supported` for `registerAccountPaid` (see `docs/WALLETD-PQ.md`).

## Guidance

- Interactive users: either CLI works; `simplewallet` is the reference if you hit
  a discrepancy.
- Exchanges / services: use `walletd` (JSON-RPC). PQ deposit-address modes
  (aggregated-multikey / single-key-index) are tracked separately.
