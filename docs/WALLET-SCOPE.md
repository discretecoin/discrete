# Wallet Scope And Support Matrix

Discrete ships three wallet front-ends. All three are supported for post-quantum
(PQ) use; `simplewallet` remains the reference CLI.

| Front-end | Binary | Role | PQ support |
|---|---|---|---|
| simplewallet | `simplewallet.exe` | Reference interactive CLI | Full, canonical |
| greenwallet | `greenwallet.exe` | Alternative zedwallet-style CLI | Full, including `--testnet` |
| walletd | `walletd.exe` | JSON-RPC wallet for services/exchanges | Full PQ service API; see `docs/WALLETD-PQ.md` and `docs/WALLETD-EXCHANGE-GUIDE.md` |

## Greenwallet

`greenwallet` is supported for Discrete PQ. It uses the same `WalletGreen`,
`PqSender`, and `PqTransactionBuilder` core as walletd and exposes the same user
operations through the interactive command dispatcher.

| Operation | simplewallet | greenwallet |
|---|---|---|
| address display | `address` | `address` |
| balance display | `balance` | `balance` |
| transfer | `transfer <address-or-account> <amount>` | `transfer` |
| free account registration | `register` | `register` |
| paid account registration | `register_paid` | `register_paid` |
| account lookup | `account` | `account` |
| message signing / verification | ML-DSA | ML-DSA |

Both interactive wallets report "available" as spendable now: confirmed, out of
the mempool, and past any coinbase/timelock unlock height. Immature or
unconfirmed funds are shown as locked.

## Walletd

`walletd` is the programmatic interface for custodial/service use. Its PQ JSON-RPC
surface includes:

- `getAddress`
- `getBalance` and `getBalance(address)`
- `getDepositScheme`
- `createDepositAddress`
- `listDepositAddresses`
- `registerAccount`
- `registerAccountPaid`
- `getAccountStatus`
- `sendTransaction`
- transaction/history/filter methods

`getBalance.availableBalance` is spendable now. `lockedAmount` is the rest of the
owned balance, including mempool effects after a reorg and immature/timelocked
outputs. Address-scoped and aggregate balance calls use the same split.

## Guidance

- Interactive users: use `simplewallet` for the reference flow; `greenwallet` is
  available when its menu-driven workflow is preferred.
- Testnet users: pass `--testnet` to `simplewallet`, `greenwallet`, `walletd`, and
  `discreted` so address HRPs and chain parameters match.
- Exchanges/services: use `walletd`, choosing `--aggregated-multikey` or
  `--single-key-index` at container creation. The deposit scheme is persisted and
  cannot be changed for an existing container.
