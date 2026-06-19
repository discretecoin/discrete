# walletd — Post-Quantum (PQ) JSON-RPC

`walletd` (the PaymentGate service) is the JSON-RPC wallet a service/exchange runs
against a Discrete node. Discrete is post-quantum from genesis, so the funds a
service holds are **PQ funds**, addressed by a **PQ address** and tracked as a
**PQ balance** that is kept entirely separate from the (unused) classical balance.

This document covers the PQ methods. They mirror what `simplewallet` shows for
the same seed.

## Running

```
discreted                                  # node
walletd --container-file w.wallet --container-password PW \
        --bind-port 8070 --rpc-password RPC
```

All examples below POST JSON-RPC 2.0 to `http://127.0.0.1:8070/json_rpc`.

## `getAddress`

Returns the wallet's PQ address (base58). This is the address payers send PQ
funds to; it is identical to `simplewallet`'s `address` for the same seed.

Request:

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getAddress", "params": {}
}'
```

Response:

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "address": "<base58 PQ address>",
    "enabled": true
  }
}
```

`enabled` is `false` (and `address` empty) for a tracking/view-only container,
which has no spend secret and therefore no PQ identity.

## `getBalance`

Returns the PQ available balance (atomic units) and the height the PQ scanner has
reached. Mirrors `simplewallet`'s `balance`.

Request:

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": {}
}'
```

Response:

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "availableBalance": 0,
    "scannedHeight": 12345,
    "enabled": true
  }
}
```

`availableBalance` is in atomic units (divide by 10^`CRYPTONOTE_DISPLAY_DECIMAL_POINT`
for whole coins). PQ and classical balances are never combined.

## `registerAccount` (free, anti-spam PoW)

Registers this wallet's PQ identity for a human-readable account number via a
`TX_FREE_REG` — no funds required, only an anti-spam proof-of-work that walletd
solves for you. Returns the registration transaction hash; poll
`getAccountStatus` until it confirms. Mirrors simplewallet's `register`.

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "registerAccount", "params": {}
}'
```

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "transactionHash": "<hex>" } }
```

## `registerAccountPaid`

**Not supported over walletd yet.** Paid registration must spend PQ funds + a fee
via a `TX_PQ` carrying the registration tag, and walletd has no PQ-send path yet.
The method is present for API completeness but returns a `function_not_supported`
error rather than building a transaction consensus would reject. Use the free
`registerAccount` instead.

## `getAccountStatus`

Polls the node's PQ account registry for this wallet's identity. Once the
registration confirms, `registered` becomes `true` and `accountNumber` holds the
human-readable H-I-C account number.

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getAccountStatus", "params": {}
}'
```

Before confirmation:

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "registered": false, "accountNumber": "", "blockHeight": 0, "txIndex": 0 } }
```

After confirmation:

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "registered": true, "accountNumber": "<H-I-C>", "blockHeight": 1234, "txIndex": 1 } }
```

Typical flow: call `registerAccount`, wait for the tx to be mined, then poll
`getAccountStatus` until `registered` is `true`. The account number is the same
one simplewallet's `account` shows for the same seed.

## Deposit-wallet modes

A walletd container is created in ONE of two deposit-wallet schemes, fixed at
creation and immutable thereafter:

| Flag | Spec | Keys | Use case | Per-deposit spend isolation |
|---|---|---|---|---|
| `--aggregated-multikey` (DEFAULT) | Spec 1 | one shared ML-KEM view key + one ML-DSA spend key **per deposit** | custodial web wallet | YES |
| `--single-key-index` | Spec 2 / H-I-T-C | one view + one spend key; deposits are an integer index `T` | exchange | NO (a spend-key compromise exposes every deposit) |

The flags are valid only with `--generate-container`, are mutually exclusive, and
the chosen scheme is persisted in the container:

```
walletd --container-file exchange.wallet --container-password PW -g --single-key-index
walletd --container-file webwallet.wallet --container-password PW -g            # aggregated-multikey (default)
```

### `getDepositScheme`

```
curl ... -d '{ "jsonrpc":"2.0","id":1,"method":"getDepositScheme","params":{} }'
# -> { "result": { "scheme": "single-key-index", "depositCount": 3 } }
```

### `createDepositAddress`

Returns a new deposit address and its index. In aggregated-multikey mode the
address is a base58 PQ address with its own spend key; in single-key-index mode it
is the **H-I-T-C** account number (the base account's `H-I` plus the new index `T`
and a Luhn check char). single-key-index requires the account to be **registered
first** (run `registerAccount` and wait for confirmation), because H-I-T-C
embeds the account's on-chain registration coordinates.

```
curl ... -d '{ "jsonrpc":"2.0","id":1,"method":"createDepositAddress","params":{} }'
# aggregated-multikey -> { "result": { "address": "<base58 PQ address>", "index": 3 } }
# single-key-index    -> { "result": { "address": "<H-I-T-C>", "index": 3 } }
```

### `listDepositAddresses`

```
curl ... -d '{ "jsonrpc":"2.0","id":1,"method":"listDepositAddresses","params":{} }'
# -> { "result": { "addresses": ["...","..."], "indices": [0,1] } }
```

Paying a deposit address works from any Discrete wallet: `simplewallet`/`greenwallet`
`transfer` accept a raw PQ address (aggregated-multikey deposit), an H-I-C account
number, or an H-I-T-C deposit subaddress (single-key-index), threading the deposit
index `T` into the payment automatically.

> Status: implemented end-to-end. Scheme selection/persistence, the deposit-address
> API, and the sender side (H-I-T-C resolution) were already in place; the walletd-side
> **scan attribution** (crediting an incoming deposit to the specific address/index it
> was paid to) is now wired into `PqWalletState`. The scanner derives the deposit keys
> for the container's scheme and, per output, routes via `scanPqOutputAggregate`
> (Spec 1) or a per-`T` scan (Spec 2), stamping each owned output with its
> `depositIndex` (persisted across reloads). `WalletGreen::pqDepositBalance(index)` /
> `pqDepositBalances()` expose the per-deposit balances for attribution. Live
> end-to-end confirmation (pay each address, observe the right credit) still depends
> on the 2-node testnet bring-up (Phase 6.2).

## Verifying parity with simplewallet

Open the same container with `simplewallet` and run `address` / `balance`.
The `getAddress.address` must equal the address `address` prints, and
`getBalance.availableBalance` must equal the `balance` amount (in atomic
units) once both have scanned to the same height. The PQ address is derived
deterministically from the container's primary spend secret, so it is stable
across reopen and identical between the two front-ends.
