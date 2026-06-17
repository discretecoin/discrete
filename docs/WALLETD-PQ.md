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

## `getPqAddress`

Returns the wallet's PQ address (base58). This is the address payers send PQ
funds to; it is identical to `simplewallet`'s `pq_address` for the same seed.

Request:

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getPqAddress", "params": {}
}'
```

Response:

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "pqAddress": "<base58 PQ address>",
    "pqEnabled": true
  }
}
```

`pqEnabled` is `false` (and `pqAddress` empty) for a tracking/view-only container,
which has no spend secret and therefore no PQ identity.

## `getPqBalance`

Returns the PQ available balance (atomic units) and the height the PQ scanner has
reached. Mirrors `simplewallet`'s `pq_balance`.

Request:

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getPqBalance", "params": {}
}'
```

Response:

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "availableBalance": 0,
    "scannedHeight": 12345,
    "pqEnabled": true
  }
}
```

`availableBalance` is in atomic units (divide by 10^`CRYPTONOTE_DISPLAY_DECIMAL_POINT`
for whole coins). PQ and classical balances are never combined.

## `registerPqAccount` (free, anti-spam PoW)

Registers this wallet's PQ identity for a human-readable account number via a
`TX_FREE_REG` — no funds required, only an anti-spam proof-of-work that walletd
solves for you. Returns the registration transaction hash; poll
`getPqAccountStatus` until it confirms. Mirrors simplewallet's `pq_register`.

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "registerPqAccount", "params": {}
}'
```

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "transactionHash": "<hex>" } }
```

## `registerPqAccountPaid`

**Not supported over walletd yet.** Paid registration must spend PQ funds + a fee
via a `TX_PQ` carrying the registration tag, and walletd has no PQ-send path yet.
The method is present for API completeness but returns a `function_not_supported`
error rather than building a transaction consensus would reject. Use the free
`registerPqAccount` instead.

## `getPqAccountStatus`

Polls the node's PQ account registry for this wallet's identity. Once the
registration confirms, `registered` becomes `true` and `accountNumber` holds the
human-readable H-I-C account number.

```
curl -s -u :RPC -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getPqAccountStatus", "params": {}
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

Typical flow: call `registerPqAccount`, wait for the tx to be mined, then poll
`getPqAccountStatus` until `registered` is `true`. The account number is the same
one simplewallet's `pq_account` shows for the same seed.

## Verifying parity with simplewallet

Open the same container with `simplewallet` and run `pq_address` / `pq_balance`.
The `getPqAddress.pqAddress` must equal the address `pq_address` prints, and
`getPqBalance.availableBalance` must equal the `pq_balance` amount (in atomic
units) once both have scanned to the same height. The PQ address is derived
deterministically from the container's primary spend secret, so it is stable
across reopen and identical between the two front-ends.
