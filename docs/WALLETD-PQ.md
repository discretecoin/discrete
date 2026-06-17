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

## Verifying parity with simplewallet

Open the same container with `simplewallet` and run `pq_address` / `pq_balance`.
The `getPqAddress.pqAddress` must equal the address `pq_address` prints, and
`getPqBalance.availableBalance` must equal the `pq_balance` amount (in atomic
units) once both have scanned to the same height. The PQ address is derived
deterministically from the container's primary spend secret, so it is stable
across reopen and identical between the two front-ends.
