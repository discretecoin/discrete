# walletd exchange integration guide

This is the operator-facing guide for running `walletd` as an exchange or
custodial service wallet on Discrete.

Discrete is post-quantum only from genesis. There are no legacy ECC outputs, no
rings, and no bridge mode. `walletd` therefore exposes the PQ wallet as the main
JSON-RPC wallet surface: `getAddress`, `getBalance`, `createDepositAddress`,
`getTransactions`, and `sendTransaction` all operate on PQ funds.

For most exchanges, the recommended mode is `single-key-index`. It behaves like a
modern subaddress wallet: one registered base account, one hot-wallet key set,
and a unique deposit account number per customer/order.

## Quick recommendation

Use this unless you have a specific reason not to:

```bash
walletd --generate-container \
  --container-file exchange.wallet \
  --container-password "$WALLET_PASSWORD" \
  --single-key-index
```

Then run:

```bash
walletd --container-file exchange.wallet \
  --container-password "$WALLET_PASSWORD" \
  --bind-address 127.0.0.1 \
  --bind-port 9335 \
  --rpc-password "$RPC_PASSWORD" \
  --daemon-address 127.0.0.1 \
  --daemon-port 9331
```

After first start, call `registerAccount`, wait until `getAccountStatus` reports
`registered: true`, then use `createDepositAddress` for customer deposits.

## The two deposit modes

A wallet container is created in exactly one deposit mode. The mode is persisted
in the container and cannot be changed later.

| Mode | Flag | Address issued by `createDepositAddress` | Keys | Best fit |
|---|---|---|---|---|
| Aggregated multikey | `--aggregated-multikey` or default | Full PQ base address | One ML-KEM view key, one derived ML-DSA spend key per deposit | Custodial wallet that wants per-deposit spend-key isolation |
| Single key index | `--single-key-index` | H-I-T-C account number | One ML-KEM view key and one ML-DSA spend key for all deposits | Exchanges and services that want familiar subaddress-style deposits |

### Aggregated multikey

Aggregated multikey derives a separate spend public key for every deposit from
the master seed. A deposit address is a normal full PQ address containing the
shared view public key and that deposit's derived spend public key.

Properties:

- No account registration is required before issuing deposit addresses.
- A deposit output commits to that deposit's derived spend key.
- Spending a deposit output signs with that deposit's derived ML-DSA key.
- A leaked deposit spend key affects that deposit bucket, not every bucket.
- Restore requires the mnemonic plus the number of deposits to regenerate.

This mode is useful for custodial web wallets that want per-deposit spend-key
isolation. It is less familiar to exchanges because every customer receives a
long full address rather than a compact account-number subaddress.

### Single key index

Single key index uses one view key and one spend key for the whole wallet.
Deposits are distinguished by an integer deposit index `T`. Once the base wallet
identity is registered on chain, each deposit address is rendered as an H-I-T-C
account number:

- `H` = registration block height.
- `I` = transaction index inside that block.
- `T` = deposit subaddress index.
- `C` = check character.

Properties:

- The base account must be registered once before H-I-T-C deposit addresses can
  be created.
- No per-deposit registration is needed after that.
- Every deposit uses the same spend key; `T` is routing/accounting metadata.
- The address format is short and stable, closer to the "one account, many
  subaddresses" flow exchanges already use.

This is the recommended exchange mode.

## Indexes: important integration detail

There are two related indexes:

| Name | Meaning | First deposit |
|---|---|---|
| `depositIndex` / `T` | Deposit bucket inside the PQ wallet and the `T` in H-I-T-C | `0` |
| Numeric address selector | String accepted by RPC fields where an address is expected | `"1"` means first deposit |

`getAddresses` returns the primary address first:

```text
address selector "0" -> primary wallet address
address selector "1" -> depositIndex/T 0
address selector "2" -> depositIndex/T 1
```

`createDepositAddress` returns the deposit `index` (`T`), not the numeric address
selector. Store the returned `address` as the customer deposit address. If you
also store the returned `index`, remember that its numeric selector is
`index + 1`.

For example, if `createDepositAddress` returns:

```json
{ "address": "<H-I-T-C>", "index": 0 }
```

then all of these refer to the same first deposit bucket inside your own wallet:

- the returned `<H-I-T-C>` string
- the returned full deposit address in aggregated mode
- numeric selector `"1"`

Prefer storing and querying by the returned `address`; use numeric selectors only
for internal scripts.

## Starting safely

Run a fully synced `discreted` node first:

```bash
discreted --rpc-bind-address 127.0.0.1 --rpc-bind-port 9331
```

Run `walletd` on localhost or a private service network. Always set
`--rpc-password`; use `--rpc-user` as well if your deployment expects Basic Auth
with a non-empty username.

`walletd` uses separate daemon host and port options:

```text
--daemon-address 127.0.0.1
--daemon-port 9331
```

Do not pass `host:port` in `--daemon-address`.

## Bootstrap: single-key-index exchange mode

1. Generate the container:

```bash
walletd --generate-container \
  --container-file exchange.wallet \
  --container-password "$WALLET_PASSWORD" \
  --single-key-index
```

2. Start the service:

```bash
walletd --container-file exchange.wallet \
  --container-password "$WALLET_PASSWORD" \
  --bind-address 127.0.0.1 \
  --bind-port 9335 \
  --rpc-password "$RPC_PASSWORD" \
  --daemon-address 127.0.0.1 \
  --daemon-port 9331
```

3. Register the base account:

```bash
curl -s -u ":$RPC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"registerAccount","params":{}}' \
  http://127.0.0.1:9335/json_rpc
```

4. Poll until registered:

```bash
curl -s -u ":$RPC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getAccountStatus","params":{}}' \
  http://127.0.0.1:9335/json_rpc
```

Ready response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "registered": true,
    "accountNumber": "<H-I-C>",
    "blockHeight": 12345,
    "txIndex": 0
  }
}
```

5. Issue deposits:

```bash
curl -s -u ":$RPC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"createDepositAddress","params":{}}' \
  http://127.0.0.1:9335/json_rpc
```

Single-key-index response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "<H-I-T-C>",
    "index": 0
  }
}
```

Give the returned `address` to the customer. Store it in your exchange database
with the user/order id and the returned `index`.

## Bootstrap: aggregated-multikey mode

Generate the container:

```bash
walletd --generate-container \
  --container-file custody.wallet \
  --container-password "$WALLET_PASSWORD" \
  --aggregated-multikey
```

`--aggregated-multikey` is the default, so the flag is optional.

Start `walletd` normally and call `createDepositAddress`. Registration is not
required before issuing deposits in this mode.

Aggregated response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "<full PQ deposit address>",
    "index": 0
  }
}
```

## Core RPC calls

All examples use:

```text
POST http://127.0.0.1:9335/json_rpc
Content-Type: application/json
```

With curl, pass HTTP Basic Auth as `-u ":$RPC_PASSWORD"`.

### `getDepositScheme`

Use this at process startup to verify the hot wallet is the mode your exchange
expects.

```json
{ "jsonrpc": "2.0", "id": 1, "method": "getDepositScheme", "params": {} }
```

Response:

```json
{
  "result": {
    "scheme": "single-key-index",
    "depositCount": 128
  }
}
```

`depositCount` is the number of issued deposit buckets. The total restore address
count is `depositCount + 1` because the primary address is included in restore
counting.

### `getAddress`

Returns the primary wallet address.

```json
{ "jsonrpc": "2.0", "id": 1, "method": "getAddress", "params": {} }
```

Response:

```json
{
  "result": {
    "address": "<primary PQ address>",
    "enabled": true
  }
}
```

The primary address is selector `"0"` in RPC fields that accept address
selectors.

### `createDepositAddress`

Creates and persists the next deposit bucket.

```json
{ "jsonrpc": "2.0", "id": 1, "method": "createDepositAddress", "params": {} }
```

Store both fields. Publish `address`; use `index` for internal reconciliation.

### `listDepositAddresses`

Returns all issued deposits as parallel arrays:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "listDepositAddresses", "params": {} }
```

Response:

```json
{
  "result": {
    "addresses": ["<deposit 0>", "<deposit 1>"],
    "indices": [0, 1]
  }
}
```

For a single-key-index wallet that has not been registered yet, the list is empty
because H-I-T-C strings cannot be rendered before the base H-I-C exists.

### `getBalance`

Global balance:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": {} }
```

Per-address balance:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getBalance",
  "params": { "address": "<deposit address or selector>" }
}
```

Response:

```json
{
  "result": {
    "availableBalance": 100000000,
    "lockedAmount": 25000000,
    "scannedHeight": 120000,
    "enabled": true
  }
}
```

`availableBalance` is spendable now. `lockedAmount` includes unconfirmed,
reorg-returned, immature coinbase, and timelocked funds. Exchanges should credit
users according to their own confirmation policy, not merely because a deposit is
seen in `lockedAmount`.

### `getStatus`

Use this to monitor sync:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "getStatus", "params": {} }
```

Important fields:

- `blockCount`: wallet's local view.
- `knownBlockCount`: network height known to the node.
- `localDaemonBlockCount`: connected daemon block count.
- `peerCount`: daemon peer count.
- `minimalFee`: node fee floor.

For deposit crediting, also compare `getBalance.scannedHeight` with daemon height
so you know the wallet scanner has caught up.

### `getTransactions`

Fetch confirmed transaction details by block range:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getTransactions",
  "params": {
    "addresses": ["<deposit address>"],
    "firstBlockIndex": 120000,
    "blockCount": 100,
    "paymentId": ""
  }
}
```

You can pass:

- an empty `addresses` array to get all wallet transactions,
- a returned deposit address,
- an H-I-C or H-I-T-C account number,
- a numeric selector such as `"1"`.

For exchange systems, query by returned deposit address where possible. It is the
least ambiguous and survives any future selector changes.

Important response fields for crediting:

| Field | Meaning for exchange crediting |
|---|---|
| `items[].blockHash` | Block containing the returned transactions. Store it for reorg audits. |
| `transactionHash` | Unique transaction id. |
| `state` | Numeric wallet state. Credit only `0` (`SUCCEEDED`). |
| `blockIndex` | Block height. |
| `confirmations` | Current wallet height minus `blockIndex`; credit only when this reaches your policy threshold. |
| `amount` | Net effect on the whole wallet. For customer deposits, require this to be positive. |
| `fee` | Fee paid by this wallet for outgoing transactions; incoming deposits normally have `0`. |
| `isBase` | Coinbase flag. Customer deposits should be `false`. |
| `transfers[].address` | One of your wallet addresses touched by the transaction. |
| `transfers[].amount` | Net effect for that address. Credit only positive amounts for known deposit addresses. |
| `transfers[].type` | Numeric transfer type. `0` is normal (`USUAL`), `1` donation, `2` change. Credit only `0`. |

State values inherited from `IWallet`:

```text
0 = SUCCEEDED
1 = FAILED
2 = CANCELLED
3 = CREATED
4 = DELETED
```

Transfer type values:

```text
0 = USUAL
1 = DONATION
2 = CHANGE
```

Example confirmed deposit response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "items": [
      {
        "blockHash": "<block hash>",
        "transactions": [
          {
            "state": 0,
            "transactionHash": "<tx hash>",
            "blockIndex": 120031,
            "confirmations": 12,
            "timestamp": 1780000000,
            "isBase": false,
            "unlockHeight": 0,
            "amount": 25000000,
            "fee": 0,
            "transfers": [
              {
                "type": 0,
                "address": "<customer deposit address>",
                "amount": 25000000
              }
            ],
            "extra": "",
            "paymentId": ""
          }
        ]
      }
    ]
  }
}
```

### `getTransactionHashes`

Use this when your backend only needs hashes first:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getTransactionHashes",
  "params": {
    "addresses": ["<deposit address>"],
    "firstBlockIndex": 120000,
    "blockCount": 100,
    "paymentId": ""
  }
}
```

### `getUnconfirmedTransactionHashes`

Use this only for mempool awareness, not final credit:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getUnconfirmedTransactionHashes",
  "params": { "addresses": ["<deposit address>"] }
}
```

### `sendTransaction`

Withdraw or sweep funds:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "sendTransaction",
  "params": {
    "addresses": [],
    "transfers": [
      { "address": "<recipient address or account number>", "amount": 100000000 }
    ],
    "fee": 0,
    "changeAddress": "0",
    "unlockHeight": 0
  }
}
```

Field notes:

- `addresses` is the source-address filter. Empty means any spendable wallet
  output may be selected.
- `transfers[].address` accepts a full PQ address, H-I-C, or H-I-T-C.
- `fee: 0` means automatic fee selection.
- `unlockHeight` must be `0` for TX_PQ. Use per-output locks only where the
  wallet explicitly supports them.
- `changeAddress` must be one of your own wallet addresses/selectors.

If the wallet has multiple deposits and `addresses` is empty, set
`changeAddress`, usually `"0"` for the primary address. Without it, the RPC
returns `CHANGE_ADDRESS_REQUIRED` because change routing would be ambiguous.

To sweep only one deposit bucket, use that deposit as the source and route change
back to the primary:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "sendTransaction",
  "params": {
    "addresses": ["<deposit address>"],
    "transfers": [
      { "address": "<cold wallet address>", "amount": 50000000 }
    ],
    "fee": 0,
    "changeAddress": "0",
    "unlockHeight": 0
  }
}
```

## Exchange deposit workflow

### Address issuance

1. Keep `discreted` and `walletd` synced.
2. At startup, call `getDepositScheme` and verify it matches the configured
   exchange wallet mode.
3. For each customer or deposit request, call `createDepositAddress`.
4. Store: customer id, returned `address`, returned `index`, creation time,
   wallet scheme, and address status.
5. Show the returned `address` to the customer.

Do not use the primary address as a general customer deposit address. Issue one
deposit address per customer/account/invoice. This avoids payment IDs and makes
change outputs easy to distinguish from customer deposits.

### Polling and crediting deposits

Recommended state in your exchange database:

- `last_scanned_height`: highest height your deposit scanner has processed.
- `reorg_window`: number of recent blocks to rescan every cycle.
- `required_confirmations`: your crediting threshold.
- deposit table keyed by the returned `address`.
- credits table with a unique key on `(transaction_hash, deposit_address)`.

Polling loop:

1. Call `getStatus`.
2. Call global `getBalance` and read `scannedHeight`.
3. Let `daemon_tip_height = getStatus.localDaemonBlockCount - 1`.
4. Let `safe_tip = min(daemon_tip_height, getBalance.scannedHeight)`.
5. Let `from = max(0, last_scanned_height - reorg_window)`.
6. Query `getTransactions` in pages from `from` through `safe_tip`; each request
   uses `firstBlockIndex = page_start` and `blockCount = page_end - page_start + 1`.
7. For each transaction transfer, apply the credit filter below.
8. Advance `last_scanned_height` only after the full page is processed and stored.

Credit filter:

```text
transaction.state == 0                 # SUCCEEDED
transaction.isBase == false            # not coinbase
transaction.amount > 0                 # wallet net incoming
transaction.confirmations >= required_confirmations
transfer.type == 0                     # USUAL
transfer.amount > 0                    # incoming to that address
transfer.address is in your deposit table
```

When all conditions pass, create or update a credit:

```text
deposit_address  = transfer.address
transaction_hash = transaction.transactionHash
amount           = transfer.amount
block_height     = transaction.blockIndex
block_hash       = items[].blockHash
confirmations    = transaction.confirmations
timestamp        = transaction.timestamp
```

Use a unique key on `(transaction_hash, deposit_address)`. `walletd` reports one
transfer per owned wallet address touched by the transaction, so this key credits
a deposit once even if a sender created multiple outputs to that same deposit in
one transaction. Store `amount` too and alert if the same key ever reappears with
a different amount.

If a transaction is seen but below your confirmation threshold, store it as
`observed` or `pending`, not credited. Re-check it on later polling cycles until
it either reaches the threshold or disappears due to a reorg.

### Reorg handling

Always rescan a recent window, even after you have advanced
`last_scanned_height`. A simple policy:

```text
from = max(0, last_scanned_height - max(reorg_window, required_confirmations + 5))
```

For uncredited observed deposits, if the transaction no longer appears in
`getTransactions`, mark it orphaned or keep it pending until it reappears.

For credited deposits, choose an exchange finality policy. Many exchanges credit
only after enough confirmations that ordinary reorgs are outside policy. If you
also want automatic reversal, keep `(block_height, block_hash)` for every credit
and reconcile the recent finality window against fresh `getTransactions` results.

`getUnconfirmedTransactionHashes` can be shown in an internal dashboard, but it
is not enough to credit users because it returns hashes only and mempool entries
can disappear.

Unlike older CryptoNote exchange integrations, you do not need a shared exchange
address plus payment IDs. A unique deposit address per customer is the preferred
flow. The RPC still has `paymentId` fields for compatibility, but new exchange
integrations should treat deposit addresses as the attribution mechanism.

## Withdrawal workflow

1. Validate the user-provided destination with `validateAddress`.
2. Call `sendTransaction` with `fee: 0`, `unlockHeight: 0`, and an explicit
   `changeAddress`.
3. Store the returned `transactionHash`.
4. Poll `getTransaction` or `getTransactions` until the transaction is confirmed.
5. Mark the withdrawal complete only after your confirmation policy is met.

If you operate a hot/cold split, use `sendTransaction` to move funds from the hot
wallet to a cold PQ address. Keep cold keys offline; they are standard PQ wallet
keys and do not need a special exchange mode.

## Backup and restore

Back up all of these:

- wallet container file,
- container password or password escrow material,
- mnemonic seed,
- deposit scheme,
- current `depositCount`,
- last scanned/credited height from your exchange database.

The mnemonic restores the key material, but it does not encode how many deposit
addresses were issued. On seed restore, pass total address count:

```text
restore-address-count = depositCount + 1
```

Example: if `getDepositScheme` reports `depositCount: 100`, restore with
`--restore-address-count 101`.

```bash
walletd --generate-container \
  --container-file restored.wallet \
  --container-password "$WALLET_PASSWORD" \
  --mnemonic-seed "25 word seed ..." \
  --restore-address-count 101 \
  --single-key-index
```

Use the same deposit scheme as the original wallet. For aggregated multikey,
using too small a restore count can make deposit funds invisible until the
missing deposit indexes are regenerated and rescanned.

## Security notes

- Bind walletd to localhost or a private network.
- Use RPC authentication. Do not expose walletd directly to the public internet.
- Prefer a reverse proxy or private service mesh for TLS and access control.
- Treat `getMnemonicSeed` and `getSpendKeys` as highly sensitive administrative
  calls.
- In single-key-index mode, one spend key controls all deposits.
- In aggregated-multikey mode, the mnemonic still controls all deposits because
  it derives every deposit spend key.
- Keep hot wallet balances limited and sweep to cold storage under policy.

## Compatibility with common exchange workflows

Discrete walletd already matches the most common current exchange pattern:

- generate one unique deposit address per customer or invoice,
- poll transactions by address and block range,
- use confirmations for final credit,
- withdraw with one send RPC,
- restore from one mnemonic plus issued address count.

The closest mode to "subaddresses" is `single-key-index`; the H-I-T-C address is
the customer-facing subaddress.

Further streamlining ideas, in priority order:

1. Add `createDepositAddresses(count)` for batch issuance.
   Exchanges often pre-generate address pools. A batch RPC would reduce round
   trips and make address-pool warmup easier.

2. Add an exchange-shaped `getDeposits` alias.
   It could wrap `getTransactions` and return flat records:
   `address`, `depositIndex`, `transactionHash`, `amount`, `blockIndex`,
   `confirmations`, `state`, and `timestamp`.

3. Include `depositIndex` or numeric `addressIndex` in transaction transfer rows.
   Today transfers include `address` and `amount`. That is enough, but explicit
   indexes would reduce lookup code for services that store integer account ids.

4. Add idempotent address reservation with a caller-supplied label.
   Example: `createDepositAddress({ "label": "user-123" })` returns the existing
   address if the label was already used. Exchanges can do this in their own DB
   today, but a wallet-side option prevents duplicate issuance during retries.

5. Add compatibility aliases for common wallet RPC names.
   For example, alias `createDepositAddress` as `makeIntegratedAddress` or
   `createSubaddress` only if an exchange integrator specifically needs it. The
   canonical Discrete method should remain `createDepositAddress`.

6. Add an optional webhook/exporter layer outside walletd.
   Many exchanges prefer polling because it is deterministic after reorgs. A
   separate notifier can be useful, but the core wallet should keep polling APIs
   as the source of truth.

The most important compatibility choice is not to resurrect payment-ID based
deposits as the main path. Unique deposit addresses are simpler, safer, and match
modern exchange integrations.
