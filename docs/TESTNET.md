# Discrete — Local 2-Node Testnet Bring-Up

A reproducible local testnet: two peered `discreted` nodes, a mining wallet, a PQ
account registration, a PQ transfer between two wallets, and `walletd` in each
deposit mode. All commands assume the built binaries are on `PATH` (they live in
`build/src/Release/` on Windows). Discrete is **PQ from genesis** and mining is
**identity-bound** (the coinbase pays the block signer's PQ identity), so mining is
driven from the daemon with a wallet file.

Defaults: P2P `9330`, node RPC `9331`, walletd gate `9335`. On `--testnet`,
checkpoints and hardcoded seeds are ignored.

## 1. Build

```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=ON -DOQS_BUILD_ONLY_LIB=ON
cmake --build build --config Release
```

## 2. Two peered nodes

Node A (terminal 1):

```
discreted --testnet --data-dir ./tn/a \
          --p2p-bind-port 19330 --rpc-bind-port 19331 \
          --add-exclusive-node 127.0.0.1:19340
```

Node B (terminal 2):

```
discreted --testnet --data-dir ./tn/b \
          --p2p-bind-port 19340 --rpc-bind-port 19341 \
          --add-exclusive-node 127.0.0.1:19330
```

Check both reach the same height (each daemon console):

```
> height
```

The two nodes should track an identical top block. A node with no reachable peers
must keep running without crashing — confirm by starting Node A alone first.

## 3. Wallets

Alice (terminal 3) and Bob (terminal 4):

```
simplewallet --testnet --generate-new-wallet alice.wallet --password pw --daemon-address 127.0.0.1:19331
simplewallet --testnet --generate-new-wallet bob.wallet   --password pw --daemon-address 127.0.0.1:19341
```

In each wallet, note the PQ address (all commands are PQ by default):

```
[wallet]> address
```

`greenwallet` also supports testnet; use `greenwallet --testnet --wallet-file
<file> --password pw --remote-daemon http://127.0.0.1:19331`.

## 4. Mine to Alice's identity

In Node A's console, mine to Alice's wallet (the coinbase is bound to her PQ
identity; mining reads her spend secret from the wallet file):

```
> start_mining alice.wallet 1
```

Provide the wallet password out-of-band when prompted (or via
`--mining-password-file`). Let it mine past the coinbase maturity window, then:

```
> stop_mining
```

In Alice's wallet, confirm the balance appears once the coinbase matures:

```
[wallet]> balance
```

## 5. Register a PQ account number (Alice)

Free (anti-spam PoW, no fee):

```
[alice]> register
```

Wait for a block, then:

```
[alice]> account
```

This prints Alice's H-I-C account number. (`register_paid` instead spends a fee if
Alice already has funds.)

## 6. Transfer Alice → Bob

From Bob, get his address (`address`), then from Alice:

```
[alice]> transfer <bob_pq_address_or_account_number> 10
```

Wait for a block; confirm Bob's `balance` rises and Alice's drops by amount + fee.
A second `transfer` re-spending the same funds must fail (no double-spend).

## 7. walletd in both deposit modes

`walletd`'s `--daemon-address` takes the host ONLY; the port is a separate
`--daemon-port` (unlike `simplewallet`, which accepts `host:port`). `-g`
*generates the container and exits* — run it once to create, then again WITHOUT
`-g` to serve.

Aggregated-multikey (Spec 1, default — custodial web wallet):

```
# create (exits):
walletd --testnet -g --container-file web.wallet --container-password pw \
        --aggregated-multikey \
        --daemon-address 127.0.0.1 --daemon-port 19331
# serve:
walletd --testnet --container-file web.wallet --container-password pw \
        --bind-address 127.0.0.1 --bind-port 19335 --rpc-password RPC \
        --daemon-address 127.0.0.1 --daemon-port 19331
```

Single-key-index (Spec 2 — exchange, H-I-T-C deposits):

```
walletd --testnet -g --container-file ex.wallet --container-password pw \
        --single-key-index \
        --daemon-address 127.0.0.1 --daemon-port 19341
walletd --testnet --container-file ex.wallet --container-password pw \
        --bind-address 127.0.0.1 --bind-port 19336 --rpc-password RPC \
        --daemon-address 127.0.0.1 --daemon-port 19341
```

The examples enable HTTP Basic authentication with an empty username and the
`--rpc-password`, so use `curl -u :RPC ...`. Authentication is optional for
loopback-only testing: omit both `--rpc-user` and `--rpc-password`, and omit
curl's `-u` option, to disable it. PQ is the default: `getAddress`/`getBalance`
return the PQ address/balance; `getStatus`, `registerAccount`,
`createDepositAddress`, and `sendTransaction` work as expected.

Then, against each (see the public [walletd RPC
guide](https://docs.discrete.cash/#/wallets/walletd-rpc) for full request bodies):
`getAddress`, `getBalance`, `registerAccount` (single-key-index requires this before
`createDepositAddress`), `createDepositAddress` ×3, fund each from Alice's wallet, and
confirm `getBalance` / per-deposit attribution credits the right deposit. `sendTransaction`
moves PQ funds back out.

## Expected results checklist

- [ ] Both nodes run and converge to the same height; an isolated node stays up.
- [ ] Mined coinbase becomes spendable in Alice's wallet after maturity.
- [ ] `register` → `account` yields a stable H-I-C number once confirmed.
- [ ] `transfer` debits sender (amount + fee) and credits recipient; double-spend rejected.
- [ ] Both walletd modes start; deposit addresses are created and attributed correctly;
      the scheme is immutable across a container reopen.

> Note: full automation of this checklist is the open multi-process E2E gate
> (completion plan Phase 6.1). The single-process chain lifecycle (mine PQ coinbase →
> spend → mine into a block → double-spend rejected at mempool and block level →
> maturity → free-reg cap → emission → miner binding) is covered by `PqChainTests`.
