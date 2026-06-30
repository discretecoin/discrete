# walletd PQ Deposit Addresses

`walletd` creates one PQ master identity from a mnemonic seed. Deposit addresses
are deterministic children of that seed, so an exchange can back up one wallet
file, one password, one mnemonic, and the number of issued deposit addresses.

For the full exchange workflow, mode selection, and H-I-T-C guidance, see
`docs/WALLETD-EXCHANGE-GUIDE.md`.

## Creating a Container

```bash
walletd --generate-container --container-file exchange.wallet --container-password "password"
```

The primary address is index `0`. Each `createDepositAddress` call reserves the
next deposit index.

## Restoring Deposits

The seed does not store how many deposits were issued. When restoring from a
mnemonic, pass the total address count to regenerate: primary address plus all
deposit addresses that may have received funds.

```bash
walletd --generate-container \
  --container-file restored.wallet \
  --container-password "password" \
  --mnemonic-seed "25 word seed ..." \
  --restore-address-count 100
```

`--scan-height` can be combined with restore to avoid scanning earlier blocks.

## Deposit Schemes

`AggregatedMultikey` is the default. It uses one ML-KEM view key and a derived
ML-DSA spend key per deposit address. Spending a deposit output requires the
matching derived spend key.

`SingleKeyIndex` uses one spend key and routes deposits by account-number index.
It requires account registration before deposit subaddresses can be issued.

## Exchange Backup Checklist

Back up the container file, container password, mnemonic seed, deposit scheme,
and highest issued address count. The mnemonic alone cannot reveal how many
deposit addresses were created.
