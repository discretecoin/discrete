# Solana escrow with an explicit immutable deployment profile

This package turns the frozen laboratory escrow into a build for a selected, normally deployable program address and one fixed legacy SPL mint. The runtime escrow rules are the donor's rules. There is no generic token-program parameter, Token-2022 support, admin withdrawal, redirect instruction or variable fee. Public amounts and the cross-chain hashlock remain visible.

`src/lib.rs` retains the ten account positions, 49/33/1-byte instruction encodings, 192-byte state, PDA seeds, error ordering, `TransferChecked` with six decimals, fixed claim/refund token-account addresses, and spent tombstones. Claims remain possible after the refund deadline until a refund consumes the escrow. Either branch consumes it once. The depositor signs funding; a relayer may submit a claim or refund to the previously fixed destination. Frozen token accounts reject transfer and preserve escrow state; issuer thaw permits a later retry. Immutability of this program cannot remove the issuer's mint/freeze authority.

## Build one profile

Use Python 3.11+ and the reviewed [Anza platform-tools 1.57](https://github.com/anza-xyz/platform-tools/releases/tag/v1.57). `Cargo.lock` and `solana-program =3.0.0` are pinned. Provide a writable, already populated Cargo cache; `--offline --locked` forbids silently downloading or resolving another dependency version. On a fresh machine, populate this separate cache from the locked crate manifest before an offline build. Do not point it at immutable historical evidence.

Generate a **new** deployment keypair with the normal Solana CLI. Keep it outside the repository and outside the build/evidence directory. Only its public address is a build input:

```sh
solana-keygen new --outfile /private/path/escrow-program-keypair.json
solana-keygen pubkey /private/path/escrow-program-keypair.json
python build.py --network devnet-usdc --program-id <PUBLIC_PROGRAM_ID> --genesis-hash <FULL_EXPECTED_GENESIS_HASH> --tools-root <PLATFORM_TOOLS> --cargo-home <WRITABLE_CARGO_CACHE> --output <NEW_BUILD_DIRECTORY>
```

`--network mainnet-usdc` fixes the mint to `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`; `devnet-usdc` fixes it to `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`. These addresses were checked against [Circle's contract registry](https://developers.circle.com/stablecoins/usdc-contract-addresses) on 2026-09-10. `local-synthetic` instead requires `--local-mint <PUBLIC_MINT>` and rejects both official mint addresses. The network argument selects the **mint preset**; the separately pinned full genesis hash selects the chain. Obtain that full hash through the maintainers' trusted chain configuration and independently check it before deployment. A truncated CAIP-2 chain identifier is not a full genesis hash. A profile built for a local fork is not a public-network qualification.

The build wrapper copies source into the new output directory, generates only the immutable `PROGRAM_ID` and `MINT_ID` constants there, and builds an SBPFv3 ELF. The unconfigured repository's `src/profile.rs` fails compilation intentionally: there is no deployable default or laboratory key hidden in a production build. The output contains `solana_escrow.so`, `build-manifest.json`, compiled source, and a build log. The manifest records selected public identities, exact source/lock/compiler hashes, ELF length and SHA-256. It is public; private keys are neither read nor copied. Same-host reproduction and independent builds must compare the whole ELF; this package does not claim path-independent or cross-host reproduction from a single build.

## Deploy, inspect, then freeze

These are operator commands, not automatically executed by this package. Use the same public program address that was compiled into the ELF, a dedicated deployment authority and an explicit RPC URL. This is normal loader deployment with creation of the program account from its keypair; it requires no genesis-preloaded account or known secret for the old laboratory `[9; 32]` address. The flow follows the [Solana deployment documentation](https://solana.com/docs/programs/deploying).

```sh
solana --url <RPC_URL> genesis-hash
solana --url <RPC_URL> program deploy <BUILD_DIRECTORY>/solana_escrow.so --program-id /private/path/escrow-program-keypair.json --upgrade-authority /private/path/authority-keypair.json
python verify_deployment.py --manifest <BUILD_DIRECTORY>/build-manifest.json --rpc-url <RPC_URL> --expected-upgrade-authority <PUBLIC_AUTHORITY>
```

Before funding any swap, verify the artifact, run the qualification for this exact deployment, and remove its upgrade authority. Removing authority is irreversible; fixes then require a new program/profile and migration of **new** swaps. Existing swaps stay bound to their original immutable deployment:

```sh
solana --url <RPC_URL> program set-upgrade-authority <PUBLIC_PROGRAM_ID> --upgrade-authority /private/path/authority-keypair.json --final
python verify_deployment.py --manifest <BUILD_DIRECTORY>/build-manifest.json --rpc-url <RPC_URL>
```

Repeat the default immutable check using independent trusted RPC endpoints. `--expected-upgrade-authority` is a pre-freeze inspection mode and must never qualify a deposit. No mainnet deployment, program address, funding budget or activation is selected by this README.

`profile.verify_rpc(manifest, rpc)` is the importable client interface. The callback returns a JSON-RPC `result` or raises. It checks the exact genesis hash, then obtains Program, linked ProgramData and selected mint together at `finalized` with a minimum context slot. It requires the upgradeable loader's correct owners/tags/executable flags, immutable authority by default, the exact ELF hash and length with zero allocation padding, and initialized six-decimal legacy SPL mint metadata. It reports the mint's freeze authority separately. The manifest must come through the trusted release channel; an attacker-supplied manifest cannot attest itself. A valid RPC observation is still not a cryptographic proof of finality or an assessment of RPC independence.

## Verify the package

```sh
python -m unittest discover -s tests -p test_profile.py -v
python -m pip install solders==0.29.0
XDS_SOLANA_BUILD=<BUILD_DIRECTORY> python -m unittest discover -s tests -p test_vm.py -v
```

On PowerShell set `$env:XDS_SOLANA_BUILD` before the last command. The 16 VM tests reuse the frozen donor's 13 actual SPL CPI tests and add rejection of the selected ELF at another program address, destination freeze/thaw for both branches, and exact principal payment despite unsolicited surplus. They cover fixed destinations, wrong keys, early refund and exact deadline, both spend orders, duplicate funding/spend, wrong secret, delegated/close-authority vaults, compute-exhaustion rollback, stale-blockhash retry, token freeze and thaw, and destination overflow. Mint accounts in LiteSVM are synthetic, including tests placed at a Circle-listed address. These tests do not prove real Circle USDC behavior, normal deployment on a live validator, public-network finality, or full wallet recovery. The profile/verifier unit tests additionally cover manifest tampering, authority checks, byte-exact deployment verification, wrong chain, stale context and changed ProgramData linkage.

State/vault accounts retain the donor's creation protocol: create a fresh 192-byte state account owned by this program and a 165-byte legacy SPL vault owned by the derived PDA; initialize the vault for the profile mint with no delegate/close authority. The state keypair and depositor must sign funding. Funding binds the existing, distinct claim/refund token-account addresses permanently. Owners must retain those destination accounts until settlement: closing or freezing a destination blocks its branch. The escrow keeps state/vault rent and any unsolicited surplus; this package adds no close/sweep instruction because that would change the reviewed state machine.
