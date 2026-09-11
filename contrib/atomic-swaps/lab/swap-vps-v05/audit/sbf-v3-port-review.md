# Rust SBPFv3 escrow port — independent bounded review

Reviewed 2026-09-08 UTC by consensus_review. The exact candidate below is accepted for the parent's separately authorized synthetic real-RPC qualification. No concrete port correctness defect remained after this review. This is a source/ABI/artifact review with readback of the author's local build and VM evidence, not a claim of successful live deployment, universal equivalence or production readiness.

## Exact baseline and candidate

Paths below are relative to `evidence/` unless prefixed with `sbf-v3/`, which is under `swap-vps-v05/`.

| Artifact | SHA256 |
|---|---|
| Frozen `swap-localnet-v04/solana_escrow.c` | `c64e6f25aa506565d553c5959c5fc3a7c27895c7b22ecffc643091d8c9bf2123` |
| Frozen `swap-localnet-v04/solana_profile.h` | `cc86c7703a1e7edf9b2ec7c1a8bbcaa60788f5f375b9292cef8207eb56666551` |
| Frozen C ELF, 9248 bytes | `91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89` |
| `sbf-v3/src/lib.rs` | `6fa662506bd667f6e510aaa3ea9aea74edaadeebdc829bd82bcfc05325b60eea` |
| `sbf-v3/Cargo.toml` | `95fbea4c3925ab8043baa328dd2bdc0509883841474ee8c811af10356e02e965` |
| `sbf-v3/Cargo.lock` | `ecb88b8469a190be6c5587f4762eaef619f4e8bdaaa45171821f6ea4c41f2102` |
| Rust ELF, 32912 bytes | `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7` |
| Unchanged original VM test copy | `48187e48a95a1a94f92ba99e4ea6e3755289e0592c8d94d874c4d4d861892c54` |
| `sbf-v3/test_differential.py` | `35bb09a6fec88e07ec0a71abeb0cef62bbfb08d7f9a48fab3f4e78066ba87e2b` |

The five fixed profile byte arrays were parsed and compared independently: program, mint, SPL Token, Clock and Sysvar owner IDs are identical to C. The native XDS fee/consensus code and all frozen originals were outside the modification scope.

Final author freeze: `sbf-v3/MANIFEST.json` SHA256 `05c72366d4c87c856c7af6839252523c17ea3d2646f38556d67789bcef877b46`. Every listed file was independently read back: 32/32 size and hash matches. Source and ELF identities above remained unchanged. The bound `source-dependency-audit.json` additionally records the author's comparison of 3872 unpacked dependency-source files against all 158 locked archives, zero failures, and identities of 57 toolchain/target-library files. This extends identity evidence; it is not an exhaustive dependency security review.

## Source equivalence

| Contract | Frozen C lines | Rust lines | Assessment |
|---|---:|---:|---|
| Exactly ten runtime accounts before deserialization; program/data and alias gates | 30–36 | 46–59, 77–82 | Same Custom 4097/4098/4099 ordering. Only the leading count is read manually; official SDK deserialization and heap/panic handlers remain. |
| State, token program/mint, Clock, PDA and vault eligibility | 37–48 | 83–100 | Same checks, order, lengths, fixed IDs and Custom 4100–4104. No new mint executable or account eligibility restriction. |
| Funding wire and signatures/source/destinations | 50–56 | 105–115 | Same 49 bytes, source authority/delegate rule, zero state, nonzero amount, future slot and empty-vault/sufficient-source conditions; Custom 4105/4106. |
| TransferChecked and overflow | 19–27 | 61–74 | Same opcode 12, LE u64 amount, decimals 6, four metas, signer selection, full ten account infos and Custom 4114 before CPI. |
| State initialization after successful transfer | 57–61 | 116–122 | Same 192-byte layout; magic/status/bump/reserved bytes, amount/deadline/hash and four committed keys match. No state mutation precedes CPI. |
| Settlement operation and funded-state binding | 64–67 | 125–128 | Same Custom 4107/4108, active status, bump/reserved bytes and all four keys. |
| Claim hash/length and refund deadline | 68–72 | 129–132 | Same 33-byte claim / 1-byte refund and Custom 4109–4111. Claim remains permitted after the refund deadline; refund uses `slot >= deadline`. |
| Destination/amount/PDA transfer and tombstone | 73–78 | 133–140 | Same Custom 4112/4113, amount checks, three seeds and transfer before final status 2/3. No redirect, admin, close or reinitialization path added. |

All account-data borrows end before `invoke_signed`: validation helpers return plain values, explicit mint/source/vault borrows end at their block boundaries, state is copied into a local 192-byte array, and destination amount's temporary borrow ends before CPI. Mutable state is reacquired only after successful CPI. The checked SDK CPI wrapper therefore does not encounter a live program borrow of the writable token accounts. The exact resolved CPI 3.1.0 implementation checks RefCells and forwards syscall results via `ProgramError`; the port does not mask SPL failures.

The split funding condition preserves short-circuit order and returns the same custom code. Every index/slice is preceded by its applicable account/data length check. `u64::MAX - amount` cannot itself overflow for a u64 amount, and the port adds no amount/time arithmetic absent from C. Destination token ownership/delegate/close fields and source close authority remain permitted exactly as in C; these are preserved semantics, not new production eligibility decisions.

## SDK and runtime ABI

The retained lock contains 159 package entries: the root package and 158 registry dependencies. Every cached `.crate` archive was independently hashed against its lock checksum: 158 matches, zero missing and zero mismatches. Direct `solana-program` is exactly 3.0.0; resolved entrypoint/account-info are 3.1.1 and CPI/SHA256 hasher are 3.1.0. The resolved syscall macros support `target_feature = "static-syscalls"`.

The C code checks the SHA256 syscall return explicitly; Rust `hashv` does not expose that return. This apparent difference was traced to the exact Agave implementation rather than assumed harmless. At commit `c9c6f3287e26f24e3476e13e751aebe710191e89`, `syscalls/src/lib.rs` lines 2540–2599 return only `Ok(0)` after writing the entire digest. Slice, memory and compute failures return VM errors, not a nonzero successful syscall return. Thus the chosen SDK API preserves this runtime behavior. The parent fetched and verified the official Git blob `2c81cc0102cebe1a1d5b32f84894bfe296930f0d`; numbered excerpts are retained in `pinned-agave-hash-syscall-source.log` (SHA256 `8d93774d8ad933e59c492db618a7f544a6cbf803e3bd438a40a543274e397298`). The official tag/commit identity readback is in `verify-agave-tag-source-identity.log` (`2dbbb9cadfa661d7dc0d85fada145d23a449d2ac5180d862a38835ca0d1ea3c6`).

Independent parsing of the actual candidate ELF confirms ELF64 little endian, EM_BPF 247, flags 3, entrypoint `0x1000016c0`, and zero named undefined symbols. It is a supported Rust `sbpfv3-solana-solana` target build, not a modified v0 ELF header. Official platform-tools Cargo/rustc compiled the locked graph offline; Rust reports 1.95.0-dev, commit `ae660768afd467d131776918a1627e18920b230c`, LLVM 22.1.2. The `cargo-build-sbf` wrapper was not used, and the documentation now distinguishes it from the actual direct Cargo command.

## Executed evidence read back

The original test file is byte-identical to V04 and resolves its local `solana_escrow.so` to the new candidate. `vm-original13.log` (`c79dbd970c257a48bf8955bcdf970b9119be76c6eb64c137fa277d0388b1d420`) reports 13/13 PASS, including real SPL CPI, exact refund-slot boundary, claim after deadline, both spend orders, issuer freeze/thaw, duplicate rejection, compute exhaustion and two-instruction rollback. No assertion or compute threshold was relaxed for the port.

The added differential suite is hash-gated to both exact C and Rust artifacts and creates 24 pairs of deterministic fresh fixtures. Four methods pass in `vm-differential-dev01.log` (`460122624b5a958b519714fd60d4df23fdae86185ba13deff6c91f141acca99e`). They compare full state/token/mint/payer/relayer account records, expected 192-byte state, all 18 custom codes across 19 rows, deadline/terminal ordering and subsequent ordinary transfer. Explicit in-process VM mutations test otherwise inconsistent inputs and C-permitted token fields; they do not claim those states are reachable through ordinary on-chain actions.

The fresh `target-repro-02` build produces the same complete ELF hash. Its receipt (`e9a1f1f5125ea2b6066f8fbf9c9106e7ac92fd76a6ba353a6736134406c5ac90`) and successful build log (`7e9f5ba195394dbfa09d449de608ec58fa088ef087f837b2cba1e8341a1104d5`) were read; the rebuilt ELF hash was independently recomputed. An earlier fresh build, `target-repro-01`, produced `e22474092bbc8426b830799ec42735d1ca0b47a05f80e4221302111452d34642` with different path spelling and remains preserved. The author traced embedded panic-path differences; exact original path spelling restores identity. This supports same-host/same-path/toolchain reproduction only, not location-independent or cross-platform reproducibility.

The reviewer did not run builds, VM tests, RPC, nodes or remote commands. Author/parent execution evidence is distinguished from the reviewer's independent file, hash, ELF and source checks.

## Remaining scope

The exact new hash must pass actual Agave deployment/finalization and on-chain immutable ProgramData readback, then all six standalone RPC and both paired XDS/Solana cases with new intents and receipts. Historical C/VM or prior native results do not qualify this ELF. Current mint/keys remain synthetic and are not Circle USDC; no real funds, public node, mainnet activation or production keys are involved. Compute usage differs by implementation and must be assessed on the real runtime. Combined VPS resource limits, process-tree cleanup, crash/expiry recovery, formal whole-input equivalence and cross-host reproducibility remain distinct gates. Stage and outer-wrapper reviews are recorded separately; the parent coordinates project status documentation during the active qualification.
