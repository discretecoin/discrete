# Post-quantum P2P transport

Discrete can carry its existing Levin protocol through an encrypted TLS 1.3
stream. This protects message headers and contents on the network path. It does
not change block or transaction validation, wallet keys, amounts recorded on the
chain, the application protocol version, or the peer database format.

## Transport policy

| Setting | Outgoing connections | Incoming connections |
| --- | --- | --- |
| `off` | Existing plaintext Levin | Existing plaintext Levin |
| `mixed` | Try PQ TLS; one new plaintext connection may follow a failed attempt for an unpinned, unrestricted endpoint | PQ TLS or existing Levin |
| `pq-required` | PQ TLS for every configured or automatically discovered peer; no plaintext fallback | PQ TLS only |

The contribution retains `off` as the release default. `pq-required` is the target
security policy; activation needs compatible seeds and sufficient reachable peer
diversity. Turning it on before that migration can disconnect a node from old
peers. Changing the release default is a separate maintainer decision.

Mixed mode explicitly permits a weaker connection when an unknown peer cannot
complete TLS. It cannot distinguish an old peer from interference on the path.
Use `pq-required` or a local endpoint rule where encryption must be guaranteed.
Logs identify the mode, plaintext retries, and encrypted connections with or
without a pin. An advertised capability or legacy numeric peer ID never changes
local transport policy or establishes trust.

```sh
# Automatically encrypt connections to compatible discovered peers.
./discreted --p2p-transport pq-required

# Transitional compatibility with old peers.
./discreted --p2p-transport mixed

# Mixed network, with a strict encryption floor for this endpoint.
./discreted --p2p-transport mixed --p2p-pq-peer 203.0.113.10:18080
```

The example address is reserved for documentation; use the actual peer's numeric
IPv4 address and advertised P2P port. A local rule is bound to that exact endpoint
on every dial path, including seed discovery, priority/exclusive peers, persisted
peers and reverse ping. It does not automatically extend to another address or
port. Reverse ping for an encrypted incoming connection also requires encryption.

## Cryptographic profile

| Element | Required value |
| --- | --- |
| Protocol | TLS 1.3 |
| Key establishment | `X25519MLKEM768`; both components |
| Server CertificateVerify | `ML-DSA-65` |
| Server credential | Raw public key, not an X.509 trust chain |
| Record cipher | `TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256` |
| ALPN | `discrete-p2p/1/` followed by the network UUID's 32 lowercase hexadecimal digits in byte-iterator order |
| Session reuse | Disabled: no tickets, resumption, PSK-only path or 0-RTT |

OpenSSL implements the handshake, key derivation, AEAD records, counters and
nonces. Discrete enforces the profile and readiness before sending or accepting
Levin commands. There is no second TLS parser or custom cryptographic handshake.
Classical-only key establishment, another signature algorithm, missing/wrong
ALPN and another network are rejected. A TLS-selected socket never switches to
plaintext after an error.

Each connection establishes fresh hybrid exchange secrets. The server identity
is generated once per node context or loaded from a separate network key file.
Clients do not present a persistent identity. An unpinned connection verifies
proof of possession of the server's ML-DSA key and the TLS transcript, but does
not establish who controls that key. Its precise status is **encrypted,
unpinned**. The dedicated P2P verifier accepts only the specific absence of an
external raw-key trust anchor; it does not bypass other verification errors or
change HTTPS trust policy.

Hybrid key establishment is not hybrid authentication. Authentication uses
ML-DSA-65 alone. This profile does not claim a single whole-channel security level
from the parameter category of one primitive, or mutual peer authentication.

## Known services and independent keys

Generate a service key with the supplied utility, under the account that runs
the daemon. The destination must not already exist.

```sh
./p2p_transport_keygen mainnet seed.example /secure/discrete-p2p.key
./discreted --p2p-transport pq-required \
  --p2p-pq-key /secure/discrete-p2p.key --p2p-pq-name seed.example
```

For testnet, generate with `testnet` and start the daemon with `--testnet`. The
file header binds the key to the exact network and canonical service name.
Wallet seeds, spend keys and transaction KEM secrets are never inputs to this
utility or the transport. If no file is configured, the node uses a process
identity that changes at restart.

The utility prints a public **SHA256-SPKI** fingerprint. Obtain that fingerprint
and the service name through an independently trusted channel. A client pins all
three values explicitly:

```text
--p2p-pq-pin 203.0.113.10:18080,seed.example,<64-lowercase-hex-SHA256-SPKI>
```

Replace the placeholder with the actual digest. The name must be lowercase ASCII,
without a trailing dot. The client sends it in SNI; the server validates it against
its configured service. Pin mismatch, wrong name or key-load failure is fatal.
A pin prohibits plaintext retry even in mixed mode. There is no automatic first-use
trust, silent re-pinning or trust derived from DNS, gossip or a legacy peer ID.
SNI is visible on the network.

Key files are unencrypted private-key material protected by filesystem access
control. On POSIX, only an owner-only regular file belonging to the current user
is accepted; symbolic links and special files are rejected. On Windows the owner
must be the current user, with access limited to that user, SYSTEM and
Administrators; reparse points are rejected. Creation writes a protected temporary
file and publishes the final name without replacing an existing key. Keep its
parent directory protected and back it up as a network credential.

Rotate a pinned key by generating a new file and distributing its new fingerprint
through the trusted configuration channel. Existing clients do not adopt a
replacement key from the network. Plan that coordination before restarting the
service with the new identity.

## Resource and connection behavior

* Incoming establishment has 16 slots, with 4 per source IP. Outgoing transport
  establishment has 4 separate slots, with 4 per destination IP. Excess work is
  rejected rather than queued. Incoming slots remain held through the initial
  Levin handshake; outgoing slots cover TCP and TLS establishment.
* Prefix detection and TLS establishment have a five-second deadline and at most
  64 KiB of wire input and output per direction. Existing application-handshake
  and reverse-ping deadlines remain in force. DNS and public peer eligibility
  are not authenticated by these limits.
* TLS uses one stable connection owner on the existing cooperative dispatcher.
  Moving a handle does not move SSL state. One read and one write can progress
  concurrently. Cancellation closes the socket and drains completions before
  releasing their buffers. Closing is abortive and bounded; destructors do not
  wait for network input or a peer's `close_notify`. TLS truncation is an error,
  and cannot complete a partially received Levin command.
* Application writes use at most 16 KiB per TLS operation. Ciphertext staging is
  bounded independently of a Levin message; no full-message ciphertext copy is
  added. The 100,000,000-byte Levin receive limit remains unchanged.
* Existing plaintext queue accounting is retained. Its 64 MiB queue limit is not
  total per-peer RSS: a popped batch, replenished queue, current Levin
  serialization buffer and receive message can coexist. TLS staging is additional
  bounded overhead; this contribution does not present the old queue limit as
  a total-memory guarantee.
* Traffic keys are updated after 1 GiB sent or 2^20 records. Each direction closes
  before 2^22 records under one key. Post-handshake control accepts only KeyUpdate,
  with 32 credits per minute and a capped extra credit per 256 MiB of authenticated
  received application data. Fast transfers can update normally; idle control
  traffic remains bounded.

KeyUpdate is not recovery from a leaked traffic secret. Recovery requires a fresh
connection and hybrid exchange. There is no claim of scheduled post-compromise
recovery or new forced connection churn in this version. The existing connection
selection and diversity logic continues among peers eligible for the selected
transport policy. A strict policy intentionally makes plaintext-only peers
ineligible.

## Build and qualification

Use a currently patched OpenSSL release with the 3.5-or-newer APIs and the required
algorithms. OpenSSL 3.5.8 was used for Linux and Windows qualification. CMake enables the
implementation when `DISCRETE_ENABLE_PQ_P2P` is on and the OpenSSL version supports
those APIs. A provider without a required algorithm fails enabled-mode startup.
Older or explicitly disabled builds retain legacy operation and reject enabled
PQ modes; they do not silently choose classical TLS.

```sh
cmake -S . -B build -DBUILD_TESTS=ON -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build --target Daemon P2pTransportKeygen P2pTransportTests
ctest --test-dir build -R '^P2pTransportTests$' --output-on-failure
```

Use the matching configuration switch, such as `-C Release`, with a multi-config
build. Keep OpenSSL headers, import/static libraries and runtime DLLs consistent.
`P2pTransportBench` measures the actual TCP-backed stream, including handshake
wire bytes, payload verification and observed KeyUpdate counts. It is a loopback
capacity measurement, not an Internet synchronization forecast.

`P2pTransportNodeTests` runs real Core, LMDB and NodeServer instances over TCP with
a synthetic, funded PQ chain. Its process mode pairs an unchanged baseline with
the candidate through seed discovery, reverse ping, transaction/block relay and
persisted-peer reconnect. Run those fixtures only in an isolated network namespace
with the documentation-only test address assigned; do not use production data.
Run `bash tests/p2p_transport/run-isolated.sh` to prepare that namespace on Linux
when run with the necessary namespace privileges. Pass it the test executable
and arguments; it keeps both native fixtures and full nodes away from host or
WSL-forwarded listener ports.

`run-functional-matrix.sh` in the same directory pairs candidate and baseline
fixture executables in one isolated namespace. It generates a shared chain, then
checks that gray-peer housekeeping does not exceed the configured ordinary-outgoing
limit, then checks old/new, new/old and required/required processes, including
three-node seed discovery and persisted-peer reconnect. The dedicated `PQ P2P transport` workflow
builds the pinned OpenSSL dependency and runs these checks; its baseline remains
the explicit pre-transport commit until deliberately updated.

Before changing a release default, qualify maintained platform artifacts, a
representative long-running network, reachable seed/anchor diversity and low-power
hosts. Local tests are not an independent cryptographic audit.

## Protocol references

* [TLS 1.3, including the raw-public-key identity considerations in Appendix F.9](https://www.rfc-editor.org/rfc/rfc9846.html)
* [Hybrid ML-KEM TLS groups](https://www.rfc-editor.org/rfc/rfc10024.html)
* [OpenSSL raw public key support](https://docs.openssl.org/3.5/man3/SSL_get0_peer_rpk/)
* [ML-DSA in TLS: standards status](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)

The ML-DSA TLS specification was still an Internet-Draft when this contribution
was prepared. Its standards status and future codepoint compatibility must remain
part of dependency and protocol-version review.
