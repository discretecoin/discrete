# Inspect a QRE evidence snapshot

`qre-verify` answers one question: at inspection time, which of the keys in
your local policy signed the same pair of block IDs for your challenge?
It reads local files and reports every authenticated statement group. It has
no daemon connection, chain database, wallet, witness signing key or rollback
command. A threshold result always carries `Branch: UNVALIDATED`.

## Build and run

Use the normal Core build prerequisites. From the source root with a configured
`build` directory:

```sh
cmake --build build --config Release --target QreVerify
build/src/qre-verify --policy policy.bin --context request.bin a.qre b.qre
```

The example path is for a single-configuration Linux build. Use the executable
from the corresponding configuration directory on a multi-configuration build.
The verifier is an explicit build target. No service needs to be running.
With `BUILD_TESTS=ON`, build `PqQreTests` and run
`ctest --test-dir build -C Release -R PqQre --output-on-failure`.

| Exit | Meaning |
| --- | --- |
| 0 | A group reached the policy threshold and no supplied signer double-voted. Inspect the block IDs and any minority observations. |
| 1 | Input, policy, context, time, bounds or signature validation failed. The snapshot has no valid result. |
| 2 | The authenticated observations fall short of the threshold for every single statement. |
| 3 | A pinned signer authenticated contradictory block IDs in this round. Its ID and the groups are displayed, even if one group reached quorum. |

## Prepare the two trusted inputs

Enroll dedicated raw ML-DSA-65 public keys out of band. Pin a policy before
collecting evidence. Select the fault assumption, threshold and collection
limits locally. For example, a four-key roster with one assumed faulty member
requires three distinct signers. The following Python fragment builds that
example from four previously enrolled public key files:

```python
import hashlib
import secrets
import struct
import time
from pathlib import Path

keys = sorted(Path(f"witness-{i}.pub").read_bytes() for i in range(1, 5))
if len(set(keys)) != 4 or any(len(key) != 1952 for key in keys):
    raise ValueError("expected four distinct raw ML-DSA-65 public keys")
policy = struct.pack("<5B5I", 1, 1, 4, 3, 1, 60, 60, 5, 64, 32) + b"".join(keys)
with open("policy.bin", "xb") as output:
    output.write(policy)
policy_id = hashlib.sha3_256(b"discrete-qre-policy-v1" + policy).digest()
```

The receiver opens a challenge before soliciting signatures. Supply your
network UUID in protocol byte order, genesis, locally verified tip and anchor,
policy generation, incident epoch, and the two heights from the same round.
This function uses raw bytes for hashes and creates a new nonce. Keep the
exact request you sent as the independent expected input to the verifier.

```python
def create_request(network_uuid, genesis, generation, epoch, tip_height, tip_id,
                   anchor_height, anchor_id, observation_height, reference_height):
    if len(network_uuid) != 16 or any(len(h) != 32 for h in (genesis, tip_id, anchor_id)):
        raise ValueError("invalid UUID or block ID width")
    start = int(time.time())
    return (b"\x01\x01" + network_uuid + genesis + policy_id
            + struct.pack("<QQ", generation, epoch) + secrets.token_bytes(32)
            + struct.pack("<I", tip_height) + tip_id
            + struct.pack("<I", anchor_height) + anchor_id
            + struct.pack("<IIQQ", observation_height, reference_height, start, start + 60))
```

Write the returned 226 bytes to a new `request.bin` and retain them before
collection. A request or a key roster supplied only by the evidence sender
cannot establish what your receiver requested or whom it trusts.
For the witness signing transcript, limits and byte layout, see the
[QRE v1 profile](QRE_RECOVERY_RFC.md#proposed-v1-byte-profile).

## Interpret repeated and partial submissions

Include **all known bundles for this challenge in the same invocation**. Within
one group, repeat signatures by a key count once. Different signed block IDs
are displayed separately. The program rejects the whole snapshot if any
supplied envelope is invalid. Preserve the input files if you need to review
why one inspection disagreed with another.

Limits apply per invocation: up to 64 bundles, 32 signatures in a bundle and
256 signature checks in total, subject to the local policy's lower budgets.
The system UTC clock must be inside the collection window including the start
and excluding the end. A signed time must be in the same window and within
the allowed future skew. A vote older than the allowed age contributes zero
fresh votes. It still identifies a double vote by the same key in that round.
A restarted process cannot establish clock
continuity, prior conflicts, consumption of a nonce or whether a witness
withheld evidence. An incident manager would have to maintain those records
before this evidence could contribute to any recovery plan.
