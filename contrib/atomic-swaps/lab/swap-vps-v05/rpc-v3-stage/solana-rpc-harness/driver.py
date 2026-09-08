"""Bounded synthetic-only Solana RPC qualification; never contacts a non-literal loopback host."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time
from urllib.parse import urlsplit
import uuid

from solders.hash import Hash
from solders.instruction import AccountMeta as Meta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams, TransferParams, create_account, transfer
from solders.sysvar import CLOCK
from solders.transaction import Transaction

PID = Pubkey.from_bytes(bytes([9]) * 32)
MINT = Pubkey.from_string("EdmxWPmx2WH6WgFfTdu9xfkYf3k1g5wD1zccTVySEEh1")
TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
LEGACY_LOADERS = {"BPFLoader1111111111111111111111111111111111", "BPFLoader2111111111111111111111111111111111"}
SBF_SHA = "30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7"
SBF_SIZE = 32912
AMOUNT = 1_234_567
SUPPLY = 10_000_000
RELAYER_SOL = 50_000_000
SECRET = bytes([77]) * 32  # Public fixture constant from V04; never a production secret.
MAX_RESPONSE = 4 * 1024 * 1024


class GateError(RuntimeError):
    pass


class RpcError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(f"RPC error code {code}; receipt, not submission response, determines outcome")


def check(ok, message):
    if not ok:
        raise GateError(message)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def u64(value):
    return struct.pack("<Q", value)


def endpoint_port(endpoint):
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise GateError("invalid endpoint") from None
    check(parsed.scheme == "http" and parsed.hostname == "127.0.0.1", "endpoint must be literal http://127.0.0.1:PORT")
    check(port is not None and 1 <= port <= 65535, "explicit endpoint port required")
    check(endpoint in (f"http://127.0.0.1:{port}", f"http://127.0.0.1:{port}/"), "endpoint must use exact canonical literal spelling")
    check(parsed.netloc == f"127.0.0.1:{port}" and parsed.path in ("", "/") and not parsed.query and not parsed.fragment,
          "credentials, aliases, query strings and non-root paths are forbidden")
    return port


class Rpc:
    def __init__(self, endpoint, genesis, commitment="confirmed", timeout=5):
        self.port = endpoint_port(endpoint)  # Before any socket construction.
        Hash.from_string(genesis)
        check(commitment in ("confirmed", "finalized"), "processed commitment is forbidden")
        self.genesis, self.commitment, self.timeout, self.counter = genesis, commitment, timeout, 0

    def call(self, method, params=None):
        self.counter += 1
        request_id = self.counter
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or []})
        # http.client neither uses proxy environment variables nor follows redirects.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            conn.request("POST", "/", body, {"Content-Type": "application/json", "Connection": "close"})
            response = conn.getresponse()
            check(response.status == 200, "RPC HTTP status must be 200; redirects are never followed")
            raw = response.read(MAX_RESPONSE + 1)
            check(len(raw) <= MAX_RESPONSE, "RPC response exceeds bound")
            value = json.loads(raw)
        finally:
            conn.close()
        check(value.get("id") == request_id and value.get("jsonrpc") == "2.0", "RPC envelope mismatch")
        if "error" in value:
            raise RpcError(value["error"].get("code"))
        check("result" in value, "RPC result absent")
        return value["result"]

    def guard(self):
        check(self.call("getGenesisHash") == self.genesis, "genesis changed or does not match the explicit expected genesis")

    def config(self, min_slot=None):
        result = {"commitment": self.commitment}
        if min_slot is not None:
            result["minContextSlot"] = min_slot
        return result

    def account(self, pubkey, min_slot=None):
        return self.call("getAccountInfo", [str(pubkey), {**self.config(min_slot), "encoding": "base64"}])["value"]

    def slot(self):
        return self.call("getSlot", [self.config()])


def account_bytes(account):
    check(account is not None, "required account absent")
    data = account["data"]
    check(isinstance(data, list) and len(data) == 2 and data[1] == "base64", "unexpected account encoding")
    return unb64(data[0])


def verify_program(rpc):
    rpc.guard()
    version = rpc.call("getVersion")
    check(version.get("solana-core") == "4.2.2", "Agave version must be exactly 4.2.2")
    program = rpc.account(PID)
    data = account_bytes(program)
    check(program["executable"], "fixed program is not executable")
    owner = program["owner"]
    if owner == LOADER:
        check(len(data) == 36 and struct.unpack_from("<I", data)[0] == 2, "unexpected upgradeable Program layout")
        programdata_key = Pubkey.from_bytes(data[4:36])
        programdata = rpc.account(programdata_key)
        raw = account_bytes(programdata)
        check(programdata["owner"] == LOADER and not programdata["executable"], "unexpected ProgramData owner")
        check(len(raw) >= 45 and struct.unpack_from("<I", raw)[0] == 3 and raw[12] == 0,
              "program must be immutable: ProgramData upgrade authority must be None")
        data = raw[45:]
    else:
        check(owner in LEGACY_LOADERS, "unsupported program loader; no relaxed fallback")
    check(len(data) >= SBF_SIZE and sha(data[:SBF_SIZE]) == SBF_SHA and not any(data[SBF_SIZE:]),
          "on-chain SBF payload/hash mismatch")
    token = rpc.account(TOKEN)
    check(token is not None and token["executable"], "SPL Token executable absent")
    rpc.guard()
    return {"program": str(PID), "program_owner": owner, "payload_bytes": SBF_SIZE, "payload_sha256": SBF_SHA,
            "zero_padding_bytes": len(data) - SBF_SIZE, "version": version}


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temp.exists():
            temp.unlink()


def read_private_json(path):
    path = Path(path)
    check(not path.is_symlink(), "private JSON path must not be a symlink")
    if os.name == "posix":
        info = path.stat()
        check(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077, "private JSON ownership/mode mismatch")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_payer(path):
    try:
        values = read_private_json(path)
        check(isinstance(values, list) and len(values) == 64 and all(type(x) is int and 0 <= x <= 255 for x in values),
              "payer key encoding invalid")
        return Keypair.from_bytes(bytes(values))
    except Exception:
        raise GateError("payer key could not be loaded safely; its contents were not logged") from None


class Store:
    def __init__(self, root):
        self.root = Path(root)
        check(not self.root.is_symlink(), "run directory must not be a symlink")
        self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
        if os.name == "posix":
            info = self.root.stat()
            check(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077, "run directory must be owned and mode 0700")
        self.lock = None

    def __enter__(self):
        import fcntl  # Linux harness; no lockfile deletion, PID guessing or stale-lock bypass.
        self.lock = open(self.root / ".lock", "a+b")
        os.chmod(self.root / ".lock", 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return self

    def __exit__(self, *_):
        self.lock.close()

    def path(self, label):
        check(re.fullmatch(r"[0-9]{2}-[a-z0-9-]+", label) is not None, "invalid intent label")
        return self.root / (label + ".json")

    def save(self, label, value):
        atomic_json(self.path(label), value)

    def read(self, label):
        return read_private_json(self.path(label))


def describe(ixs, payer, debit, expected_error):
    return {"payer": str(payer), "lamports_outside_fee": debit, "expected_error": expected_error,
            "instructions": [{"program": str(ix.program_id), "data": b64(bytes(ix.data)),
                              "accounts": [[str(m.pubkey), m.is_signer, m.is_writable] for m in ix.accounts]} for ix in ixs]}


def restore_instructions(intent):
    return [Instruction(Pubkey.from_string(ix["program"]), unb64(ix["data"]),
                        [Meta(Pubkey.from_string(a), s, w) for a, s, w in ix["accounts"]])
            for ix in intent["instructions"]]


def verify_record(record, genesis):
    check(record["schema"] == 1 and record["genesis"] == genesis and record["program_sha256"] == SBF_SHA,
          "intent profile mismatch")
    wire = unb64(record["wire"])
    check(sha(wire) == record["wire_sha256"] and len(wire) <= 1232, "persisted wire hash/size mismatch")
    tx = Transaction.from_bytes(wire)
    tx.verify()
    check(str(tx.signatures[0]) == record["txid"], "persisted signature mismatch")
    expected = Message.new_with_blockhash(restore_instructions(record["intent"]),
                                         Pubkey.from_string(record["intent"]["payer"]), tx.message.recent_blockhash)
    check(bytes(expected) == bytes(tx.message), "wire differs from persisted semantic intent")
    return tx


class Sender:
    def __init__(self, rpc, store, wait_seconds):
        self.rpc, self.store, self.wait_seconds = rpc, store, wait_seconds

    def prepare(self, label, ixs, payer, signers=(), debit=0, error=None):
        intent = describe(ixs, payer.pubkey(), debit, error)
        path = self.store.path(label)
        if path.exists():
            record = self.store.read(label)
            check(record["intent"] == intent, "refusing a changed intent under an existing label")
            verify_record(record, self.rpc.genesis)
            return record
        self.rpc.guard()
        latest = self.rpc.call("getLatestBlockhash", [self.rpc.config()])
        value = latest["value"]
        tx = Transaction([payer, *signers], Message(ixs, payer.pubkey()), Hash.from_string(value["blockhash"]))
        wire = bytes(tx)
        check(len(wire) <= 1232, "transaction exceeds Solana wire limit")
        fee = self.rpc.call("getFeeForMessage", [b64(bytes(tx.message)), self.rpc.config()])["value"]
        check(type(fee) is int and fee >= 0, "fee quote unavailable")
        record = {"schema": 1, "label": label, "genesis": self.rpc.genesis, "program_sha256": SBF_SHA,
                  "intent": intent, "txid": str(tx.signatures[0]), "wire": b64(wire), "wire_sha256": sha(wire),
                  "last_valid_block_height": value["lastValidBlockHeight"], "blockhash_context_slot": latest["context"]["slot"],
                  "fee_quote": fee, "state": "prepared", "send_attempts": [], "receipt": None}
        verify_record(record, self.rpc.genesis)
        self.store.save(label, record)  # Signed bytes + semantic intent durably precede every handoff.
        return record

    def handoff(self, record):
        self.rpc.guard()
        verify_record(record, self.rpc.genesis)
        record["state"] = "attempt-started"
        record["send_attempts"].append({"time_ns": time.time_ns()})
        self.store.save(record["label"], record)  # Sticky ambiguous-delivery marker before send.
        try:
            txid = self.rpc.call("sendTransaction", [record["wire"], {"encoding": "base64", "skipPreflight": True,
                                   "preflightCommitment": self.rpc.commitment, "maxRetries": 0}])
            check(txid == record["txid"], "RPC returned another transaction identity")
            record["send_attempts"][-1]["result"] = "accepted-for-relay"
        except (RpcError, OSError, http.client.HTTPException) as error:
            record["send_attempts"][-1]["result"] = "delivery-uncertain"
            record["send_attempts"][-1]["error_type"] = type(error).__name__
        self.store.save(record["label"], record)

    def receipt(self, record):
        status = self.rpc.call("getSignatureStatuses", [[record["txid"]], {"searchTransactionHistory": True}])["value"][0]
        if status is None:
            return None
        accepted = {"finalized"} if self.rpc.commitment == "finalized" else {"confirmed", "finalized"}
        if status.get("confirmationStatus") not in accepted:
            return None
        result = self.rpc.call("getTransaction", [record["txid"], {"encoding": "base64", "commitment": self.rpc.commitment,
                                                                  "maxSupportedTransactionVersion": 0}])
        if result is None:
            return None
        self.rpc.guard()
        check(result["transaction"][1] == "base64" and unb64(result["transaction"][0]) == unb64(record["wire"]),
              "receipt is not for the exact persisted wire")
        meta = result["meta"]
        check(meta is not None and meta["err"] == record["intent"]["expected_error"] and status["err"] == meta["err"],
              "confirmed result differs from the expected success/rejection")
        check(result["slot"] == status["slot"], "status/receipt slot disagreement")
        check(meta["fee"] == record["fee_quote"], "receipt fee differs from signed-message quote")
        debit = record["intent"]["lamports_outside_fee"] if meta["err"] is None else 0
        check(meta["preBalances"][0] - meta["postBalances"][0] == meta["fee"] + debit,
              "payer lamports do not equal exact fee plus intended System Program outflow")
        return {"slot": result["slot"], "confirmation_status": status["confirmationStatus"], "err": meta["err"],
                "fee": meta["fee"], "pre_balances": meta["preBalances"], "post_balances": meta["postBalances"],
                "compute_units": meta.get("computeUnitsConsumed"), "wire_sha256": record["wire_sha256"]}

    def finish(self, record, force_send=False):
        deadline, next_send = time.monotonic() + self.wait_seconds, 0.0
        if force_send:
            self.handoff(record)
            next_send = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                self.rpc.guard()
                receipt = self.receipt(record)
                if receipt is not None:
                    record["receipt"], record["state"] = receipt, "chain-receipt"
                    self.store.save(record["label"], record)
                    return receipt
                height = self.rpc.call("getBlockHeight", [self.rpc.config()])
                if height > record["last_valid_block_height"]:
                    record["state"] = "expired-without-qualified-receipt"
                    self.store.save(record["label"], record)
                    raise GateError("blockhash expired without a qualified receipt; no replacement or new intent was created")
                if time.monotonic() >= next_send:
                    self.handoff(record)
                    next_send = time.monotonic() + 2
            except (RpcError, OSError, http.client.HTTPException):
                pass  # Reads and identical wire retries only, bounded by the outer deadline.
            time.sleep(0.5)
        raise GateError("bounded receipt wait expired; inspect/recover the persisted identity, never create a substitute")

    def send(self, label, ixs, payer, signers=(), debit=0, error=None):
        record = self.prepare(label, ixs, payer, signers, debit, error)
        receipt = self.finish(record)
        print(json.dumps({"intent": label, "txid": record["txid"], "receipt": receipt["confirmation_status"], "slot": receipt["slot"]}), flush=True)
        return record, receipt


def mint_matches(account, payer):
    data = account_bytes(account)
    check(account["owner"] == str(TOKEN) and not account["executable"] and len(data) == 82, "mint account owner/layout mismatch")
    check(data[:4] == struct.pack("<I", 1) and data[4:36] == bytes(payer) and data[44:46] == b"\x06\x01",
          "existing synthetic mint must have the configured payer as mint authority and decimals=6")
    check(data[46:50] == struct.pack("<I", 1) and data[50:82] == bytes(payer), "fixture freeze authority must also match the payer")
    return struct.unpack_from("<Q", data, 36)[0]


class Fixture:
    def __init__(self, payer, relayer):
        self.payer, self.relayer = payer, relayer
        for name in ("state", "vault", "source", "claim", "refund"):
            setattr(self, name, Keypair())
        self.authority, self.bump = Pubkey.find_program_address([b"xds-swap-v1", bytes(self.state.pubkey())], PID)
        self.deadline = None

    def persisted_keys(self):
        return {name: list(bytes(getattr(self, name))) for name in ("state", "vault", "source", "claim", "refund")}

    def keys(self):
        return [self.state.pubkey(), self.vault.pubkey(), MINT, self.claim.pubkey(), self.refund.pubkey(),
                self.source.pubkey(), self.payer.pubkey(), self.authority, TOKEN, CLOCK]

    def ix(self, op, secret=SECRET):
        data = b"\0" + u64(AMOUNT) + u64(self.deadline) + hashlib.sha256(SECRET).digest() if op == 0 else b"\x01" + secret if op == 1 else b"\x02"
        return Instruction(PID, data, [Meta(k, op == 0 and i in (0, 6), i in (0, 1, 3, 4, 5)) for i, k in enumerate(self.keys())])

    def snapshot(self, rpc, min_slot=None):
        names = ("state", "vault", "source", "claim", "refund")
        result = rpc.call("getMultipleAccounts", [[str(getattr(self, n).pubkey()) for n in names],
                                                   {**rpc.config(min_slot), "encoding": "base64"}])
        values = dict(zip(names, result["value"]))
        state = account_bytes(values["state"])
        check(values["state"]["owner"] == str(PID) and not values["state"]["executable"] and len(state) == 192, "state layout changed")
        out = {"state_hex": state.hex(), "balances": {}}
        owners = {"vault": self.authority, "source": self.payer.pubkey(), "claim": self.relayer.pubkey(), "refund": self.payer.pubkey()}
        for name, owner in owners.items():
            account, data = values[name], account_bytes(values[name])
            check(account["owner"] == str(TOKEN) and not account["executable"] and len(data) == 165 and data[:32] == bytes(MINT)
                  and data[32:64] == bytes(owner) and data[108] == 1 and not any(data[109:113]), "token account binding changed")
            check(not any(data[72:76]) and not any(data[129:133]), "unexpected token delegate/close authority")
            out["balances"][name] = struct.unpack_from("<Q", data, 64)[0]
        return out

    def expect(self, snap, status, vault, source, claim, refund):
        expected = bytearray(192)
        if status:
            expected[:8] = b"XDSV0001"
            expected[8:10] = bytes([status, self.bump])
            expected[16:24], expected[24:32] = u64(AMOUNT), u64(self.deadline)
            expected[32:64] = hashlib.sha256(SECRET).digest()
            for offset, key in ((64, self.vault.pubkey()), (96, MINT), (128, self.claim.pubkey()), (160, self.refund.pubkey())):
                expected[offset:offset + 32] = bytes(key)
        check(snap["state_hex"] == expected.hex(), "state bytes differ from immutable terms/tombstone")
        check(snap["balances"] == {"vault": vault, "source": source, "claim": claim, "refund": refund}, "exact token accounting mismatch")


def create_ix(payer, keypair, size, owner, rent):
    return create_account(CreateAccountParams(from_pubkey=payer.pubkey(), to_pubkey=keypair.pubkey(), lamports=rent[size], space=size, owner=owner))


def token_transfer(source, destination, owner):
    return Instruction(TOKEN, b"\x0c" + u64(AMOUNT) + b"\x06", [Meta(source.pubkey(), False, True), Meta(MINT, False, False),
                                                               Meta(destination.pubkey(), False, True), Meta(owner.pubkey(), True, False)])


def wait_for_slot(rpc, target, timeout):
    deadline = time.monotonic() + timeout
    while True:
        rpc.guard()
        slot = rpc.slot()
        if slot >= target:
            return slot
        check(time.monotonic() < deadline, "actual-slot wait exceeded its bound; no warp was used")
        time.sleep(0.5)


def require_duplicate_ingress(record, first_replay_attempt):
    attempts = record["send_attempts"]
    check(0 <= first_replay_attempt < len(attempts), "duplicate qualification has no replay attempt")
    accepted = [i for i in range(first_replay_attempt, len(attempts)) if attempts[i].get("result") == "accepted-for-relay"]
    check(accepted, "duplicate ingress unconfirmed: replay had no accepted-for-relay response; old receipt cannot qualify it")
    return accepted


def setup_fixture(f, sender, prefix, rent):
    p = f.payer
    groups = [(f.source, p.pubkey()), (f.vault, f.authority), (f.claim, f.relayer.pubkey()), (f.refund, p.pubkey())]
    for batch, pairs in enumerate((groups[:2], groups[2:])):
        ixs, signers, debit = [], [], 0
        for kp, owner in pairs:
            ixs.extend([create_ix(p, kp, 165, TOKEN, rent), Instruction(TOKEN, b"\x12" + bytes(owner),
                         [Meta(kp.pubkey(), False, True), Meta(MINT, False, False)])])
            signers.append(kp)
            debit += rent[165]
        if batch == 0:
            ixs.append(create_ix(p, f.state, 192, PID, rent))
            signers.append(f.state)
            debit += rent[192]
        sender.send(f"{prefix + batch:02d}-accounts", ixs, p, signers, debit)
    mint_before = mint_matches(sender.rpc.account(MINT), p.pubkey())
    _, receipt = sender.send(f"{prefix + 2:02d}-mint-source", [Instruction(TOKEN, b"\x0e" + u64(SUPPLY) + b"\x06",
                  [Meta(MINT, False, True), Meta(f.source.pubkey(), False, True), Meta(p.pubkey(), True, False)])], p)
    check(mint_matches(sender.rpc.account(MINT, receipt["slot"]), p.pubkey()) == mint_before + SUPPLY, "MintToChecked supply delta mismatch")
    snap = f.snapshot(sender.rpc, receipt["slot"])
    f.expect(snap, 0, 0, SUPPLY, 0, 0)


def run_cases(args, rpc, store, payer, profile):
    check(not (store.root / "run.json").exists(), "run directory already has a run; use explicit recover-intent or a new empty directory")
    check(not list(store.root.glob("[0-9][0-9]-*.json")), "existing signed intents must not be overwritten")
    relayer = Keypair()
    claim_f, refund_f = Fixture(payer, relayer), Fixture(payer, relayer)
    fixture_keys = {"relayer": list(bytes(relayer)), "claim_fixture": claim_f.persisted_keys(), "refund_fixture": refund_f.persisted_keys()}
    atomic_json(store.root / "synthetic-fixture-keys.json", fixture_keys)  # Never contains the configured payer key.
    report = {"schema": 1, "status": "running", "genesis": rpc.genesis, "commitment": rpc.commitment,
              "payer": str(payer.pubkey()), "synthetic_mint": str(MINT), "profile": profile, "cases": []}
    atomic_json(store.root / "run.json", report)
    sender = Sender(rpc, store, args.wait_seconds)

    def case(name, body):
        report["cases"].append({"name": name, "status": "PASS", **body})
        atomic_json(store.root / "run.json", report)
        print(json.dumps({"case": name, "status": "PASS"}), flush=True)

    rent = {size: rpc.call("getMinimumBalanceForRentExemption", [size, rpc.config()]) for size in (82, 165, 192)}
    mint_kp = Keypair.from_seed(bytes([4]) * 32)
    check(mint_kp.pubkey() == MINT, "fixed seed/profile mismatch")
    existing_mint = rpc.account(MINT)
    if existing_mint is not None:
        mint_matches(existing_mint, payer.pubkey())
    budget = RELAYER_SOL + 8 * rent[165] + 2 * rent[192] + (rent[82] if existing_mint is None else 0) + 1_000_000
    check(rpc.call("getBalance", [str(payer.pubkey()), rpc.config()])["value"] >= budget, "synthetic payer balance below calculated fixture budget")
    if existing_mint is None:
        sender.send("00-create-mint", [create_ix(payer, mint_kp, 82, TOKEN, rent), Instruction(TOKEN,
                    b"\x14\x06" + bytes(payer.pubkey()) + b"\x01" + bytes(payer.pubkey()), [Meta(MINT, False, True)])], payer, [mint_kp], rent[82])
    mint_matches(rpc.account(MINT), payer.pubkey())
    sender.send("01-fund-relayer", [transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=relayer.pubkey(), lamports=RELAYER_SOL))], payer, debit=RELAYER_SOL)
    setup_fixture(claim_f, sender, 10, rent)
    claim_f.deadline = rpc.slot() + args.refund_delay_slots
    atomic_json(store.root / "claim-terms.json", {"deadline": claim_f.deadline, "state": str(claim_f.state.pubkey()), "amount": AMOUNT})
    _, receipt = sender.send("13-fund-claim-escrow", [claim_f.ix(0)], payer, [claim_f.state])
    funded = claim_f.snapshot(rpc, receipt["slot"])
    claim_f.expect(funded, 1, AMOUNT, SUPPLY - AMOUNT, 0, 0)
    case("01-fund", {"snapshot": funded})

    _, receipt = sender.send("14-wrong-secret", [claim_f.ix(1, bytes([66]) * 32)], relayer,
                           error={"InstructionError": [0, {"Custom": 4110}]})
    unchanged = claim_f.snapshot(rpc, receipt["slot"])
    check(unchanged == funded, "wrong-secret changed token balances or state")
    case("02-wrong-secret-rejection", {"snapshot": unchanged, "receipt": receipt})

    claim_record, receipt = sender.send("15-claim", [claim_f.ix(1)], relayer)
    claimed = claim_f.snapshot(rpc, receipt["slot"])
    claim_f.expect(claimed, 2, 0, SUPPLY - AMOUNT, AMOUNT, 0)
    # Replay is the exact already-confirmed signature, including the original blockhash.
    balance_before = rpc.call("getBalance", [str(relayer.pubkey()), rpc.config(receipt["slot"])])["value"]
    first_replay_attempt = len(claim_record["send_attempts"])
    duplicate = sender.finish(claim_record, force_send=True)
    accepted_replay_attempts = require_duplicate_ingress(claim_record, first_replay_attempt)
    duplicate_handoff_slot = rpc.slot()
    observed_slot = wait_for_slot(rpc, duplicate_handoff_slot + 2, args.slot_wait_seconds)
    # No other financial intent is sent while this replay-observation window is open.
    duplicate = sender.receipt(claim_record)
    check(duplicate is not None, "original receipt disappeared during the duplicate observation window")
    check(duplicate["slot"] == receipt["slot"] and duplicate["wire_sha256"] == receipt["wire_sha256"], "duplicate produced another receipt")
    check(claim_f.snapshot(rpc, observed_slot) == claimed, "duplicate changed token/state accounting")
    check(rpc.call("getBalance", [str(relayer.pubkey()), rpc.config(observed_slot)])["value"] == balance_before, "duplicate charged an additional fee")
    case("03-claim-and-identical-duplicate", {"snapshot": claimed, "txid": claim_record["txid"],
                                             "accepted_replay_attempts": accepted_replay_attempts,
                                             "duplicate_handoff_slot": duplicate_handoff_slot, "observed_slot": observed_slot})

    _, receipt = sender.send("16-next-transfer-after-claim", [token_transfer(claim_f.claim, claim_f.refund, relayer)], relayer)
    moved = claim_f.snapshot(rpc, receipt["slot"])
    claim_f.expect(moved, 2, 0, SUPPLY - AMOUNT, 0, AMOUNT)
    case("04-next-transfer-after-claim", {"snapshot": moved})

    setup_fixture(refund_f, sender, 20, rent)
    refund_f.deadline = rpc.slot() + args.refund_delay_slots
    atomic_json(store.root / "refund-terms.json", {"deadline": refund_f.deadline, "state": str(refund_f.state.pubkey()), "amount": AMOUNT})
    _, receipt = sender.send("23-fund-refund-escrow", [refund_f.ix(0)], payer, [refund_f.state])
    refund_locked = refund_f.snapshot(rpc, receipt["slot"])
    refund_f.expect(refund_locked, 1, AMOUNT, SUPPLY - AMOUNT, 0, 0)
    check(rpc.slot() < refund_f.deadline, "early-refund window already passed")
    _, receipt = sender.send("24-early-refund", [refund_f.ix(2)], relayer, error={"InstructionError": [0, {"Custom": 4111}]})
    check(receipt["slot"] < refund_f.deadline, "rejection receipt did not occur before the deadline")
    check(refund_f.snapshot(rpc, receipt["slot"]) == refund_locked, "early refund changed token balances or state")
    case("05-early-refund-rejection", {"deadline": refund_f.deadline, "receipt": receipt})

    wait_for_slot(rpc, refund_f.deadline, args.slot_wait_seconds)
    # A distinct test intent after a definitively rejected earlier attempt; never a delivery-uncertainty replacement.
    _, receipt = sender.send("25-refund-after-deadline", [refund_f.ix(2)], relayer)
    check(receipt["slot"] >= refund_f.deadline, "refund receipt precedes the deadline")
    refunded = refund_f.snapshot(rpc, receipt["slot"])
    refund_f.expect(refunded, 3, 0, SUPPLY - AMOUNT, 0, AMOUNT)
    _, receipt = sender.send("26-next-transfer-after-refund", [token_transfer(refund_f.refund, refund_f.claim, payer)], payer)
    refund_moved = refund_f.snapshot(rpc, receipt["slot"])
    refund_f.expect(refund_moved, 3, 0, SUPPLY - AMOUNT, AMOUNT, 0)
    case("06-refund-and-next-transfer", {"deadline": refund_f.deadline, "refunded_snapshot": refunded, "next_transfer_snapshot": refund_moved})
    verify_program(rpc)
    report["status"] = "PASS"
    atomic_json(store.root / "run.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--expected-genesis", required=True)
    parser.add_argument("--payer-keypair", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--commitment", choices=("confirmed", "finalized"), default="confirmed")
    parser.add_argument("--wait-seconds", type=int, default=90)
    parser.add_argument("--slot-wait-seconds", type=int, default=240)
    parser.add_argument("--refund-delay-slots", type=int, default=160)
    parser.add_argument("--recover-intent", help="only reconcile/retry this existing immutable wire; does not resume case generation")
    args = parser.parse_args()
    check(sys.platform == "linux", "this qualification runner targets Linux")
    check(importlib.metadata.version("solders") == "0.29.0", "solders must be exactly 0.29.0")
    check(10 <= args.wait_seconds <= 300 and 10 <= args.slot_wait_seconds <= 600 and 64 <= args.refund_delay_slots <= 512,
          "wait/slot bounds out of range")
    rpc = Rpc(args.endpoint, args.expected_genesis, args.commitment)
    payer = load_payer(args.payer_keypair)
    profile = verify_program(rpc)  # No financial instruction until all profile gates pass.
    with Store(args.run_dir) as store:
        if args.recover_intent:
            run = read_private_json(store.root / "run.json")
            check(run["genesis"] == rpc.genesis and run["payer"] == str(payer.pubkey()), "recovery run identity mismatch")
            check(run["commitment"] == rpc.commitment, "recovery must preserve the original run commitment")
            record = store.read(args.recover_intent)
            check(record["label"] == args.recover_intent, "recovery label mismatch")
            verify_record(record, rpc.genesis)
            receipt = Sender(rpc, store, args.wait_seconds).finish(record)
            print(json.dumps({"recovered_intent": record["label"], "txid": record["txid"], "receipt": receipt}), flush=True)
        else:
            report = run_cases(args, rpc, store, payer, profile)
            print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "genesis": rpc.genesis}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Do not print arbitrary exception text/tracebacks that could contain key material.
        message = str(error) if isinstance(error, GateError) else type(error).__name__
        print(json.dumps({"status": "STOPPED", "reason": message}), file=sys.stderr, flush=True)
        raise SystemExit(1)
