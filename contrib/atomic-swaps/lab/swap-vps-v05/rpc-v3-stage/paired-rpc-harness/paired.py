"""Narrow per-swap fixture, public witness validation and observed admission policy."""
from dataclasses import asdict, dataclass
import hashlib
import time

from bindings import sol, Admission


class PairFixture(sol.Fixture):
    """No secret is stored here: the funding path receives only its 32-byte hash."""
    def __init__(self, bob, alice, hashlock):
        sol.check(type(hashlock) is bytes and len(hashlock) == 32, "hashlock must be exactly 32 bytes")
        sol.check(bob.pubkey() != alice.pubkey(), "Solana owners must be distinct")
        super().__init__(bob, alice)
        self.hashlock = hashlock

    def ix(self, op, public_preimage=None):
        sol.check(type(op) is int and op in (0, 1, 2), "unknown escrow instruction")
        if op == 0:
            sol.check(public_preimage is None, "funding takes a hashlock only")
            data = b"\0" + sol.u64(sol.AMOUNT) + sol.u64(self.deadline) + self.hashlock
        elif op == 1:
            sol.check(type(public_preimage) is bytes and len(public_preimage) == 32
                      and hashlib.sha256(public_preimage).digest() == self.hashlock,
                      "claim requires an explicit matching public preimage")
            data = b"\1" + public_preimage
        else:
            sol.check(public_preimage is None, "refund takes no preimage")
            data = b"\2"
        return sol.Instruction(sol.PID, data, [sol.Meta(k, op == 0 and i in (0, 6), i in (0, 1, 3, 4, 5))
                                             for i, k in enumerate(self.keys())])

    def snapshot(self, rpc, min_slot=None):
        class Capture:
            def __init__(self):
                self.context = None
            def config(self, slot=None):
                return rpc.config(slot)
            def call(self, method, params):
                sol.check(method == "getMultipleAccounts" and self.context is None, "unexpected snapshot call")
                result = rpc.call(method, params)
                self.context = result["context"]["slot"]
                return result
        capture = Capture()
        out = super().snapshot(capture, min_slot)
        sol.check(type(capture.context) is int and capture.context >= (min_slot or 0), "snapshot context below receipt")
        return {**out, "context_slot": capture.context, "commitment": rpc.commitment}

    def expect(self, snap, status, vault, source, claim, refund):
        # Byte-for-byte frozen Fixture.expect layout; only the global hash is replaced.
        expected = bytearray(192)
        if status:
            expected[:8] = b"XDSV0001"
            expected[8:10] = bytes([status, self.bump])
            expected[16:24], expected[24:32] = sol.u64(sol.AMOUNT), sol.u64(self.deadline)
            expected[32:64] = self.hashlock
            for offset, key in ((64, self.vault.pubkey()), (96, sol.MINT),
                                (128, self.claim.pubkey()), (160, self.refund.pubkey())):
                expected[offset:offset + 32] = bytes(key)
        sol.check(snap["state_hex"] == expected.hex(), "foreign state differs from required immutable terms/status")
        sol.check(snap["balances"] == {"vault": vault, "source": source, "claim": claim, "refund": refund},
                  "foreign exact token accounting mismatch")

    def public_terms(self, genesis):
        return {"network": "owned-real-rpc-synthetic-spl", "genesis": genesis, "commitment": "finalized",
                "program": str(sol.PID), "program_sha256": sol.SBF_SHA, "mint": str(sol.MINT),
                "amount": sol.AMOUNT, "deadline_slot": self.deadline, "hashlock": self.hashlock.hex(),
                **{name: str(getattr(self, name).pubkey()) for name in ("state", "vault", "source", "claim", "refund")},
                "source_refund_owner_bob": str(self.payer.pubkey()), "claim_owner_alice": str(self.relayer.pubkey()),
                "vault_authority": str(self.authority)}


@dataclass(frozen=True)
class Policy:
    xds_confirmations: int = 11
    xds_claim_budget_blocks: int = 2
    foreign_claim_budget_slots: int = 128
    foreign_refund_delay_slots: int = 768
    max_finalized_lag_slots: int = 96
    max_observation_seconds: int = 15
    receipt_wait_seconds: int = 180
    slot_wait_seconds: int = 600

    def validate(self):
        sol.check(all(type(v) is int and v > 0 for v in asdict(self).values()), "policy values must be positive integers")
        sol.check(self.xds_confirmations == 11 and self.xds_claim_budget_blocks == 2,
                  "paired qualification preserves 11 confirmations and the two-block budget")
        sol.check(128 <= self.foreign_claim_budget_slots <= 256 and 512 <= self.foreign_refund_delay_slots <= 1024,
                  "foreign laboratory policy outside reviewed bounds")
        sol.check(self.foreign_refund_delay_slots > 2 * self.foreign_claim_budget_slots
                  and self.max_finalized_lag_slots <= 128 and self.max_observation_seconds <= 15
                  and 30 <= self.receipt_wait_seconds <= 300 and self.slot_wait_seconds <= 600,
                  "observation/wait policy outside reviewed bounds")
        return self


def admission_from_observations(c, f, outpoint, snapshot, processed_slot, fee, fee_balance,
                                balance_slot, quote_slot, observed_seconds, policy):
    """Called only with current RPC readbacks by observe_admission. No caller proof flags."""
    policy.validate()
    f.expect(snapshot, 1, sol.AMOUNT, sol.SUPPLY - sol.AMOUNT, 0, 0)
    sol.check(snapshot["commitment"] == "finalized", "foreign settlement observation must be finalized")
    sol.check(outpoint["status"] == "OK" and outpoint["found"] and outpoint["in_chain"]
              and outpoint["spent_known"] and not outpoint["spent"] and not outpoint["spent_in_pool"]
              and outpoint["amount_atoms"] == 1001 and outpoint["tx_as_hex"] == c["fund"]["tx_as_hex"]
              and outpoint["genesis_hash"] == c["terms"]["genesis_hash"], "XDS funding is not the exact live unspent contract")
    sol.check(c["terms"]["hashlock"] == f.hashlock.hex(), "cross-chain hashlock mismatch")
    numeric = (processed_slot, fee, fee_balance, balance_slot, quote_slot, snapshot["context_slot"],
               outpoint["height"], outpoint["block_height"], outpoint["confirmations"], c["foreign_funding_slot"])
    sol.check(all(type(n) is int and n >= 0 for n in numeric) and fee > 0, "invalid observed numeric evidence")
    sol.check(outpoint["confirmations"] == outpoint["height"] - outpoint["block_height"],
              "XDS confirmation count differs from observed heights")
    contexts = (snapshot["context_slot"], balance_slot, quote_slot)
    fresh = (0 <= observed_seconds <= policy.max_observation_seconds
             and all(c["foreign_funding_slot"] <= slot <= processed_slot
                     and processed_slot - slot <= policy.max_finalized_lag_slots for slot in contexts))
    return Admission(outpoint["confirmations"], policy.xds_claim_budget_blocks,
                     max(0, c["terms"]["refund_height"] - outpoint["height"]),
                     policy.foreign_claim_budget_slots, max(0, f.deadline - processed_slot),
                     True, fresh, fee_balance >= 2 * fee)


def observe_admission(x, c, f, rpc, policy):
    started = time.monotonic()
    sol.check(rpc.commitment == "finalized", "paired RPC commitment must be finalized")
    rpc.guard()
    outpoint = x.n.outpoint(c["fund"]["tx_hash"])
    snapshot = f.snapshot(rpc, c["foreign_funding_slot"])
    latest = rpc.call("getLatestBlockhash", [rpc.config(snapshot["context_slot"])])
    # Fee quote only: no signature or actual preimage, and this message is never submitted.
    fee_ix = sol.Instruction(sol.PID, b"\1" + bytes(32),
                            [sol.Meta(k, False, i in (0, 1, 3, 4, 5)) for i, k in enumerate(f.keys())])
    message = sol.Message.new_with_blockhash([fee_ix], f.relayer.pubkey(), sol.Hash.from_string(latest["value"]["blockhash"]))
    quote = rpc.call("getFeeForMessage", [sol.b64(bytes(message)), rpc.config(snapshot["context_slot"])])
    balance = rpc.call("getBalance", [str(f.relayer.pubkey()), rpc.config(snapshot["context_slot"])])
    rpc.guard()
    # Last chain clock read. This does not qualify funding/settlement as processed.
    clock = rpc.call("getSlot", [{"commitment": "processed", "minContextSlot": snapshot["context_slot"]}])
    elapsed = time.monotonic() - started
    result = admission_from_observations(c, f, outpoint, snapshot, clock, quote["value"], balance["value"],
                                         balance["context"]["slot"], quote["context"]["slot"], elapsed, policy)
    evidence = {"xds": outpoint, "foreign": snapshot, "processed_clock_slot": clock,
                "claim_fee_quote_lamports": quote, "claim_owner_balance_lamports": balance,
                "latest_blockhash_context_slot": latest["context"]["slot"], "observation_seconds": elapsed,
                "policy": asdict(policy), "admission": asdict(result), "allow_first_exposure": result.allow_first_exposure(),
                "recorded_time_ns": time.time_ns()}
    return result, evidence


def validate_public_witness(c, f, raw, details, outpoint):
    txid = c["settlement"]["tx_hash"]
    sol.check(raw["status"] == "OK" and raw["txs_as_hex"] == [c["settlement"]["tx_as_hex"]], "public XDS wire mismatch")
    d = details["transaction"]
    sol.check(d["inBlockchain"] and d["hash"] == txid and d["fee"] == 1 and d["txType"] == 5
              and outpoint["in_chain"] and d["blockHash"] == outpoint["block_hash"]
              and outpoint["tx_as_hex"] == c["settlement"]["tx_as_hex"], "public XDS claim inclusion mismatch")
    sol.check(len(d["inputs"]) == 1 and d["inputs"][0]["type"] == "20", "public XDS SwapInput mismatch")
    w = d["inputs"][0]["data"]["input"]
    sol.check(w["prev_txid"] == c["fund"]["tx_hash"] and w["prev_out_index"] == 0 and w["branch"] == 1,
              "public claim spent another contract or branch")
    secret = bytes.fromhex(w["secret"])
    sol.check(len(secret) == 32 and hashlib.sha256(secret).hexdigest() == c["terms"]["hashlock"]
              and hashlib.sha256(secret).digest() == f.hashlock, "public preimage differs from either contract")
    return secret
