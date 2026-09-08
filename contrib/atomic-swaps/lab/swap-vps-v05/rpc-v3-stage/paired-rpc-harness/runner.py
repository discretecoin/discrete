"""Two owned real-RPC swap cases. Linux execution is explicit; import/tests never start nodes."""
from dataclasses import asdict
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import sys
import time

from bindings import sol, xds, localnet, verify_pins
from paired import PairFixture, Policy, observe_admission, validate_public_witness


def event(phase, **fields):
    print(json.dumps({"phase": phase, **fields}), flush=True)


def persist_admission(result, evidence, observations, path, started, policy):
    observations.append(evidence)
    sol.atomic_json(path, observations)
    sol.check(0 <= time.monotonic() - started <= policy.max_observation_seconds,
              "admission observation aged out while persisting evidence; no first disclosure")
    return result


def persist_coordinated(x, c, kind, sender, record):
    """Both durable stores must agree before the coordinator can invoke the sender."""
    sol.verify_record(record, sender.rpc.genesis)
    sol.check(kind in ("foreign-fund", "foreign-claim", "foreign-refund"), "unsupported coordinated foreign kind")
    terms, intent = c["foreign"], record["intent"]
    sol.check(x.journal.terms(c["id"])["foreign"] == terms and terms["genesis"] == sender.rpc.genesis,
              "foreign terms differ from the immutable coordinator")
    op = {"foreign-fund": 0, "foreign-claim": 1, "foreign-refund": 2}[kind]
    instructions = intent["instructions"]
    sol.check(len(instructions) == 1 and instructions[0]["program"] == str(sol.PID)
              and intent["lamports_outside_fee"] == 0 and intent["expected_error"] is None,
              "foreign intent must contain only the selected escrow operation")
    data = sol.unb64(instructions[0]["data"])
    expected_data = (b"\0" + sol.u64(terms["amount"]) + sol.u64(terms["deadline_slot"])
                     + bytes.fromhex(terms["hashlock"])) if op == 0 else b"\2" if op == 2 else data
    sol.check(data == expected_data and (op != 1 or (len(data) == 33 and data[0] == 1
              and sol.sha(data[1:]) == terms["hashlock"] == c["terms"]["hashlock"])),
              "foreign instruction differs from its kind/hash/amount/deadline")
    keys = [terms[n] for n in ("state", "vault", "mint", "claim", "refund", "source", "source_refund_owner_bob", "vault_authority")]
    keys += [str(sol.TOKEN), str(sol.CLOCK)]
    sol.check(instructions[0]["accounts"] == [[key, op == 0 and i in (0, 6), i in (0, 1, 3, 4, 5)] for i, key in enumerate(keys)]
              and intent["payer"] == terms["source_refund_owner_bob" if op == 0 else "claim_owner_alice"],
              "foreign owners/destinations/metas differ from immutable terms")
    saved = sender.store.read(record["label"])
    sol.check(saved == record and record["state"] == "prepared" and not record["send_attempts"],
              "new coordinated intent must already be persisted and never sent")
    x.journal.prepare(c["id"], kind, sol.unb64(record["wire"]), record["txid"])


def send_coordinated(x, c, kind, sender, record):
    def send(wire, txid):
        intent = x.journal.intent(c["id"], kind)
        sol.check(intent["stage"] == "attempt-started" and intent["payload"] == wire
                  and wire == sol.unb64(record["wire"]) and txid == record["txid"],
                  "coordinator and RPC journals disagree at handoff")
        if kind == "foreign-claim":
            sol.check(x.journal.exposed(c["id"]), "foreign claim cannot precede mined XDS disclosure")
        return sender.finish(record)  # Only this persisted wire, including every uncertain retry.
    receipt = x.journal.broadcast(c["id"], kind, send)
    sol.check(receipt["confirmation_status"] == "finalized", "paired receipt must be finalized")
    x.journal.reconcile(c["id"], kind, record["txid"], "confirmed")
    event(kind, txid=record["txid"], finalized_slot=receipt["slot"])
    return receipt


def xds_settled(x, c, kind):
    x.journal.reconcile(c["id"], kind, c["settlement"]["tx_hash"], "confirmed")
    for node in x.net.nodes:
        funded = node.outpoint(c["fund"]["tx_hash"])
        payout = node.outpoint(c["settlement"]["tx_hash"])
        sol.check(funded["spent"] and payout["in_chain"] and payout["amount_atoms"] == 1000
                  and payout["tx_as_hex"] == c["settlement"]["tx_as_hex"], "XDS settlement readback mismatch")


def wallet_balances(x):
    x.alice.synced()
    x.bob.synced()
    return {"alice": x.alice.balance(), "bob": x.bob.balance()}


def wait_balances(x, target):
    xds.wait_for(lambda: wallet_balances(x) == target, "exact paired wallet balances", 90)
    return wallet_balances(x)


def public_witness(x, c, f, path):
    node, txid = x.net.nodes[3], c["settlement"]["tx_hash"]
    raw = node.call("/gettransactions", {"txs_hashes": [txid]})
    details = node.call("/get_transaction_details_by_hash", {"hash": txid})
    outpoint = node.outpoint(txid)
    observed = validate_public_witness(c, f, raw, details, outpoint)
    sol.atomic_json(path, {"node_index": 3, "raw": raw, "details": details, "outpoint": outpoint})
    # Revalidate the public witness file; no fallback to c['secret'].
    saved = sol.read_private_json(path)
    sol.check(observed == validate_public_witness(c, f, saved["raw"], saved["details"], saved["outpoint"]),
              "persisted public witness mismatch")
    return observed


def wait_processed(rpc, target, timeout):
    deadline, next_progress = time.monotonic() + timeout, 0.0
    while True:
        rpc.guard()
        current = rpc.call("getSlot", [{"commitment": "processed"}])
        if current >= target:
            return current
        sol.check(time.monotonic() < deadline, "bounded real processed-slot wait expired")
        if time.monotonic() >= next_progress:
            event("waiting-actual-slot", current=current, target=target)
            next_progress = time.monotonic() + 30
        time.sleep(0.5)


def setup_solana(rpc, sender, bob, alice, rent):
    mint_kp = sol.Keypair.from_seed(bytes([4]) * 32)
    sol.check(mint_kp.pubkey() == sol.MINT, "synthetic mint seed/profile mismatch")
    existing = rpc.account(sol.MINT)
    if existing is not None:
        sol.mint_matches(existing, bob.pubkey())
    budget = sol.RELAYER_SOL + 8 * rent[165] + 2 * rent[192] + (rent[82] if existing is None else 0) + 1_000_000
    balance = rpc.call("getBalance", [str(bob.pubkey()), rpc.config()])
    sol.check(balance["value"] >= budget, "Bob synthetic SOL balance below exact setup budget")
    if existing is None:
        sender.send("00-create-mint", [sol.create_ix(bob, mint_kp, 82, sol.TOKEN, rent), sol.Instruction(sol.TOKEN,
                    b"\x14\x06" + bytes(bob.pubkey()) + b"\1" + bytes(bob.pubkey()), [sol.Meta(sol.MINT, False, True)])],
                    bob, [mint_kp], rent[82])
    sol.mint_matches(rpc.account(sol.MINT), bob.pubkey())
    sender.send("01-fund-alice-fees", [sol.transfer(sol.TransferParams(from_pubkey=bob.pubkey(),
                to_pubkey=alice.pubkey(), lamports=sol.RELAYER_SOL))], bob, debit=sol.RELAYER_SOL)
    return {"rent_lamports": rent, "calculated_setup_budget_lamports": budget, "initial_bob_sol": balance}


def run_pair(name, x, rpc, parent_store, bob, alice, rent, policy):
    case_root = parent_store.root / name
    with sol.Store(case_root) as store:
        sender = sol.Sender(rpc, store, policy.receipt_wait_seconds)
        bob_secret = secrets.token_bytes(32)
        c = x.contract(bob_secret, delay=32)
        f = PairFixture(bob, alice, bytes.fromhex(c["terms"]["hashlock"]))
        before = wallet_balances(x)
        sol.atomic_json(case_root / "private-case-keys.json", {"bob_xds_preimage": bob_secret.hex(),
                        "rho_a": c["rho_a"].hex(), "rho_b": c["rho_b"].hex(), "fixture": f.persisted_keys()})
        negatives = []
        # Same future state account is absent on the actual finalized ledger before setup.
        absent = rpc.call("getAccountInfo", [str(f.state.pubkey()), {**rpc.config(), "encoding": "base64"}])
        sol.check(absent["value"] is None, "fresh fixture state unexpectedly exists")
        try:
            f.snapshot(rpc, absent["context"]["slot"])
        except sol.GateError:
            negatives.append({"predicate": "absent-foreign-state", "source": "actual-finalized-RPC",
                              "snapshot": absent, "phase": "before setup/registration; no claim intent exists"})
        else:
            raise sol.GateError("absent foreign state was accepted")
        sol.setup_fixture(f, sender, 10, rent)
        clock = rpc.call("getSlot", [{"commitment": "processed"}])
        f.deadline = clock + policy.foreign_refund_delay_slots
        funding = sender.prepare("13-foreign-fund", [f.ix(0)], bob, [f.state])
        c["foreign"] = {**f.public_terms(rpc.genesis), "funding_txid": funding["txid"],
                        "funding_wire_sha256": funding["wire_sha256"], "laboratory_policy": asdict(policy)}
        x.journal.register(c["id"], {"xds": c["terms"], "foreign": c["foreign"], "fixture_only": True})
        sol.atomic_json(case_root / "terms.json", {"swap_id": c["id"], "xds": c["terms"], "foreign": c["foreign"],
                        "roles": {"alice_xds": c["a"], "bob_xds": c["b"]}, "wallet_start_atoms": before,
                        "xds_atom_value": "0.01 XDS", "xds_fund_fee_atoms": 1, "xds_spend_fee_atoms": 1})
        persist_coordinated(x, c, "foreign-fund", sender, funding)
        foreign_fund_receipt = send_coordinated(x, c, "foreign-fund", sender, funding)
        c["foreign_funding_slot"] = foreign_fund_receipt["slot"]
        funded = f.snapshot(rpc, c["foreign_funding_slot"])
        f.expect(funded, 1, sol.AMOUNT, sol.SUPPLY - sol.AMOUNT, 0, 0)
        sol.atomic_json(case_root / "foreign-funded.json", {"snapshot": funded, "receipt": foreign_fund_receipt})

        x.prepare_fund(c)
        first_funding = x.relay(c, "xds-fund")
        exact_retry = x.relay(c, "xds-fund")
        x.mine(1)
        x.journal.reconcile(c["id"], "xds-fund", c["fund"]["tx_hash"], "confirmed")
        for node in x.net.nodes:
            outpoint = node.outpoint(c["fund"]["tx_hash"])
            sol.check(outpoint["in_chain"] and outpoint["amount_atoms"] == 1001
                      and outpoint["tx_as_hex"] == c["fund"]["tx_as_hex"], "XDS foreign-first funding mismatch")
        sol.atomic_json(case_root / "xds-funding.json", {"prepared": c["fund"], "first": first_funding, "identical_retry": exact_retry})
        observations = []

        def fresh_admission():
            started = time.monotonic()
            result, evidence = observe_admission(x, c, f, rpc, policy)
            return persist_admission(result, evidence, observations,
                                     case_root / "admission-observations.json", started, policy)

        if name == "success":
            x.prepare_spend(c)
            blocked_wire = x.journal.intent(c["id"], "xds-claim")["payload"]
            try:
                x.relay(c, "xds-claim", fresh_admission)
            except ValueError as error:
                sol.check(str(error) == "fresh first-exposure admission failed", "unexpected underconfirmation failure")
            else:
                raise sol.GateError("underconfirmed XDS disclosure was allowed")
            sol.check(observations and observations[-1]["admission"]["confirmations"] == 1
                      and not x.journal.exposed(c["id"])
                      and x.journal.intent(c["id"], "xds-claim")["stage"] == "prepared"
                      and not x.n.outpoint(c["settlement"]["tx_hash"])["found"],
                      "underconfirmed claim was exposed or sent")
            negatives.append({"predicate": "underconfirmed-XDS", "source": "actual-journal-denial-at-handoff",
                              "confirmations": 1, "exposure": False, "stage": "prepared"})
            x.mine(10)
            sol.check(x.n.outpoint(c["fund"]["tx_hash"])["confirmations"] == 11, "exact 11-confirmation baseline changed")
            x.relay(c, "xds-claim", fresh_admission)
            sol.check(x.journal.intent(c["id"], "xds-claim")["payload"] == blocked_wire
                      and x.journal.exposed(c["id"]), "first admitted claim changed bytes or lost exposure")
            x.mine(1)
            xds_settled(x, c, "xds-claim")
            # Read the public node-3 witness immediately; wallet scan waits are outside the redemption critical path.
            observed = public_witness(x, c, f, case_root / "public-xds-claim.json")
            claim = sender.prepare("14-foreign-claim", [f.ix(1, observed)], alice)
            persist_coordinated(x, c, "foreign-claim", sender, claim)
            receipt = send_coordinated(x, c, "foreign-claim", sender, claim)
            after = f.snapshot(rpc, receipt["slot"])
            f.expect(after, 2, 0, sol.SUPPLY - sol.AMOUNT, sol.AMOUNT, 0)
            # A late protective claim is still executed, but does not qualify the timing policy as PASS.
            sol.check(receipt["slot"] < f.deadline, "claim settled after refund boundary; timing policy not qualified")
            wallet_after = wait_balances(x, {"alice": before["alice"] - 1002, "bob": before["bob"] + 1000})
            _, next_receipt = sender.send("15-alice-next-transfer", [sol.token_transfer(f.claim, f.refund, alice)], alice)
            next_state = f.snapshot(rpc, next_receipt["slot"])
            f.expect(next_state, 2, 0, sol.SUPPLY - sol.AMOUNT, 0, sol.AMOUNT)
        else:
            x.mine(10)
            initial = fresh_admission()
            sol.check(initial.allow_first_exposure(), "abandonment baseline did not have sufficient actual admission")
            wait_processed(rpc, f.deadline - policy.foreign_claim_budget_slots, policy.slot_wait_seconds)
            denied = fresh_admission()
            sol.check(not denied.allow_first_exposure() and denied.foreign_claim_remaining <= denied.foreign_claim_budget,
                      "actual insufficient foreign timing margin was accepted")
            sol.check(not x.journal.exposed(c["id"]) and x.journal.intent(c["id"], "xds-claim") is None
                      and x.journal.intent(c["id"], "foreign-claim") is None, "abandonment prepared a secret-bearing claim")
            negatives.append({"predicate": "insufficient-real-slot-margin", "source": "actual-admission-read",
                              "remaining_slots": denied.foreign_claim_remaining, "budget_slots": denied.foreign_claim_budget,
                              "no_claim_intent": True, "exposure": False})
            x.mine(c["terms"]["refund_height"] - x.n.info()["height"])
            x.prepare_spend(c, refund=True)
            x.relay(c, "xds-refund")
            x.mine(1)
            xds_settled(x, c, "xds-refund")
            wallet_after = wait_balances(x, {"alice": before["alice"] - 2, "bob": before["bob"]})
            wait_processed(rpc, f.deadline, policy.slot_wait_seconds)
            refund = sender.prepare("14-foreign-refund", [f.ix(2)], alice)
            persist_coordinated(x, c, "foreign-refund", sender, refund)
            receipt = send_coordinated(x, c, "foreign-refund", sender, refund)
            sol.check(receipt["slot"] >= f.deadline, "refund preceded the immutable deadline")
            after = f.snapshot(rpc, receipt["slot"])
            f.expect(after, 3, 0, sol.SUPPLY - sol.AMOUNT, 0, sol.AMOUNT)
            try:
                f.expect(after, 1, sol.AMOUNT, sol.SUPPLY - sol.AMOUNT, 0, 0)
            except sol.GateError:
                negatives.append({"predicate": "consumed-foreign-escrow", "source": "actual-finalized-state-predicate",
                                  "snapshot": after, "no_claim_intent": True, "exposure": False})
            else:
                raise sol.GateError("consumed foreign state was accepted as funded")
            sol.check(not x.journal.exposed(c["id"]), "refund-only swap became exposed")
            _, next_receipt = sender.send("15-bob-next-transfer", [sol.token_transfer(f.refund, f.source, bob)], bob)
            next_state = f.snapshot(rpc, next_receipt["slot"])
            f.expect(next_state, 3, 0, sol.SUPPLY, 0, 0)

        records = [store.read(p.stem) for p in sorted(store.root.glob("[0-9][0-9]-*.json"))]
        fees = [{"intent": r["label"], "payer": r["intent"]["payer"], "fee_lamports": r["receipt"]["fee"],
                 "setup_outflow_lamports": r["intent"]["lamports_outside_fee"]} for r in records]
        result = {"case": name, "status": "PASS", "swap_id": c["id"], "wallet_before_atoms": before,
                  "wallet_after_atoms": wallet_after, "foreign_settlement": {"snapshot": after, "receipt": receipt},
                  "ordinary_owner_transfer": {"snapshot": next_state, "receipt": next_receipt},
                  "coordinator_exposed": x.journal.exposed(c["id"]), "negative_controls": negatives,
                  "solana_setup_and_fees": fees}
        sol.atomic_json(case_root / "result.json", result)
        event("paired-case", name=name, status="PASS")
        return result


def run(args):
    sol.check(os.name == "posix", "actual paired runner requires Linux; offline tests are portable")
    sol.check(importlib.metadata.version("solders") == "0.29.0", "solders must be exactly 0.29.0")
    policy = Policy().validate()
    rpc = sol.Rpc(args.endpoint, args.expected_genesis, "finalized")
    bob = sol.load_payer(args.payer_keypair)
    profile = sol.verify_program(rpc)
    pins = verify_pins()
    for binary in (localnet.DAEMON, localnet.WALLET):
        sol.check(binary.is_file() and os.access(binary, os.X_OK), "required explicitly configured XDS binary absent")
    with sol.Store(args.run_dir) as store:
        sol.check(not list(store.root.iterdir()) or {p.name for p in store.root.iterdir()} == {".lock"},
                  "paired run requires an empty directory; no automatic restart or resigning")
        alice = sol.Keypair()
        sol.atomic_json(store.root / "private-alice-solana.json", list(bytes(alice)))
        report = {"schema": 1, "status": "RUNNING", "genesis": rpc.genesis, "commitment": "finalized",
                  "profile": profile, "dependency_hashes": pins, "policy": asdict(policy), "cases": [],
                  "bob_solana": str(bob.pubkey()), "alice_solana": str(alice.pubkey()),
                  "binaries": {str(p): sol.sha(p.read_bytes()) for p in (localnet.DAEMON, localnet.WALLET)}}
        sol.atomic_json(store.root / "run.json", report)
        old_root, started = localnet.ROOT, False
        try:
            # Only output placement changes; no helper implementation or process/network flags change.
            localnet.ROOT = store.root / "xds"
            event("starting-owned-four-XDS-daemons-and-two-wallets")
            xds.WalletNetwork.setUpClass()
            started = True
            x = xds.WalletNetwork("runTest")
            report["xds_run_dir"] = str(x.net.directory)
            sol.atomic_json(store.root / "run.json", report)
            sender = sol.Sender(rpc, store, policy.receipt_wait_seconds)
            rent = {size: rpc.call("getMinimumBalanceForRentExemption", [size, rpc.config()]) for size in (82, 165, 192)}
            report["solana_setup"] = setup_solana(rpc, sender, bob, alice, rent)
            for name in ("success", "abandonment"):
                report["cases"].append(run_pair(name, x, rpc, store, bob, alice, rent, policy))
                sol.atomic_json(store.root / "run.json", report)
            report["status"] = "PASS"
        except BaseException as error:
            report["status"] = "STOPPED"
            report["error_type"] = type(error).__name__
            raise
        finally:
            try:
                if started:
                    xds.WalletNetwork.tearDownClass()
            except BaseException as error:
                report["status"] = "STOPPED"
                report["cleanup_error_type"] = type(error).__name__
                raise
            finally:
                localnet.ROOT = old_root
                sol.atomic_json(store.root / "run.json", report)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--expected-genesis", required=True)
    parser.add_argument("--payer-keypair", required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run(args)
    event("paired-run", status=report["status"], cases=len(report["cases"]))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        reason = str(error) if isinstance(error, sol.GateError) else type(error).__name__
        print(json.dumps({"status": "STOPPED", "reason": reason}), file=sys.stderr, flush=True)
        sys.exit(1)
