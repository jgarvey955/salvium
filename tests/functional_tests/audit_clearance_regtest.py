#!/usr/bin/env python3
"""Isolated owner request, main processing, immutable chain clearance and H+1 spend."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from audit_gate_regtest import AuditChain, COIN
from audit_release_regtest import LocalChain, RpcError


class PrivateChain(AuditChain):
    activation = 140
    rpc_login = ("audit-fixture", "isolated-test-password")

    def start(self, name, command, rpc, ready_method):
        if name == "daemon":
            rpc.login = self.rpc_login
            command += ["--regtest-private-audit-height", str(self.activation),
                        "--regtest-private-audit-public-key", self.authority, "--keep-fakechain",
                        "--rpc-login", ":".join(self.rpc_login)]
        else:
            command += ["--regtest-lineage-audit-height", str(self.activation),
                        "--daemon-login", ":".join(self.rpc_login)]
        return LocalChain.start(self, name, command, rpc, ready_method)


def rejected(function):
    try:
        function()
    except RpcError:
        return
    raise AssertionError("Invalid audit action accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, default=Path("build/audit/release/bin"))
    parser.add_argument("--full-stake", action="store_true", help="Mine and spend the complete 21600-block cleared stake payout")
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="salvium-private-clearance-"))
    print(root, flush=True)
    bins = args.binaries.resolve()
    tool = bins / "salvium-audit-review"

    def command(*args):
        result = subprocess.run([str(tool), *map(str, args)], capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    secret = root / "developer.key"
    public = command("--keygen", secret).split()[-1]
    chain = PrivateChain(bins, root)
    chain.authority = public
    checks = []
    try:
        chain.launch()
        chain.mine(100, fund_miner=True)
        funding = chain.transfer(0, 1, 50 * COIN, relay=False)
        chain.submit(funding, True); chain.mine(11)
        onward = chain.transfer(1, 2, 10 * COIN, relay=False)
        chain.submit(onward, True); chain.mine(11)
        stake = chain.transfer(1, 1, 12 * COIN, tx_type=6, relay=False)
        chain.submit(stake, True); chain.mine(11)
        prebuilt = chain.transfer(1, 2, 3 * COIN, relay=False)
        chain.mine(chain.activation - chain.tip())
        assert chain.balance(1)["unlocked_balance"] == 0
        chain.submit(prebuilt, False)
        checks.append("wallet and daemon lock at activation")
        snapshot = chain.tip()
        evidence = []
        for i, wallet in enumerate(chain.wallets):
            response = wallet.call("audit", {"export_evidence": True, "snapshot_height": snapshot})
            path = root / f"owner-{i}.json"; path.write_text(response["private_evidence"]); evidence.append(path)
        complete = root / "complete"
        print(command("--data-dir", root / "chain/fake", "--network", "fakechain", "--opening", "0",
            "--activation-height", chain.activation, "--clearance-authority", public,
            "--input", *evidence, "--public-work-limit", "0", "--sign-key", secret, "--outdir", complete), flush=True)
        case = json.loads((complete / "case.json").read_text())
        assert case["outputs"] and all(o["state"] == "CLEARED" for o in case["outputs"]), case
        checks.append("cross-wallet funding and stake principal reconcile automatically")
        receipts = [p for p in complete.glob("*.json") if p.name not in ("case.json", "review-queue.json")]
        by_wallet = {}
        for i, path in enumerate(evidence):
            request = json.loads(path.read_text())
            # Receipt package identity is covered by the wallet importer; try
            # each recipient only with its matching exported package context.
            for receipt in receipts:
                report = json.loads(receipt.read_text())
                own = chain.wallets[i].call("audit", {"status_only": True})["outputs"]
                identities = {(o["transaction"], o["output_index"], o["stake"]) for o in own}
                if not all((o["transaction"], o["output_index"], o["stake"]) in identities for o in report["outputs"]):
                    continue
                assert report["clearances"], report
                forged = copy.deepcopy(report); forged["outputs"][0]["amount"] += 1
                rejected(lambda: chain.wallets[i].call("audit", {"review_result": json.dumps(forged), "developer_public_key": public}))
                by_wallet.setdefault(i, []).append(receipt)
        assert len(by_wallet) == 3
        publisher = Path(__file__).resolve().parents[2] / "utils/process_private_audit.py"
        rpc_login_file = root / "rpc.login"
        rpc_login_file.write_text(":".join(chain.rpc_login)); rpc_login_file.chmod(0o600)
        def publish(folder, success=True):
            result = subprocess.run([sys.executable, str(publisher), "--daemon-address", chain.daemon.url,
                "--rpc-login-file", str(rpc_login_file), "--case-directory", str(folder)],
                capture_output=True, text=True, timeout=180)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result.stdout
        # A purchase can resolve otherwise incomplete funding automatically,
        # but only after the main operator authenticates the exact ledger.
        pending = root / "exchange-pending"
        command("--data-dir", root / "chain/fake", "--network", "fakechain", "--opening", "0",
            "--activation-height", chain.activation, "--clearance-authority", public,
            "--input", *evidence[1:], "--public-work-limit", "0", "--sign-key", secret, "--outdir", pending)
        pending_case = json.loads((pending / "case.json").read_text())
        alice_rows = chain.wallets[1].call("audit", {"status_only": True})["outputs"]
        alice_keys = {(r["transaction"], r["output_index"], r["stake"]) for r in alice_rows}
        custody = {r["package_id"] for r in pending_case["outputs"]
            if (r["transaction"], r["output_index"], r["stake"]) in alice_keys}
        reserve = sum(r["amount"] for r in pending_case["outputs"] if r["package_id"] in custody and not r["spent"])
        withdrawal = next(r for r in pending_case["outputs"] if r["transaction"] == onward["tx_hash"]
            and not r["stake"] and r["amount"] == 10 * COIN and r["package_id"] not in custody)
        assert withdrawal["state"] == "REVIEW_REQUIRED" and withdrawal["amount"] == 10 * COIN
        amount = withdrawal["amount"]
        ledger = {k: pending_case[k] for k in ("network", "genesis", "snapshot_height", "snapshot_hash")}
        ledger.update(version=1, scope_complete=True, assets_in_scope=["SAL1"], custody_package_ids=sorted(custody),
            balances=[dict(account="seller", asset="SAL1", opening_atomic=str(reserve + amount), closing_atomic=str(reserve)),
                      dict(account="buyer", asset="SAL1", opening_atomic="0", closing_atomic="0")],
            events=[dict(id="sell", group="trade", kind="trade", account="seller", asset="SAL1", delta_atomic=str(-amount)),
                    dict(id="buy", group="trade", kind="trade", account="buyer", asset="SAL1", delta_atomic=str(amount)),
                    dict(id="withdraw", kind="withdrawal", account="buyer", asset="SAL1", delta_atomic=str(-amount),
                         transaction=withdrawal["transaction"], output_index=withdrawal["output_index"], acquisition="market_purchase")])
        ledger_file = root / "operator-ledger.json"; ledger_file.write_text(json.dumps(ledger))
        adapter = Path(__file__).resolve().parents[2] / "utils/reconcile_nonkyc_audit.py"
        purchase = root / "automatic-purchase"
        adapter_args = [sys.executable, str(adapter), "--case", str(pending / "case.json"), "--ledger", str(ledger_file),
            "--verifier", str(tool), "--developer-public-key", public, "--sign-key", str(secret),
            "--activation-height", str(chain.activation), "--daemon-address", chain.daemon.url,
            "--rpc-login-file", str(rpc_login_file)]
        invalid = subprocess.run(adapter_args + ["--output", str(root / "unapproved.json"), "--outdir", str(root / "unapproved"),
            "--approved-ledger-sha256", "0" * 64], capture_output=True, text=True, timeout=60)
        assert invalid.returncode != 0 and not (root / "unapproved").exists()
        subprocess.run(adapter_args + ["--output", str(root / "purchase-reconciliation.json"), "--outdir", str(purchase),
            "--approved-ledger-sha256", hashlib.sha256(ledger_file.read_bytes()).hexdigest()], check=True, timeout=180)
        purchased_case = json.loads((purchase / "case.json").read_text())
        purchased_row = next(r for r in purchased_case["outputs"] if r["transaction"] == withdrawal["transaction"]
            and r["output_index"] == withdrawal["output_index"] and r["package_id"] == withdrawal["package_id"] and not r["stake"])
        assert purchased_row["decision"] == "CLEAR" and purchased_row["reason"] == withdrawal["reason"]
        checks.append("authenticated exchange purchase signs and publishes automatically; unapproved ledger rejected; finding retained")
        print(publish(complete), flush=True)
        public_manifest = json.loads((complete / "clearances.public").read_text())
        queue = next((root / "chain").rglob("audit-clearance-queue-v4"))
        queued = len(list(queue.iterdir()))
        certs = [bytes.fromhex(c) for receipt in receipts for c in json.loads(receipt.read_text())["clearances"]]
        def varint(value):
            result = bytearray()
            while value >= 128:
                result.append((value & 127) | 128); value >>= 7
            result.append(value); return bytes(result)
        repacked = b"\x04" + varint(len(certs)) + b"".join(reversed(certs))
        chain.daemon.call("submit_audit_clearance", {"data": repacked.hex()})
        assert len(list(queue.iterdir())) == queued
        tampered = bytearray.fromhex(public_manifest["batches"][0]); tampered[-1] ^= 1
        rejected(lambda: chain.daemon.call("submit_audit_clearance", {"data": tampered.hex()}))
        checks.append("certificate repacking is deduplicated and forged signatures are rejected")
        assert chain.balance(1)["unlocked_balance"] == 0
        checks.append("automatic main processing publishes public clearance without owner import")
        confirmed = chain.mine(1)["height"]
        assert chain.balance(1)["unlocked_balance"] > 0
        spent = chain.transfer(1, 2, 2 * COIN, relay=False)
        chain.submit(spent, True)
        next_block = chain.mine(1)
        assert next_block["height"] == confirmed + 1
        assert spent["tx_hash"] in chain.block(chain.tip())["tx_hashes"]
        checks.append("confirmed H certificate spends in H+1 without extra audit wait")
        print(publish(complete), flush=True)
        # An optional receipt import is idempotent; spending already worked without it.
        for receipt in by_wallet[1]:
            chain.wallets[1].call("audit", {"review_result": receipt.read_text(), "developer_public_key": public})
        checks.append("confirmed receipt retry is idempotent")
        # A main developer can resolve a denial, but cannot change final CLEAR.
        own = json.loads(by_wallet[2][0].read_text())["outputs"][0]
        decisions = {"report_hash": command("--report", complete / "case.json", "--verify-key", public).split()[-1],
            "decisions": [{"package_id": own["package_id"], "transaction": own["transaction"],
                "output_index": own["output_index"], "stake": own["stake"], "action": "DENY", "reason": "immutability test"}]}
        path = root / "deny.json"; path.write_text(json.dumps(decisions))
        denied = root / "attempted-change"
        command("--report", complete / "case.json", "--decisions", path, "--activation-height", chain.activation,
            "--sign-key", secret, "--outdir", denied)
        publish(denied, success=False)
        checks.append("even developer cannot alter final output clearance")
        chain.mine(10)
        inherited = chain.balance(2)["unlocked_balance"]
        assert inherited >= 12 * COIN
        checks.append("valid subsequent transfer inherits clearance after ordinary maturity")
        # Rewind all clearance carriers and subsequent spends, then refresh.
        chain.daemon.request("/pop_blocks", {"nblocks": chain.tip() - snapshot})
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        assert chain.balance(1)["unlocked_balance"] == 0
        checks.append("reorg removes orphaned clearance")
        if args.full_stake:
            print(publish(complete), flush=True)
            chain.mine(1)
            _, inclusion = chain.transaction(stake["tx_hash"])
            payout_height = inclusion + 21601
            while chain.tip() < payout_height - 1:
                chain.mine(min(500, payout_height - 1 - chain.tip()), refresh=False)
                print("CLEARED_STAKE_WAIT", chain.tip(), payout_height, flush=True)
            for wallet in chain.wallets:
                chain.refresh_wallet(wallet)
            before = chain.balance(1)["unlocked_balance"]
            yield_rows = []
            for start in range(inclusion + 1, payout_height, 1000):
                yield_rows.extend(chain.daemon.call("get_yield_info", {"include_raw_data": True,
                    "from_height": start, "to_height": min(start + 999, payout_height - 1)})["yield_data"])
            assert all(row["locked_coins_tally"] == 12 * COIN for row in yield_rows)
            expected = 12 * COIN + sum(row["slippage_total_this_block"] for row in yield_rows)
            chain.mine(1)
            protocol = chain.block(payout_height)["protocol_tx"]
            assert len(protocol["vout"]) == 1 and protocol["vout"][0]["amount"] == expected
            assert chain.balance(1)["unlocked_balance"] == before
            chain.mine(60)
            assert chain.balance(1)["unlocked_balance"] == before + expected
            rows = chain.outputs(1)
            payout = [r for r in rows if r["block_height"] == payout_height and r["amount"] == expected]
            assert len(payout) == 1
            image = payout[0]["key_image"]
            for row in rows:
                if not row["spent"] and row["key_image"] != image:
                    chain.wallets[1].call("freeze", {"key_image": row["key_image"]})
            payout_spend = chain.transfer(1, 2, expected // 2, relay=False)
            chain.submit(payout_spend, True); chain.mine(1)
            transaction, _ = chain.transaction(payout_spend["tx_hash"])
            assert [i["key"]["k_image"] for i in transaction["vin"]] == [image]
            checks.append("cleared pre-activation stake principal pays exact yield, matures and payout itself spends without another audit")
        result = {"passed": True, "checks": checks, "fixture": str(root)}
        (root / "result.json").write_text(json.dumps(result, indent=2))
        print("AUDIT_CLEARANCE_REGTEST_PASS", json.dumps(result), flush=True)
    finally:
        chain.close()


if __name__ == "__main__":
    main()
