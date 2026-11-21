#!/usr/bin/env python3
"""Native wallet export, cross-wallet verification, signed clearance and reorg revocation."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from audit_gate_regtest import AuditChain, COIN
from audit_release_regtest import Rpc, RpcError


def must_fail(call):
    try:
        call()
    except (RpcError, subprocess.CalledProcessError):
        return
    raise AssertionError("Invalid audit result was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, default=Path("build/audit/release/bin"))
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="salvium-private-review-"))
    print(root, flush=True)
    bins = root / "bin"
    bins.mkdir()
    for name in ("salviumd", "salvium-wallet-rpc", "salvium-wallet-cli", "salvium-audit-review"):
        shutil.copy2(args.binaries.resolve() / name, bins / name)
    chain = AuditChain(bins, root)
    tool = str(bins / "salvium-audit-review")

    def command(*arguments):
        result = subprocess.run([tool, *map(str, arguments)], capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result.stdout

    def receipts(folder):
        return [p for p in folder.glob("*.json") if p.name not in ("case.json", "review-queue.json")]

    def owned_receipts(folder, wallet):
        rows = wallet.call("audit", {"status_only": True})["outputs"]
        identities = {(r["transaction"], r["output_index"], r["stake"]) for r in rows}
        return [p for p in receipts(folder) if all((r["transaction"], r["output_index"], r["stake"]) in identities
            for r in json.loads(p.read_text())["outputs"])]

    def run_case(name, inputs, key=None, public_work_limit=0):
        folder = root / name
        params = ["--data-dir", root / "chain/fake", "--network", "fakechain", "--opening", "0",
            "--outdir", folder, "--public-work-limit", str(public_work_limit)]
        if key:
            params += ["--sign-key", key]
        params += ["--input", *inputs]
        print(name, command(*params).strip(), flush=True)
        return folder

    try:
        chain.launch()
        must_fail(lambda: Rpc(chain.wallets[2].port).call("audit", {"status_only": True}))
        chain.mine(100, fund_miner=True)
        funding = chain.transfer(0, 1, 50 * COIN, relay=False)
        assert chain.daemon.request("/send_raw_transaction", {"tx_as_hex": funding["tx_blob"], "do_not_relay": True})["status"] == "OK"
        chain.mine(11)
        sent = chain.transfer(1, 2, 10 * COIN, relay=False)
        assert chain.daemon.request("/send_raw_transaction", {"tx_as_hex": sent["tx_blob"], "do_not_relay": True})["status"] == "OK"
        chain.mine(11)
        stake = chain.transfer(1, 1, 12 * COIN, tx_type=6, relay=False)
        assert chain.daemon.request("/send_raw_transaction", {"tx_as_hex": stake["tx_blob"], "do_not_relay": True})["status"] == "OK"
        chain.mine(11)
        # All accounts are covered even when ordinary CLI scope is another account.
        account = chain.wallets[2].call("create_account", {"label": "NonKYC"})["account_index"]
        for offset in range(0, 1000, 64):
            chain.wallets[2].call("create_address", {"account_index": account, "count": min(64, 1000 - offset)})
        snapshot = chain.tip()
        evidence = []
        for number, wallet in enumerate(chain.wallets):
            result = wallet.call("audit", {"export_evidence": True, "snapshot_height": snapshot})
            request = json.loads(result["private_evidence"])
            assert request["version"] == 3 and request["packages"]
            assert all(p["network"] == 3 and p["snapshot_height"] == snapshot for p in request["packages"])
            assert all(not row["key_image"] for row in result["outputs"])
            path = root / f"wallet-{number}.json"
            path.write_text(result["private_evidence"])
            evidence.append(path)
        secret = root / "developer.key"
        public = command("--keygen", secret).strip().split()[-1]
        automatic = run_case("public-ancestry", evidence[2:], secret, public_work_limit=50000)
        public_case = json.loads((automatic / "case.json").read_text())
        assert public_case["public_outputs_checked"] > 0
        # Recent locked decoys can make public provenance insufficient to prove
        # actual funding maturity. Exact owner proofs below resolve that ambiguity.
        assert all(r["state"] in ("CLEARED", "REVIEW_REQUIRED") for r in public_case["outputs"]), public_case
        assert all(r["reason"] in ("ALL_RING_CANDIDATES_VERIFIED", "MISSING_FUNDING_EVIDENCE")
            for r in public_case["outputs"]), public_case
        pending = run_case("bob-alone", evidence[2:], secret)
        case = json.loads((pending / "case.json").read_text())
        assert case["outputs"] and all(r["state"] == "REVIEW_REQUIRED" for r in case["outputs"])
        assert all(r["reason"] == "MISSING_FUNDING_EVIDENCE" and r["recommendation"] == "DENY" for r in case["outputs"])
        bob = chain.wallets[2]
        for path in receipts(pending):
            bob.call("audit", {"review_result": path.read_text(), "developer_public_key": public})
        request = json.loads((pending / "review-queue.json").read_text())
        for item in request["decisions"]:
            item["action"] = "CLEAR"
            item["reason"] = "Controlled test: developer verified independent purchase records"
        decisions = root / "decisions.json"
        decisions.write_text(json.dumps(request))
        manual = root / "manual"
        command("--report", pending / "case.json", "--decisions", decisions, "--sign-key", secret, "--outdir", manual)
        for path in receipts(manual):
            report = json.loads(path.read_text())
            forged = copy.deepcopy(report)
            forged["outputs"][0]["amount"] += 1
            must_fail(lambda: bob.call("audit", {"review_result": json.dumps(forged), "developer_public_key": public}))
            bob.call("audit", {"review_result": path.read_text(), "developer_public_key": public})
        assert all(r["state"] == "CLEARED_BY_DEVELOPER" for r in bob.call("audit", {"status_only": True})["outputs"])
        for path in receipts(pending):
            must_fail(lambda: bob.call("audit", {"review_result": path.read_text(), "developer_public_key": public}))
        complete = run_case("all-owners", evidence, secret)
        case = json.loads((complete / "case.json").read_text())
        assert all(r["state"] == "CLEARED" for r in case["outputs"]), case
        assert any(r["stake"] for r in case["outputs"])
        must_fail(lambda: chain.wallets[0].call("audit", {
            "review_result": (complete / "case.json").read_text(), "developer_public_key": public}))
        for name, mutate in (
                ("unsigned-case", lambda r: r.update(signer="", signature="")),
                ("altered-case", lambda r: r["outputs"][0].update(amount=r["outputs"][0]["amount"] + 1)),
                ("invalid-recipient", lambda r: r["outputs"][0].update(package_id="invalid-package-identity"))):
            invalid = copy.deepcopy(case)
            mutate(invalid)
            invalid_path = root / (name + ".json")
            invalid_path.write_text(json.dumps(invalid))
            rejected_output = root / (name + "-rejected")
            rejected = subprocess.run([tool, "--report", str(invalid_path), "--sign-key", str(secret),
                "--outdir", str(rejected_output)], capture_output=True, text=True, timeout=30)
            assert rejected.returncode != 0 and not rejected_output.exists(), name
        repeated = json.loads(evidence[0].read_text())
        repeated["packages"][0]["proofs"].append(repeated["packages"][0]["proofs"][0])
        repeated_path = root / "repeated-evidence.json"
        repeated_path.write_text(json.dumps(repeated))
        rejected = subprocess.run([tool, "--data-dir", str(root / "chain/fake"), "--network", "fakechain",
            "--opening", "0", "--input", str(repeated_path), "--sign-key", str(secret),
            "--outdir", str(root / "repeated-evidence-rejected")], capture_output=True, text=True, timeout=30)
        assert rejected.returncode != 0 and not (root / "repeated-evidence-rejected").exists()
        custody = {json.loads(path.read_text())["outputs"][0]["package_id"]
            for path in owned_receipts(complete, chain.wallets[1])}
        reserve = sum({(r["transaction"], r["output_index"], r["stake"]): r["amount"]
            for r in case["outputs"] if r["package_id"] in custody and not r["spent"]}.values())
        ledger = {field: case[field] for field in ("network", "genesis", "snapshot_height", "snapshot_hash")}
        ledger.update(version=1, scope_complete=True, assets_in_scope=["SAL1"],
            custody_package_ids=sorted(custody), events=[], balances=[dict(account="test-exchange",
                asset="SAL1", opening_atomic=str(reserve), closing_atomic=str(reserve))])
        ledger_path = root / "synthetic-exchange-ledger.json"
        ledger_path.write_text(json.dumps(ledger))
        subprocess.run([sys.executable, str(Path(__file__).resolve().parents[2] / "utils/reconcile_nonkyc_audit.py"),
            "--case", str(complete / "case.json"), "--ledger", str(ledger_path), "--verifier", tool,
            "--developer-public-key", public, "--output", str(root / "reconciliation.json")], check=True)
        assert json.loads((root / "reconciliation.json").read_text())["status"] == "RECONCILED_FOR_HUMAN_REVIEW"
        newer = root / "newer"
        command("--report", complete / "case.json", "--revision", "3", "--sign-key", secret, "--outdir", newer)
        for wallet in chain.wallets:
            own = owned_receipts(newer, wallet)
            assert own
            for path in own:
                wallet.call("audit", {"review_result": path.read_text(), "developer_public_key": public})
            current = wallet.call("audit", {"status_only": True})
            assert all(r["state"] == "CLEARED" for r in current["outputs"]), current
        bob_rows = bob.call("audit", {"status_only": True})["outputs"]
        bob_keys = {(r["transaction"], r["output_index"], r["stake"]) for r in bob_rows}
        original = json.loads((newer / "case.json").read_text())
        changes = {"report_hash": command("--report", newer / "case.json", "--verify-key", public).split()[-1],
            "decisions": [{"package_id": r["package_id"], "transaction": r["transaction"],
                "output_index": r["output_index"], "stake": r["stake"], "action": "DENY",
                "reason": "Controlled test: developer records an adverse review decision"}
                for r in original["outputs"] if (r["transaction"], r["output_index"], r["stake"]) in bob_keys]}
        denied_decisions = root / "denied-decisions.json"
        denied_decisions.write_text(json.dumps(changes))
        denied = root / "denied"
        command("--report", newer / "case.json", "--decisions", denied_decisions, "--sign-key", secret, "--outdir", denied)
        for path in owned_receipts(denied, bob):
            bob.call("audit", {"review_result": path.read_text(), "developer_public_key": public})
        assert all(r["state"] == "DENIED_BY_DEVELOPER" for r in bob.call("audit", {"status_only": True})["outputs"])
        changes["report_hash"] = command("--report", denied / "case.json", "--verify-key", public).split()[-1]
        for row in changes["decisions"]:
            row.update(action="CLEAR", reason="Controlled test: developer verifies new exculpatory evidence")
        restored_decisions = root / "restored-decisions.json"
        restored_decisions.write_text(json.dumps(changes))
        restored = root / "restored"
        command("--report", denied / "case.json", "--decisions", restored_decisions, "--sign-key", secret, "--outdir", restored)
        for path in owned_receipts(restored, bob):
            bob.call("audit", {"review_result": path.read_text(), "developer_public_key": public})
        assert all(r["state"] == "CLEARED_BY_DEVELOPER" for r in bob.call("audit", {"status_only": True})["outputs"])
        must_fail(lambda: chain.wallets[0].call("audit", {"review_result": receipts(pending)[0].read_text(), "developer_public_key": public}))
        # Persisted results are consumed by the real CLI entry point.
        bob.call("close_wallet")
        cli_arguments = [str(bins / "salvium-wallet-cli"), "--config-file", str(root / "isolated.conf"),
            "--wallet-file", str(root / "bob/wallet"), "--password", "",
            "--shared-ringdb-dir", str(root / "bob/ringdb"), "--daemon-address", chain.daemon.url,
            "--daemon-ssl", "disabled", "--trusted-daemon", "--allow-mismatched-daemon-version",
            "--regtest-lineage-audit-height", str(chain.activation), "--log-file", str(root / "cli.log")]
        result = subprocess.run(cli_arguments + ["--command", "audit"], input="", capture_output=True, text=True, timeout=180)
        (root / "cli-output.txt").write_text(result.stdout + result.stderr)
        assert result.returncode == 0 and "CLEARED" in result.stdout, result.stderr + result.stdout
        bob.call("open_wallet", {"filename": "wallet", "password": ""})
        bob.call("auto_refresh", {"enable": False})
        old_hash = chain.daemon.call("get_block_header_by_height", {"height": snapshot})["block_header"]["hash"]
        chain.daemon.request("/pop_blocks", {"nblocks": 1})
        chain.mine(1)
        new_hash = chain.daemon.call("get_block_header_by_height", {"height": snapshot})["block_header"]["hash"]
        assert old_hash != new_hash
        revoked = bob.call("audit", {"status_only": True})
        assert all(r["state"] == "REVIEW" for r in revoked["outputs"]), revoked
        for path in owned_receipts(newer, bob):
            must_fail(lambda: bob.call("audit", {"review_result": path.read_text(), "developer_public_key": public}))
        bob.call("close_wallet")
        cli_export = root / "cli-request.json"
        result = subprocess.run(cli_arguments + ["--command", "audit", "export", str(cli_export), str(chain.tip())],
            input="", capture_output=True, text=True, timeout=180)
        (root / "cli-export-output.txt").write_text(result.stdout + result.stderr)
        assert result.returncode == 0 and cli_export.is_file(), result.stdout + result.stderr
        assert cli_export.stat().st_mode & 0o077 == 0
        current_parent_evidence = []
        for number, wallet in enumerate(chain.wallets[:2]):
            result = wallet.call("audit", {"export_evidence": True, "snapshot_height": chain.tip()})
            path = root / f"current-parent-{number}.json"
            path.write_text(result["private_evidence"])
            current_parent_evidence.append(path)
        cli_case = run_case("cli-owner-request", [cli_export, *current_parent_evidence], secret)
        bob_identities = {(r["transaction"], r["output_index"], r["stake"]) for r in revoked["outputs"]}
        cli_package_ids = {r["package_id"] for r in json.loads((cli_case / "case.json").read_text())["outputs"]
            if (r["transaction"], r["output_index"], r["stake"]) in bob_identities}
        cli_receipts = [path for path in receipts(cli_case) if path.stem in cli_package_ids]
        assert cli_receipts
        for path in cli_receipts:
            result = subprocess.run(cli_arguments + ["--command", "audit", "import", str(path), public],
                input="", capture_output=True, text=True, timeout=180)
            (root / "cli-import-output.txt").write_text(result.stdout + result.stderr)
            assert result.returncode == 0 and "CLEARED" in result.stdout, result.stdout + result.stderr
        summary = dict(status="PRIVATE_AUDIT_WALLET_PASS", snapshot=snapshot,
            checks=["native_rpc_private_exports", "cross_wallet_all_funding_clearance", "missing_owner_review",
                "immature_stake_review", "signed_developer_clearance", "forgery_rejection", "stale_revision_rejection",
                "recipient_isolation", "wallet_reopen_and_native_cli", "reorg_revokes_all_decisions",
                "native_nonkyc_signature_reconciliation", "native_cli_owner_export_and_signed_import",
                "authenticated_case_revision", "invalid_recipient_and_duplicate_evidence_rejection",
                "unauthenticated_rpc_rejection", "signed_denial_and_later_reasoned_clearance"],
            note="1000 unused NonKYC subaddresses exercise scope discovery; this is not a 1000-funded-output capacity test")
        (root / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary), flush=True)
    finally:
        chain.close()


if __name__ == "__main__":
    main()
