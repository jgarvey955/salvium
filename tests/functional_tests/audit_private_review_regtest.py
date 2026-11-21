#!/usr/bin/env python3
"""Native wallet export, cross-wallet verification, signed clearance and reorg revocation."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_gate_regtest import AuditChain, COIN
from audit_release_regtest import RpcError


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
        chain.wallets[2].call("create_address", {"account_index": account, "count": 1000})
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
        assert all(r["state"] == "CLEARED" for r in public_case["outputs"]), public_case
        assert any(r["reason"] == "ALL_RING_CANDIDATES_VERIFIED" for r in public_case["outputs"])
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
        newer = root / "newer"
        command("--report", complete / "case.json", "--revision", "3", "--sign-key", secret, "--outdir", newer)
        for wallet in chain.wallets:
            own = owned_receipts(newer, wallet)
            assert own
            for path in own:
                wallet.call("audit", {"review_result": path.read_text(), "developer_public_key": public})
            current = wallet.call("audit", {"status_only": True})
            assert all(r["state"] == "CLEARED" for r in current["outputs"]), current
        must_fail(lambda: chain.wallets[0].call("audit", {"review_result": receipts(pending)[0].read_text(), "developer_public_key": public}))
        # Persisted results are consumed by the real CLI entry point.
        bob.call("close_wallet")
        result = subprocess.run([str(bins / "salvium-wallet-cli"), "--config-file", str(root / "isolated.conf"),
            "--wallet-file", str(root / "bob/wallet"), "--password", "",
            "--shared-ringdb-dir", str(root / "bob/ringdb"), "--daemon-address", chain.daemon.url,
            "--daemon-ssl", "disabled", "--trusted-daemon", "--allow-mismatched-daemon-version",
            "--regtest-lineage-audit-height", str(chain.activation), "--log-file", str(root / "cli.log"),
            "--command", "audit"], input="", capture_output=True, text=True, timeout=180)
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
        summary = dict(status="PRIVATE_AUDIT_WALLET_PASS", snapshot=snapshot,
            checks=["native_rpc_private_exports", "cross_wallet_all_funding_clearance", "missing_owner_review",
                "immature_stake_review", "signed_developer_clearance", "forgery_rejection", "stale_revision_rejection",
                "recipient_isolation", "wallet_reopen_and_native_cli", "reorg_revokes_all_decisions"],
            note="1000 unused NonKYC subaddresses exercise scope discovery; this is not a 1000-funded-output capacity test")
        (root / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary), flush=True)
    finally:
        chain.close()


if __name__ == "__main__":
    main()
