#!/usr/bin/env python3
"""Full-owner private audit versus independent canonical issuance conservation."""
import copy
import json
from pathlib import Path
import subprocess
import sys



def verify_index_aggregation(tool, case_path, public, inputs, root):
    """Native per-case limits must support a larger shared owner collection."""
    import stat
    root.mkdir(exist_ok=True)
    baseline = root / "index-baseline.json"

    def run(paths, output, success=True):
        result = subprocess.run([str(tool), "--report", str(case_path), "--verify-key", public,
            "--ownership-index", str(output), "--input", *map(str, paths)],
            capture_output=True, text=True, timeout=300)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        assert output.exists() == success
        if success:
            assert not (stat.S_IMODE(output.stat().st_mode) & 0o077)
            return json.loads(output.read_text())

    expected = run(inputs, baseline)
    duplicate = run([*inputs, *inputs], root / "index-repeated.json")
    assert duplicate == expected
    package = copy.deepcopy(json.loads(inputs[0].read_text())["packages"][0])
    # A separate same-snapshot package is unrelated to this signed case.
    package["nonce"] = "00" * 32 if package["nonce"] != "00" * 32 else "01" * 32
    package["proofs"] = package["proofs"][:1]
    unrelated = root / "unrelated-owners.json"
    unrelated.write_text(json.dumps(dict(version=3, packages=[package] * 2300)))
    aggregated = run([unrelated, *inputs, unrelated], root / "index-shared-collection.json")
    assert aggregated == expected
    excessive = root / "oversized-request.json"
    excessive.write_text(json.dumps(dict(version=3, packages=[package] * 4097)))
    run([*inputs, excessive], root / "index-oversized.json", False)
    run([], root / "index-missing.json", False)
    return ["native private index is idempotent and owner-readable only",
            "shared collections above 4096 total packages preserve exact per-case ownership",
            "oversized individual requests and missing evidence fail without an index"]


def verify_supply(chain, tool, public, secret, root, required_assets=("SAL1", "salYAHU"), cached=None):
    root.mkdir(exist_ok=True)
    snapshot = chain.tip()
    checks, evidence, balances = [], [], {}
    chain.observer.call("open_wallet", {"filename": "mining-sink", "password": ""})
    owners = [*chain.wallets, chain.observer]
    for index, wallet in enumerate(owners):
        chain.refresh_wallet(wallet)
        if cached:
            request = json.loads((cached / f"supply-owner-{index}.json").read_text())
        else:
            response = wallet.call("audit", {"export_evidence": True, "snapshot_height": snapshot})
            request = json.loads(response["private_evidence"])
            while response["evidence_more"]:
                response = wallet.call("audit", {"export_evidence": True, "snapshot_height": snapshot,
                    "export_id": response["export_id"], "evidence_offset": response["next_evidence_offset"]})
                request["packages"].extend(json.loads(response["private_evidence"])["packages"])
        path = root / f"supply-owner-{index}.json"
        path.write_text(json.dumps(request))
        evidence.append(path)
        rows = wallet.call("get_balance", {"all_accounts": True, "all_assets": True})
        for row in rows.get("balances", []):
            asset = row["asset_type"]
            balances[asset] = balances.get(asset, 0) + row["balance"]
    chain.observer.call("close_wallet")

    def review(inputs, folder, success=True):
        command = [str(tool), "--network", "fakechain", "--data-dir", str(chain.root / "chain/fake"),
            "--opening", "0", "--activation-height", "0", "--public-work-limit", "0",
            "--input", *map(str, inputs), "--sign-key", str(secret), "--outdir", str(folder)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        (root / (folder.name + ".log")).write_text(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        return folder / "case.json"

    if cached:
        full = root / "supply-all-owners.json"
        full.write_text((cached / "supply-all-owners/case.json").read_text())
        authenticated = subprocess.run([str(tool), "--report", str(full), "--verify-key", public],
                                       capture_output=True, text=True, timeout=300)
        assert authenticated.returncode == 0, "Cached native owner report is not authentic"
    else:
        full = review(evidence, root / "supply-all-owners")
    case = json.loads(full.read_text())
    assert case["snapshot_height"] == snapshot
    assert case["snapshot_hash"] == chain.daemon.call("get_block_header_by_height",
        {"height": snapshot})["block_header"]["hash"]
    assert all(row["state"] == "CLEARED" and not row["decision"] for row in case["outputs"])
    amounts = {}
    seen = set()
    for row in case["outputs"]:
        identity = row["transaction"], row["output_index"], row["stake"]
        if row["spent"] or identity in seen:
            continue
        seen.add(identity)
        asset = row["asset_type"]
        amounts[asset] = amounts.get(asset, 0) + row["amount"]
    assert {a: v for a, v in amounts.items() if v} == {a: v for a, v in balances.items() if v}, (amounts, balances)
    checks.append("all native-authenticated owner balances exactly equal all-account all-asset wallet balances, including the mining sink")
    print("FULL_OWNER_BALANCES_PASS", json.dumps(balances), flush=True)
    canonical = root / "supply-canonical.jsonl"
    verifier = chain.binaries / "salvium-blockchain-verification"
    with (root / "supply-canonical.log").open("w") as log:
        result = subprocess.run([str(verifier), "--db-path", str(chain.root / "chain/fake/lmdb"),
            "--regtest", "--start-height", "1", "--end-height", str(snapshot),
            "--historical-records", str(canonical), "--log-level", "0"],
            stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    assert result.returncode == 0, "Canonical native supply validation failed; inspect private log"
    script = Path(__file__).resolve().parents[2] / "utils/audit_supply_reconciliation.py"

    def reconcile(cases, name, success=True, writes=True, witness_inputs=None):
        output = root / (name + ".json")
        result = subprocess.run([sys.executable, str(script), "--evidence", str(canonical),
            "--case", *map(str, cases), "--verifier", str(tool), "--authority", public,
            "--wallet-evidence", *map(str, evidence if witness_inputs is None else witness_inputs),
            "--output", str(output)], capture_output=True, text=True, timeout=600)
        (root / (name + ".log")).write_text(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        if not writes:
            assert not output.exists()
            return None
        report = json.loads(output.read_text())
        assert (report["status"] == "PASS") == success, report["errors"]
        return report

    supply = reconcile([full], "supply-complete")
    for asset, value in balances.items():
        assert int(supply["assets"][asset]["outstanding_supply_including_stakes"]) == (
            value + int(supply["assets"][asset]["public_unspent_issuance"]))
        assert supply["assets"][asset]["owner_reconciliation_difference"] == "0"
        assert supply["assets"][asset]["stake_reconciliation_difference"] == "0"
    assert set(required_assets) <= set(supply["active_audit_assets"])
    assert "SAL" not in supply["active_audit_assets"]
    checks.append("every required asset independently reconciles canonical issuance, fees, burns, staking and circulating output supply")
    assert supply["all_actual_spends_bound_to_owner_proofs"]
    checks.append("every actual spend is bound to authenticated ownership; untouched public treasury rewards are included")
    duplicate = reconcile([full, full], "supply-idempotent-repeat")
    assert duplicate["assets"] == supply["assets"]
    checks.append("repeated owner submissions do not multiply circulating supply")
    missing = review(evidence[1:3], root / "supply-missing-miner-and-sink")
    incomplete = reconcile([missing], "supply-incomplete-owner-coverage", False)
    assert any("owner balance reconciliation" in error for error in incomplete["errors"])
    checks.append("known incomplete owner coverage fails full circulating supply verification")
    altered = copy.deepcopy(case)
    altered["outputs"][0]["amount"] += 1
    path = root / "supply-altered-owner-amount.json"
    path.write_text(json.dumps(altered))
    reconcile([path], "supply-unauthenticated-amount", False, False)
    checks.append("altered signed balance fails native authentication")
    bad_request = json.loads(evidence[1].read_text())
    bad_request["packages"][0]["snapshot_height"] -= 1
    path = root / "supply-orphaned-owner-context.json"
    path.write_text(json.dumps(bad_request))
    review([path], root / "supply-invalid-snapshot", False)
    checks.append("owner evidence with a mismatched snapshot fails native verification")
    bad_request = json.loads(evidence[1].read_text())
    proof = bytearray.fromhex(bad_request["packages"][0]["proofs"][0])
    proof[-1] ^= 1
    bad_request["packages"][0]["proofs"][0] = proof.hex()
    path = root / "supply-invalid-owner-proof.json"
    path.write_text(json.dumps(bad_request))
    review([path], root / "supply-invalid-proof", False)
    reconcile([full], "supply-unbound-spend-witness", False, False,
              [evidence[0], path, *evidence[2:]])
    checks.append("invalid ownership proof fails native verification without affecting known-good owners")
    checks.append("changed private spend witnesses cannot authenticate against a valid owner report")
    checks.extend(verify_index_aggregation(tool, full, public, evidence, root / "index-regressions"))
    print("FULL_FAKECHAIN_SUPPLY_PASS", flush=True)
    return dict(status="PASS", snapshot=snapshot, assets=supply["assets"], checks=checks,
                report=str(root / "supply-complete.json"))


def main():
    import argparse
    import hashlib
    import shutil
    import tempfile
    from audit_clearance_regtest import PrivateChain
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True,
                        help="Copy a funded exchange/subaddress fixture with completed native owner proofs")
    args = parser.parse_args()
    source, bins = args.fixture.resolve(), args.binaries.resolve()
    assert source.name.startswith("salvium-exchange-subaddresses-")
    signed = json.loads((source / "supply-all-owners/case.json").read_text())
    activation = json.loads((source / "owner-1.json").read_text())["packages"][0]["snapshot_height"]
    root = Path(tempfile.mkdtemp(prefix="salvium-supply-ownership-"))
    print(root, flush=True)
    for name in ("chain", "miner", "alice", "bob", "observer"):
        shutil.copytree(source / name, root / name)
    secret = root / "developer.key"
    shutil.copy2(source / "developer.key", secret)
    chain = PrivateChain(bins, root)
    chain.activation, chain.authority = activation, signed["signer"]
    try:
        chain.launch()
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        result = verify_supply(chain, bins / "salvium-audit-review", chain.authority, secret, root, cached=source)
        result.update(fixture=str(root), source_fixture=str(source), cached_native_owner_proofs=True,
            binary_sha256={name: hashlib.sha256((bins / name).read_bytes()).hexdigest()
                           for name in ("salviumd", "salvium-wallet-rpc", "salvium-audit-review")})
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print("AUDIT_FULL_SUPPLY_PASS", json.dumps(result), flush=True)
    finally:
        chain.close()


if __name__ == "__main__":
    main()
