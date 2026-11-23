#!/usr/bin/env python3
"""Read-only canonical snapshot audit, proposed amnesty inventory and report bundle."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from historical_audit_report import digest, generate, load, write_json


def snapshot_info(binary, path):
    r = subprocess.run([str(binary), "--db-path", str(path), "--snapshot-info"],
                       check=True, capture_output=True, text=True)
    line = next(line for line in r.stdout.splitlines() if line.startswith("SNAPSHOT_INFO "))
    return dict(re.findall(r"(\w+)=([^ ]+)", line))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, default=Path("build/audit/release/bin/salvium-blockchain-verification"))
    parser.add_argument("--db-path", type=Path, required=True, help="Source LMDB directory; never opened for writing")
    parser.add_argument("--outdir", type=Path, required=True, help="Private local run directory")
    parser.add_argument("--use-existing-snapshot", action="store_true", help="Audit an existing immutable snapshot directly")
    parser.add_argument("--scan-start", type=int, default=169101, help="First newly audited height; opening is 169100 by default")
    parser.add_argument("--policy", type=Path, help="Optional proposed policy bound to the exact canonical snapshot")
    parser.add_argument("--resume", action="store_true", help="Reuse completed stages with matching source and binary fingerprints")
    parser.add_argument("--regtest", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.outdir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=args.resume)
    binary = args.verifier.resolve()
    source = args.db_path.resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    patch = subprocess.check_output(["git", "diff", "--binary", "HEAD"])
    (root / "source-working-tree.patch").write_bytes(patch)
    identity = dict(source_commit=commit, source_working_diff_sha256=digest(root / "source-working-tree.patch"),
                    verifier_sha256=digest(binary), source_database=str(source), scan_start=args.scan_start,
                    regtest=args.regtest)
    identity_path = root / "run_identity.json"
    if identity_path.exists() and load(identity_path.read_text()) != identity:
        raise ValueError("Run source, binary or scan boundary changed; choose a new run directory")
    write_json(identity_path, identity)
    if args.use_existing_snapshot:
        snapshot = source
    else:
        snapshot = root / "snapshot" / "lmdb"
        marker = root / "snapshot.complete.json"
        if not marker.exists():
            snapshot.mkdir(parents=True, exist_ok=False)
            with (root / "snapshot-copy.log").open("w") as log:
                subprocess.run([str(binary), "--db-path", str(source), "--copy-db", str(snapshot)],
                               check=True, stdout=log, stderr=subprocess.STDOUT)
            write_json(marker, snapshot_info(binary, snapshot))
    anchor = snapshot_info(binary, snapshot)
    if args.scan_start < 0 or args.scan_start > int(anchor["height"]):
        raise ValueError("Invalid audit starting height")
    write_json(root / "canonical_snapshot.json", anchor)
    native = root / "historical_evidence.jsonl"
    if not native.exists():
        command = [str(binary), "--db-path", str(snapshot), "--start-height", str(args.scan_start),
                   "--end-height", anchor["height"], "--historical-records", str(native), "--log-level", "0"]
        if args.regtest: command.append("--regtest")
        write_json(root / "native_command.json", command)
        print(f"SCANNING canonical_height={anchor['height']} hash={anchor['hash']}", flush=True)
        with (root / "native-scan.log").open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    # A partial export has no complete marker. The report generator rejects it
    # rather than silently treating an interrupted prefix as full coverage.
    if args.policy:
        policy = args.policy
    else:
        assets = {"SAL", "SAL1"}
        with native.open() as source_records:
            for raw in source_records:
                r = load(raw)
                if r["record_type"] == "output": assets.add(r["asset"])
        policy = root / "proposed_policy.json"
        write_json(policy, dict(network=3 if args.regtest else 0, genesis=anchor["genesis"],
            snapshot_height=int(anchor["height"]), snapshot_hash=anchor["hash"],
            historical_cutoff_height=int(anchor["height"]), policy_version="historical-amnesty-1-PROPOSED",
            eligible_assets=sorted(assets), deny_proven_illicit_funding=True,
            approved=False, production_activation_height=0,
            purchase_exception="Authenticated purchases require independent private verification; unavailable records alone never disqualify"))
    report = generate(native, policy, root / "reports", commit)
    write_json(root / "completed_run.json", dict(identity=identity, canonical_snapshot=anchor,
        native_evidence_sha256=report["native_evidence_sha256"], report_status=report["status"]))
    print(f"REPORT_BUNDLE {root / 'reports' / 'audit_final_summary.md'}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
