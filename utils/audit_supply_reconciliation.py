#!/usr/bin/env python3
"""Reconcile a complete native chain inventory with authenticated owner balances.

Run privately. Historical output face values, clearance counts and wallet coverage
claims are never used as circulating supply. No certificate is signed or published.
"""
import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile

from historical_audit_report import SCHEMA, amount, ingest, load, digest


def reconcile(db, context, complete, cases, witnesses=None):
    errors = []
    totals = defaultdict(lambda: defaultdict(int))
    source_assets = set()
    if complete.get("cryptographic_failures") != 0:
        errors.append("Canonical transaction cryptography did not pass")
    for data, in db.execute("SELECT data FROM accounting"):
        row = load(data)
        asset = row["reward_asset"]
        totals[asset]["authorized_emission"] += amount(row["base_reward_atomic"])
        totals[asset]["treasury_mint"] += amount(row["treasury_mint_atomic"])
        totals[asset]["reward_reserve_allocated"] += amount(row["stake_reserve_atomic"])
        totals[asset]["fees_distributed_to_miners_and_reserve"] += amount(row["fees_atomic"])
        if row["verification"] != "PASS":
            errors.append("Unresolved canonical monetary authorization")
    for data, in db.execute("SELECT data FROM outputs"):
        row = load(data)
        asset = row["asset"]
        totals[asset]["canonical_outputs"] += 1
        if row["structural_status"] != "PASS" or row["monetary_status"] != "PASS":
            errors.append("Unresolved or disqualifying canonical output")
        if row["category"] in ("MINER", "PROTOCOL"):
            value = amount(row["public_amount_atomic"])
            if value is None:
                errors.append("Missing public issuance value")
            else:
                totals[asset]["miner_outputs" if row["category"] == "MINER" else "protocol_outputs"] += value
    for data, in db.execute("SELECT data FROM transactions"):
        row = load(data)
        if row["category"] in ("MINER", "PROTOCOL"):
            continue
        asset = row["source_asset"]
        source_assets.add(asset)
        value = amount(row["amount_burnt_atomic"])
        fee = amount(row["fee_atomic"])
        if row["version"] >= 5 and asset != "SAL1":
            fee = 0  # The separate SAL1 rollup funds this transaction's fee.
        totals[asset]["fees_removed_from_inputs"] += fee
        totals[asset]["value_removed_from_outputs"] += value
        if row["category"] == "STAKE":
            totals[asset]["stake_principal_deposited"] += value
        elif row["category"] in ("BURN", "CREATE_TOKEN"):
            totals[asset]["permanent_burns"] += value
        elif row["category"] in ("AUDIT", "CONVERT"):
            totals[asset]["conversion_source_retired"] += value
        elif row["category"] == "ROLLUP":
            totals[asset]["prepaid_fee_escrow"] += value
        elif row["category"] != "TRANSFER" or value:
            errors.append("Unsupported monetary transaction")
        if (row["crypto_status"] != "PASS" or row["rules_status"] != "PASS" or
                row["duplicate_key_image"] != "no" or row["cross_asset_origin"] != "no"):
            errors.append("Unresolved or disqualifying canonical transaction")
    authorizations = set()
    for data, in db.execute("SELECT data FROM payouts"):
        row = load(data)
        if row["verification"] != "PASS" or row["authorization"] in authorizations:
            errors.append("Invalid or duplicate protocol authorization")
            continue
        authorizations.add(row["authorization"])
        asset = row["asset"]
        value = amount(row["actual_atomic"])
        if row["source_type"] == 6:
            principal = amount(row["principal_atomic"])
            totals[row["source_asset"]]["stake_principal_returned"] += principal
            totals[asset]["staking_rewards_paid"] += value - principal
            if principal > value or row["source_asset"] != asset:
                errors.append("Inconsistent stake return")
        elif row["source_type"] == 9:
            totals[asset]["token_creation"] += value
        else:
            totals[asset]["conversion_destination_issued"] += value
    for asset, data in db.execute("SELECT asset,data FROM stored_supply"):
        if asset not in ("BURN", "STAKE"):
            totals[asset]["database_circulating_supply"] = amount(load(data)["amount_atomic"])
    # Authenticate cases before calling this function. A duplicated proof or
    # resubmitted wallet must never multiply its economic balance.
    identities = {}
    owner_rows = {}
    bound = ("network", "genesis", "snapshot_height", "snapshot_hash")
    expected = (context["network"], context["genesis"], context["scan_end_height"],
                context["ending_block_hash"])
    for case in cases:
        if tuple(case.get(k) for k in bound) != expected:
            raise ValueError("Owner evidence and canonical inventory have different snapshots")
        if case.get("coverage") != "SUBMITTED_OUTPUTS_ONLY":
            raise ValueError("Unsupported owner evidence coverage")
        for row in case["outputs"]:
            identity = (row["transaction"], row["output_index"], row["stake"])
            if type(row["spent"]) is not bool or type(row["stake"]) is not bool:
                raise ValueError("Invalid owner spend status")
            value = amount(row["amount"])
            normalized = (row["asset_type"], value, row["spent"])
            if identity in identities:
                if identities[identity] != normalized:
                    raise ValueError("Conflicting authenticated ownership evidence")
                continue
            identities[identity] = normalized
            owner_rows[identity] = row
            if row["stake"]:
                found = db.execute("SELECT data FROM transactions WHERE id=?", (identity[0],)).fetchone()
                if not found:
                    raise ValueError("Owner stake is absent from canonical inventory")
                tx = load(found[0])
                if (identity[1] != 0 or tx["category"] != "STAKE" or
                        tx["source_asset"] != row["asset_type"] or amount(tx["amount_burnt_atomic"]) != value):
                    raise ValueError("Owner stake differs from canonical principal")
            else:
                found = db.execute("SELECT data FROM outputs WHERE tx=? AND idx=?", identity[:2]).fetchone()
                if not found or load(found[0])["asset"] != row["asset_type"]:
                    raise ValueError("Owner output is absent from canonical asset inventory")
            if not row["spent"]:
                key = "owner_locked_stake" if row["stake"] else "owner_output_balances"
                totals[row["asset_type"]][key] += value
    # Exact owner proofs can account for every actual key image without
    # guessing which ring decoy was spent. If all spends are thus covered,
    # remaining public issuance (including treasury rewards) is provably
    # unspent. A private balance omission still fails the amount reconciliation.
    images = {}
    for index in witnesses or []:
        for row in index.get("outputs", []):
            identity = (row["transaction"], row["output_index"], False)
            if identity not in identities:
                raise ValueError("Spend witness is outside authenticated owner reports")
            image = row["image"]
            if image in images and images[image] != identity:
                raise ValueError("Ambiguous ownership key image")
            images[image] = identity
    all_spends_accounted = witnesses is not None
    inputs_checked = 0
    for data, in db.execute("SELECT data FROM transactions"):
        row = load(data)
        if row["category"] in ("MINER", "PROTOCOL"):
            continue
        encoded = row.get("key_images")
        if not isinstance(encoded, str) or len(encoded) != row.get("inputs", -1) * 64:
            all_spends_accounted = False
            continue
        for offset in range(0, len(encoded), 64):
            identity = images.get(encoded[offset:offset + 64])
            if (identity is None or not owner_rows[identity]["spent"] or
                    owner_rows[identity]["asset_type"] != row["source_asset"]):
                all_spends_accounted = False
            else:
                inputs_checked += 1
    if all_spends_accounted:
        if db.execute("""SELECT 1 FROM outputs GROUP BY json_extract(data,'$.public_key')
            HAVING COUNT(*)>1 LIMIT 1""").fetchone():
            errors.append("Duplicate output keys prevent unambiguous global spend accounting")
            all_spends_accounted = False
        else:
            for tx, idx, data in db.execute("SELECT tx,idx,data FROM outputs WHERE category IN ('MINER','PROTOCOL')"):
                if (tx, idx, False) not in identities:
                    row = load(data)
                    totals[row["asset"]]["public_unspent_issuance"] += amount(row["public_amount_atomic"])
    # An asset with no spending inputs has only untouched public issuance.
    # This accounts for the fixed legacy genesis output in isolated fakechains
    # without inventing a private owner or a clearance for unsupported SAL.
    for asset, values in totals.items():
        if not all_spends_accounted and asset not in source_assets:
            values["public_unspent_issuance"] = values["miner_outputs"] + values["protocol_outputs"]
            # Do not count an owner's proof of that same public issuance twice.
            values["public_unspent_issuance"] -= values["owner_output_balances"]
        values["circulating_output_supply"] = (values["miner_outputs"] + values["protocol_outputs"] -
            values["fees_removed_from_inputs"] - values["value_removed_from_outputs"])
        values["locked_stake_principal"] = values["stake_principal_deposited"] - values["stake_principal_returned"]
        values["outstanding_supply_including_stakes"] = values["circulating_output_supply"] + values["locked_stake_principal"]
        values["unpaid_reward_reserve"] = values["reward_reserve_allocated"] - values["staking_rewards_paid"]
        values["owner_reconciliation_difference"] = values["circulating_output_supply"] - (
            values["owner_output_balances"] + values["public_unspent_issuance"])
        values["stake_reconciliation_difference"] = values["locked_stake_principal"] - values["owner_locked_stake"]
        values["emission_reconciliation_difference"] = (values["miner_outputs"] + values["reward_reserve_allocated"] -
            values["authorized_emission"] - values["treasury_mint"] - values["fees_distributed_to_miners_and_reserve"])
        values["unallocated_fee_escrow"] = values["fees_removed_from_inputs"] + values["prepaid_fee_escrow"] - values["fees_distributed_to_miners_and_reserve"]
        values["accounted_existing_value_with_fee_escrow"] = values["outstanding_supply_including_stakes"] + values["unallocated_fee_escrow"]
        # Retired SAL was settled by the accepted SAL-to-SAL1 audit. Keep
        # its historical movements as context; current SAL ownership is not
        # an enrollment or circulating-supply prerequisite for SAL1/tokens.
        if asset == "SAL":
            continue
        if values["owner_reconciliation_difference"] or values["stake_reconciliation_difference"]:
            errors.append("Incomplete authenticated owner balance reconciliation: " + asset)
        if values["emission_reconciliation_difference"]:
            errors.append("Emission schedule does not reconcile: " + asset)
        if min(values["circulating_output_supply"], values["locked_stake_principal"],
               values["unpaid_reward_reserve"], values["public_unspent_issuance"],
               values["unallocated_fee_escrow"]) < 0:
            errors.append("Negative monetary stock or reward reserve: " + asset)
        if ("database_circulating_supply" in values and
                values["database_circulating_supply"] != values["circulating_output_supply"]):
            errors.append("Database circulating tally differs from independent ledger: " + asset)
    return dict(status="PASS" if not errors else "FAIL", context=context,
        definition="Circulating supply is all current output value, including immature or audit-frozen outputs; "
                   "outstanding supply also includes locked stake principal. Prepaid but undistributed fees "
                   "are existing-value escrow. Scheduled unpaid rewards are separate from current output supply.",
        active_audit_assets=sorted(a for a in totals if a != "SAL"),
        legacy_conversion_context_assets=sorted(a for a in totals if a == "SAL"),
        scope="SAL1 and supported tokens; retired SAL is historical conversion accounting only, with no new enrollment",
        errors=sorted(set(errors)), unique_owner_identities=len(identities),
        all_actual_spends_bound_to_owner_proofs=all_spends_accounted,
        actual_inputs_with_authenticated_ownership=inputs_checked,
        assets={asset: {key: str(value) for key, value in sorted(values.items())}
                for asset, values in sorted(totals.items()) if asset != "SAL"},
        legacy_conversion_context={asset: {key: str(value) for key, value in sorted(values.items())}
                for asset, values in sorted(totals.items()) if asset == "SAL"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case", type=Path, nargs="+", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--wallet-evidence", type=Path, nargs="+",
                        help="Private proof packages for exact spend coverage and public treasury holdings")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.output.exists():
        raise ValueError("Choose a new private output file")
    cases = []
    witnesses = [] if args.wallet_evidence else None
    authenticated_hashes = []
    for path in args.case:
        # The native verifier checks the independent trusted authority and
        # signed amounts/spend flags. A report's own signer field is insufficient.
        result = subprocess.run([str(args.verifier.resolve()), "--report", str(path.resolve()),
            "--verify-key", args.authority], capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise ValueError("Owner report authentication failed")
        authenticated_hashes.append(result.stdout.split()[-1])
        cases.append(load(path.read_text()))
    with tempfile.TemporaryDirectory(prefix="salvium-supply-") as root:
        if witnesses is not None:
            for number, path in enumerate(args.case):
                index = Path(root) / f"ownership-{number}.json"
                result = subprocess.run([str(args.verifier.resolve()), "--report", str(path.resolve()),
                    "--verify-key", args.authority, "--ownership-index", str(index),
                    "--input", *[str(p.resolve()) for p in args.wallet_evidence]],
                    capture_output=True, text=True, timeout=300)
                if result.returncode:
                    raise ValueError("Private spend witnesses are not bound to the authenticated report")
                witness = load(index.read_text())
                if witness["report_hash"] != authenticated_hashes[number]:
                    raise ValueError("Private ownership index belongs to another report")
                witnesses.append(witness)
        db = sqlite3.connect(Path(root) / "inventory.sqlite3")
        try:
            db.executescript(SCHEMA)
            context, complete, counts, evidence_hash = ingest(args.evidence, db)
            report = reconcile(db, context, complete, cases, witnesses)
            report.update(native_evidence_sha256=evidence_hash, counts=counts,
                          authenticated_case_sha256=[digest(p) for p in args.case])
        finally:
            db.close()
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"], flush=True)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
