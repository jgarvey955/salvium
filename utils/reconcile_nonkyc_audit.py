#!/usr/bin/env python3
"""Private NonKYC ledger reconciliation; recommendations always require developer signature."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def load_json(raw):
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON field: {key}")
            result[key] = value
        return result
    def invalid_number(value):
        raise ValueError(f"Invalid JSON number: {value}")
    return json.loads(raw, object_pairs_hook=unique_fields, parse_constant=invalid_number)


def atomic(value):
    # Never round exchange finance data through a float.
    if not isinstance(value, str) or not value or value in ("-", "+"):
        raise ValueError("Atomic amounts must be decimal integer strings")
    parsed = int(value)
    if str(parsed) != value or abs(parsed) > 2**64 - 1:
        raise ValueError("Invalid or overflowing atomic amount")
    return parsed


def reconcile(case, ledger, case_hash, ledger_hash):
    for source in (case, ledger):
        if type(source["network"]) is not int or source["network"] not in range(4) or \
                type(source["snapshot_height"]) is not int or not 0 <= source["snapshot_height"] < 2**64:
            raise ValueError("Invalid native network or snapshot height")
    for field in ("genesis", "network", "snapshot_height", "snapshot_hash"):
        if case[field] != ledger[field]:
            raise ValueError(f"NonKYC {field} differs from the native audit snapshot")
    if ledger.get("version") != 1:
        raise ValueError("Unsupported NonKYC reconciliation format")
    scope = set(ledger["assets_in_scope"])
    if not scope or len(scope) != len(ledger["assets_in_scope"]):
        raise ValueError("Declare unique native assets in reconciliation scope")
    errors, warnings, purchase_review_warnings = [], [], []
    if ledger.get("scope_complete") is not True:
        errors.append("Exchange has not declared complete ledger and custody scope")
    balances, liabilities = {}, defaultdict(int)
    for row in ledger["balances"]:
        if row["asset"] not in scope:
            raise ValueError("Balance asset is outside declared scope")
        identity = row["account"], row["asset"]
        if identity in balances:
            raise ValueError("Duplicate account/asset closing balance")
        opening, closing = atomic(row["opening_atomic"]), atomic(row["closing_atomic"])
        if opening < 0 or closing < 0:
            raise ValueError("Negative customer balances require separate review")
        balances[identity] = [opening, closing]
        liabilities[row["asset"]] += closing
    output_map = {}
    reserves = defaultdict(int)
    owned = set(ledger["custody_package_ids"])
    for row in case["outputs"]:
        if type(row["amount"]) is not int or not 0 <= row["amount"] < 2**64 or \
                type(row["output_index"]) is not int or not 0 <= row["output_index"] < 2**32 or \
                type(row["stake"]) is not bool or type(row["spent"]) is not bool:
            raise ValueError("Noncanonical native output fields")
        key = row["transaction"], row["output_index"], row["stake"]
        if key in output_map:
            prior = output_map[key]
            if (prior["amount"], prior["asset_type"], prior["spent"]) != (row["amount"], row["asset_type"], row["spent"]):
                raise ValueError("Conflicting canonical output in native audit case")
        else:
            output_map[key] = row
        # Multiple proofs of the same output never create additional reserves.
    custody_keys = set()
    for row in case["outputs"]:
        key = row["transaction"], row["output_index"], row["stake"]
        if row["package_id"] in owned and row["asset_type"] in scope and not row["spent"] and key not in custody_keys:
            custody_keys.add(key)
            reserves[row["asset_type"]] += row["amount"]
            if row["reason"] in {"CONFIRMED_MALFORMED_ORIGIN", "INVALID_ISSUANCE_OR_TRANSACTION",
                                  "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW", "PREMATURE_FUNDING"}:
                warnings.append("Custody includes an output with a confirmed defect or illicit funding exposure")
    if not owned or owned - {row["package_id"] for row in case["outputs"]}:
        errors.append("A declared custody package is missing from the native case")
    running = {key: value[0] for key, value in balances.items()}
    seen, trade_groups = set(), defaultdict(lambda: defaultdict(int))
    eligible_receipts = set()
    matched_deposits = set()
    matched_withdrawals = set()
    purchased = defaultdict(int)
    for event in ledger["events"]:
        if event["id"] in seen:
            raise ValueError("Duplicate exchange ledger event ID")
        seen.add(event["id"])
        key = event["account"], event["asset"]
        if key not in running:
            raise ValueError("Ledger event belongs to an undeclared account/asset")
        delta = atomic(event["delta_atomic"])
        kind = event["kind"]
        if kind not in {"deposit", "withdrawal", "trade", "fee", "internal", "adjustment"}:
            raise ValueError("Unknown NonKYC ledger event kind")
        if kind == "deposit" and delta <= 0 or kind in {"withdrawal", "fee"} and delta >= 0:
            raise ValueError("Ledger event has an invalid direction")
        running[key] += delta
        purchased_before = purchased[key]
        if running[key] < 0:
            errors.append(f"Negative running balance after event {event['id']}")
        if kind in {"trade", "internal"}:
            trade_groups[(kind, event["group"])][event["asset"]] += delta
        if kind == "trade":
            purchased[key] = max(0, purchased[key] + delta)
        elif delta < 0:
            purchased[key] = max(0, purchased[key] + delta)
        if kind == "adjustment":
            warning = f"Manual adjustment {event['id']} requires developer review"
            warnings.append(warning)
            purchase_review_warnings.append(warning)
        if kind in {"deposit", "withdrawal"}:
            receipt = event["transaction"], event["output_index"], False
            proof = output_map.get(receipt)
            if not proof or proof["asset_type"] != event["asset"] or proof["amount"] != abs(delta):
                errors.append(f"Missing exact receipt/amount evidence for {event['id']}")
                continue
            if kind == "deposit":
                if receipt in matched_deposits:
                    errors.append(f"Deposit output credited more than once: {event['id']}")
                matched_deposits.add(receipt)
                if not any(row["package_id"] in owned and (row["transaction"], row["output_index"], row["stake"]) == receipt
                           for row in case["outputs"]):
                    errors.append(f"Deposit {event['id']} is not proven exchange custody")
            elif event.get("acquisition") == "market_purchase" and purchased_before >= abs(delta):
                # A verified purchase establishes the recipient's clearance
                # basis; it does not rewrite the original issuance history.
                eligible_receipts.add(receipt)
            elif event.get("acquisition") == "market_purchase":
                errors.append(f"Market purchase does not cover withdrawal {event['id']}")
            if kind == "withdrawal":
                if receipt in matched_withdrawals:
                    errors.append(f"Withdrawal output debited more than once: {event['id']}")
                matched_withdrawals.add(receipt)
    for group, assets in trade_groups.items():
        if any(value != 0 for value in assets.values()):
            errors.append(f"Unbalanced trade/internal group {group}")
    for key, (opening, closing) in balances.items():
        if running[key] != closing:
            errors.append(f"Closing ledger mismatch for {key[0]}/{key[1]}")
    equity = {}
    for row in ledger.get("exchange_equity", []):
        if row["asset"] not in scope:
            raise ValueError("Equity asset is outside declared scope")
        if row["asset"] in equity:
            raise ValueError("Duplicate exchange equity asset")
        equity[row["asset"]] = atomic(row["amount_atomic"])
        if equity[row["asset"]] < 0:
            errors.append(f"Negative exchange equity for {row['asset']}")
    reconciliation = []
    for asset in sorted(scope):
        difference = reserves[asset] - liabilities[asset] - equity.get(asset, 0)
        reconciliation.append({"asset": asset, "reserves_atomic": str(reserves[asset]),
            "customer_liabilities_atomic": str(liabilities[asset]),
            "exchange_equity_atomic": str(equity.get(asset, 0)), "difference_atomic": str(difference)})
        if difference:
            errors.append(f"Unreconciled custody difference for {asset}: {difference}")
    decisions = []
    for row in case["outputs"]:
        if row["state"] != "REVIEW_REQUIRED" or row.get("decision"):
            continue
        identity = row["transaction"], row["output_index"], row["stake"]
        recommend_clear = (not errors and not purchase_review_warnings and identity in eligible_receipts)
        action = "CLEAR" if recommend_clear else "DENY"
        reason = (f"NonKYC records reconcile a market purchase; original finding retained: {row['reason']}. "
                  "Automatic signing requires independently authenticated exchange records. " if recommend_clear else
                  f"Retain review: {row['reason']}; reconciliation errors={len(errors)}, warnings={len(warnings)}. ")
        decisions.append({"package_id": row["package_id"], "transaction": row["transaction"],
            "output_index": row["output_index"], "stake": row["stake"], "action": action,
            "reason": reason + f"NonKYC evidence sha256={ledger_hash}"})
    return {"version": 1, "status": "RECONCILED_FOR_HUMAN_REVIEW" if not errors else "RECONCILIATION_FAILED",
        "ledger_sha256": ledger_hash, "errors": errors, "warnings": warnings,
        "purchase_review_warnings": purchase_review_warnings,
        "per_asset": reconciliation, "developer_decisions": {"report_hash": case_hash, "decisions": decisions},
        "limits": ["Exchange scope and purchase attribution are operator assertions.",
                   "Reconciliation never creates a cryptographic funding link or clears an output automatically.",
                   "Submitted custody outputs are not proof that undisclosed wallets do not exist."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--developer-public-key", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--decisions-output", type=Path, help="Optional editable developer decision template")
    parser.add_argument("--approved-ledger-sha256", help="Main developer approval of the independently obtained operator ledger")
    parser.add_argument("--sign-key", type=Path, help="Main developer private signing key; used only with approved ledger")
    parser.add_argument("--outdir", type=Path, help="New directory for automatically signed qualifying purchase receipts")
    parser.add_argument("--daemon-address", help="Publish automatic clearances directly; owners need no import")
    parser.add_argument("--rpc-login-file", type=Path, help="Private publisher RPC credentials file")
    parser.add_argument("--activation-height", type=int, help="Certificate epoch; must match the native verifier configuration")
    args = parser.parse_args()
    case_raw = args.case.read_bytes()
    case = load_json(case_raw)
    # Verify the exact bytes parsed below, even if an input file changes while
    # the native verifier runs. The temporary directory is owner-only.
    with tempfile.TemporaryDirectory(prefix="salvium-nonkyc-case-") as temporary:
        snapshot = Path(temporary) / "case.json"
        snapshot.write_bytes(case_raw)
        verification = subprocess.run([str(args.verifier.resolve()), "--report", str(snapshot),
            "--verify-key", args.developer_public_key], check=True, capture_output=True, text=True)
    case_hash = next(line.split()[1] for line in verification.stdout.splitlines() if line.startswith("VERIFIED "))
    raw = args.ledger.read_bytes()
    result = reconcile(case, load_json(raw), case_hash, hashlib.sha256(raw).hexdigest())
    automatic = bool(args.sign_key or args.outdir or args.approved_ledger_sha256 or args.daemon_address or args.rpc_login_file)
    if automatic:
        if not (args.sign_key and args.outdir and args.approved_ledger_sha256):
            parser.error("Automatic processing requires --sign-key, --outdir and --approved-ledger-sha256")
        if args.approved_ledger_sha256.lower() != result["ledger_sha256"]:
            parser.error("Ledger differs from the independently approved operator records")
        if result["errors"] or result["purchase_review_warnings"]:
            parser.error("Ledger requires developer review; automatic purchase clearance is unavailable")
    # Refuse overwrites and restrict private ledger-derived evidence to its owner.
    import os
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(result, out, indent=2); out.write("\n")
    if args.decisions_output:
        fd = os.open(args.decisions_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump(result["developer_decisions"], out, indent=2); out.write("\n")
    if automatic:
        # Never turn an unresolved recommendation into an automatic denial.
        # The developer queue retains those rows and their original findings.
        changes = dict(result["developer_decisions"])
        changes["decisions"] = [row for row in changes["decisions"] if row["action"] == "CLEAR"]
        with tempfile.TemporaryDirectory(prefix="salvium-approved-purchases-") as temporary:
            snapshot = Path(temporary) / "case.json"
            decisions = Path(temporary) / "purchases.json"
            snapshot.write_bytes(case_raw)
            decisions.write_text(json.dumps(changes))
            command = [str(args.verifier.resolve()), "--report", str(snapshot), "--decisions", str(decisions),
                       "--sign-key", str(args.sign_key.resolve()), "--outdir", str(args.outdir.resolve())]
            if args.activation_height is not None:
                command += ["--activation-height", str(args.activation_height)]
            subprocess.run(command, check=True)
            if args.daemon_address:
                import sys
                publication = [sys.executable, str(Path(__file__).with_name("process_private_audit.py")),
                    "--daemon-address", args.daemon_address, "--case-directory", str(args.outdir.resolve())]
                if args.rpc_login_file:
                    publication += ["--rpc-login-file", str(args.rpc_login_file.resolve())]
                subprocess.run(publication, check=True)
    print(result["status"], f"errors={len(result['errors'])}", f"warnings={len(result['warnings'])}")
    return 2 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
