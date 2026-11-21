#!/usr/bin/env python3
"""Accounting, attribution and duplicate-counting controls for private reconciliation."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("nonkyc", Path(__file__).resolve().parents[2] / "utils/reconcile_nonkyc_audit.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Reconciliation(unittest.TestCase):
    def setUp(self):
        anchor = dict(genesis="a" * 64, network=0, snapshot_height=100, snapshot_hash="b" * 64)
        self.case = dict(anchor, outputs=[
            dict(package_id="custody", transaction="c" * 64, output_index=0, stake=False, spent=False,
                 amount=100, asset_type="SAL1", state="CLEARED", reason="VERIFIED_ISSUANCE", decision=""),
            dict(package_id="buyer", transaction="d" * 64, output_index=0, stake=False, spent=False,
                 amount=20, asset_type="SAL1", state="REVIEW_REQUIRED", reason="MISSING_FUNDING_EVIDENCE", decision="")])
        self.ledger = dict(anchor, version=1, scope_complete=True, assets_in_scope=["SAL1"],
            custody_package_ids=["custody"], balances=[
                dict(account="seller", asset="SAL1", opening_atomic="120", closing_atomic="100"),
                dict(account="buyer", asset="SAL1", opening_atomic="0", closing_atomic="0")],
            events=[
                dict(id="sell", group="trade", kind="trade", account="seller", asset="SAL1", delta_atomic="-20"),
                dict(id="buy", group="trade", kind="trade", account="buyer", asset="SAL1", delta_atomic="20"),
                dict(id="withdraw", kind="withdrawal", account="buyer", asset="SAL1", delta_atomic="-20",
                     transaction="d" * 64, output_index=0, acquisition="market_purchase")])

    def run_case(self):
        return module.reconcile(self.case, self.ledger, "case-hash", "ledger-hash")

    def test_balanced_purchase_is_recommendation_only(self):
        result = self.run_case()
        self.assertFalse(result["errors"])
        self.assertEqual(result["developer_decisions"]["decisions"][0]["action"], "CLEAR")
        self.assertEqual(self.case["outputs"][1]["state"], "REVIEW_REQUIRED")

    def test_innocent_purchase_recommendation_preserves_proven_funding_finding(self):
        self.case["outputs"][1]["reason"] = "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW"
        self.assertEqual(self.run_case()["developer_decisions"]["decisions"][0]["action"], "CLEAR")
        self.assertEqual(self.case["outputs"][1]["state"], "REVIEW_REQUIRED")
        self.case["outputs"][1]["reason"] = "CONFIRMED_MALFORMED_ORIGIN"
        self.assertEqual(self.run_case()["developer_decisions"]["decisions"][0]["action"], "DENY")

    def test_duplicate_custody_proof_never_doubles_reserves(self):
        self.case["outputs"].append(copy.deepcopy(self.case["outputs"][0]))
        self.assertEqual(self.run_case()["per_asset"][0]["reserves_atomic"], "100")

    def test_incomplete_scope_prevents_clear_recommendation(self):
        self.ledger["scope_complete"] = False
        result = self.run_case()
        self.assertTrue(result["errors"])
        self.assertEqual(result["developer_decisions"]["decisions"][0]["action"], "DENY")

    def test_duplicate_deposit_credit(self):
        self.ledger["balances"][0]["closing_atomic"] = "300"
        for number in (1, 2):
            self.ledger["events"].append(dict(id=f"deposit-{number}", kind="deposit", account="seller",
                asset="SAL1", delta_atomic="100", transaction="c" * 64, output_index=0))
        self.assertTrue(any("credited more than once" in error for error in self.run_case()["errors"]))

    def test_forged_receipt_amount(self):
        self.case["outputs"][1]["amount"] = 21
        self.assertTrue(self.run_case()["errors"])

    def test_duplicate_withdrawal_output(self):
        repeated = copy.deepcopy(self.ledger["events"][-1])
        repeated["id"] = "withdraw-again"
        self.ledger["events"].append(repeated)
        self.assertTrue(any("debited more than once" in error for error in self.run_case()["errors"]))

    def test_purchase_claim_without_trade(self):
        self.ledger["events"] = self.ledger["events"][-1:]
        self.ledger["balances"][1].update(opening_atomic="20")
        self.assertTrue(any("purchase does not cover" in error for error in self.run_case()["errors"]))

    def test_bad_custody_prevents_clear_recommendation(self):
        self.case["outputs"][0]["reason"] = "CONFIRMED_MALFORMED_ORIGIN"
        result = self.run_case()
        self.assertTrue(result["warnings"])
        self.assertEqual(result["developer_decisions"]["decisions"][0]["action"], "DENY")

    def test_snapshot_and_precision(self):
        self.ledger["snapshot_hash"] = "wrong"
        with self.assertRaises(ValueError):
            self.run_case()
        for value in (1.5, 10, "1.0", "01", "+1", str(2**64)):
            with self.assertRaises(ValueError):
                module.atomic(value)


if __name__ == "__main__":
    unittest.main()
