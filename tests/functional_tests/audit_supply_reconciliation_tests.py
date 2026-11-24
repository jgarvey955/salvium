#!/usr/bin/env python3
"""Independent supply ledger accounting and incomplete-evidence regressions."""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "utils"))
import audit_supply_reconciliation as supply


class SupplyAccounting(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(supply.SCHEMA)
        self.context = dict(network=3, genesis="a" * 64, scan_end_height=10,
                            ending_block_hash="b" * 64)
        accounting = dict(reward_asset="SAL1", base_reward_atomic=1000, treasury_mint_atomic=0,
                          stake_reserve_atomic=100, fees_atomic=10, verification="PASS")
        self.db.execute("INSERT INTO accounting VALUES(?,?)", (1, json.dumps(accounting)))
        self.output("1", "SAL1", "MINER", 910)
        self.output("2", "SAL1", "PROTOCOL", 120)
        self.output("3", "salTEST", "PROTOCOL", 500)
        self.output("4", "SAL1", "TRANSFER", "NOT VERIFIABLE")
        self.output("5", "salTEST", "TRANSFER", "NOT VERIFIABLE")
        for name, category, burnt, fee in (("6", "STAKE", 100, 3), ("7", "STAKE", 100, 3),
                ("8", "BURN", 50, 2), ("9", "ROLLUP", 25, 2)):
            self.transaction(name, category, burnt, fee)
        for name, asset in (("4", "SAL1"), ("5", "salTEST")):
            self.transaction(name, "TRANSFER", 0, 0, asset)
        for key, source_type, value, principal, asset in (("2", 6, 120, 100, "SAL1"),
                                                         ("3", 9, 500, 0, "salTEST")):
            row = dict(authorization=key, verification="PASS", source_type=source_type,
                       actual_atomic=value, principal_atomic=principal, asset=asset, source_asset="SAL1")
            self.db.execute("INSERT INTO payouts VALUES(?,?,?,?,?)",
                            (key * 64, 0, key, "6" * 64, json.dumps(row)))
        self.case = dict(network=3, genesis="a" * 64, snapshot_height=10, snapshot_hash="b" * 64,
            coverage="SUBMITTED_OUTPUTS_ONLY", outputs=[
                dict(transaction="4" * 64, output_index=0, stake=False, spent=False, asset_type="SAL1", amount=745),
                dict(transaction="5" * 64, output_index=0, stake=False, spent=False, asset_type="salTEST", amount=500),
                dict(transaction="7" * 64, output_index=0, stake=True, spent=False, asset_type="SAL1", amount=100)])

    def tearDown(self):
        self.db.close()

    def output(self, name, asset, category, value):
        row = dict(asset=asset, category=category, public_amount_atomic=value,
                   structural_status="PASS", monetary_status="PASS")
        self.db.execute("INSERT INTO outputs VALUES(?,?,?,?,?,?,?,?,?)",
                        (name * 64, 0, 1, asset, category, "", "", "PASS", json.dumps(row)))

    def transaction(self, name, category, burnt, fee, asset="SAL1"):
        row = dict(source_asset=asset, category=category, version=5, amount_burnt_atomic=burnt,
                   fee_atomic=fee, crypto_status="PASS", rules_status="PASS",
                   duplicate_key_image="no", cross_asset_origin="no")
        self.db.execute("INSERT INTO transactions VALUES(?,?,?)", (name * 64, 1, json.dumps(row)))

    def check_case(self, cases=None):
        return supply.reconcile(self.db, self.context, dict(cryptographic_failures=0),
                                [self.case] if cases is None else cases)

    def test_full_supply_with_locked_stakes_rewards_burns_and_tokens(self):
        report = self.check_case()
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["status"], "PASS")
        sal1 = report["assets"]["SAL1"]
        self.assertEqual(sal1["circulating_output_supply"], "745")
        self.assertEqual(sal1["locked_stake_principal"], "100")
        self.assertEqual(sal1["outstanding_supply_including_stakes"], "845")
        self.assertEqual(sal1["unpaid_reward_reserve"], "80")
        self.assertEqual(sal1["unallocated_fee_escrow"], "25")
        self.assertEqual(sal1["accounted_existing_value_with_fee_escrow"], "870")
        self.assertEqual(report["assets"]["salTEST"]["circulating_output_supply"], "500")

    def test_retired_sal_is_context_and_needs_no_new_owner_enrollment(self):
        before = self.check_case()
        self.output("a", "SAL", "MINER", 1000)
        self.transaction("b", "TRANSFER", 0, 0, "SAL")
        report = self.check_case()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["assets"], before["assets"])
        self.assertNotIn("SAL", report["active_audit_assets"])
        self.assertNotIn("SAL", report["assets"])
        self.assertEqual(report["legacy_conversion_context"]["SAL"]["owner_reconciliation_difference"], "1000")

    def test_duplicate_owner_submissions_are_idempotent(self):
        self.assertEqual(self.check_case()["assets"], self.check_case([self.case, self.case])["assets"])

    def test_missing_owner_or_altered_amount_does_not_verify_total_supply(self):
        for remove in (True, False):
            case = copy.deepcopy(self.case)
            if remove:
                case["outputs"].pop(0)
            else:
                case["outputs"][0]["amount"] += 1
            self.assertEqual(self.check_case([case])["status"], "FAIL")

    def test_conflicting_authenticated_owner_reports_fail(self):
        altered = copy.deepcopy(self.case)
        altered["outputs"][0]["amount"] += 1
        with self.assertRaises(ValueError):
            self.check_case([self.case, altered])

    def test_wrong_snapshot_does_not_reconcile(self):
        case = dict(self.case, snapshot_height=9)
        with self.assertRaises(ValueError):
            self.check_case([case])

    def test_bad_crypto_and_monetary_origin_prevent_false_supply_pass(self):
        self.assertEqual(supply.reconcile(self.db, self.context,
            dict(cryptographic_failures=1), [self.case])["status"], "FAIL")
        data = json.loads(self.db.execute("SELECT data FROM outputs LIMIT 1").fetchone()[0])
        data["monetary_status"] = "CONFIRMED_INVALID"
        self.db.execute("UPDATE outputs SET data=? WHERE tx=?", (json.dumps(data), "1" * 64))
        self.assertEqual(self.check_case()["status"], "FAIL")

    def test_database_tally_is_compared_instead_of_trusted(self):
        self.db.execute("INSERT INTO stored_supply VALUES(?,?)",
                        ("SAL1", json.dumps(dict(amount_atomic=746))))
        report = self.check_case()
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("Database" in error for error in report["errors"]))

    def test_public_treasury_balance_requires_complete_actual_spend_proofs(self):
        db = sqlite3.connect(":memory:")
        db.executescript(supply.SCHEMA)
        try:
            accounting = dict(reward_asset="SAL1", base_reward_atomic=1000, treasury_mint_atomic=0,
                              stake_reserve_atomic=100, fees_atomic=10, verification="PASS")
            db.execute("INSERT INTO accounting VALUES(?,?)", (0, json.dumps(accounting)))
            for tx, idx, category, value, key in (("1", 0, "MINER", 885, "a"),
                    ("1", 1, "MINER", 25, "b"), ("2", 0, "TRANSFER", "NOT VERIFIABLE", "c")):
                output = dict(asset="SAL1", public_key=key * 64, category=category,
                              public_amount_atomic=value, structural_status="PASS", monetary_status="PASS")
                db.execute("INSERT INTO outputs VALUES(?,?,?,?,?,?,?,?,?)",
                    (tx * 64, idx, 0, "SAL1", category, "", "", "PASS", json.dumps(output)))
            tx = dict(category="TRANSFER", source_asset="SAL1", version=5, amount_burnt_atomic=0,
                      fee_atomic=10, crypto_status="PASS", rules_status="PASS", duplicate_key_image="no",
                      cross_asset_origin="no", inputs=1, key_images="d" * 64)
            db.execute("INSERT INTO transactions VALUES(?,?,?)", ("2" * 64, 1, json.dumps(tx)))
            case = dict(self.case, outputs=[
                dict(transaction="1" * 64, output_index=0, stake=False, spent=True, asset_type="SAL1", amount=885),
                dict(transaction="2" * 64, output_index=0, stake=False, spent=False, asset_type="SAL1", amount=875)])
            witnesses = [dict(outputs=[dict(transaction="1" * 64, output_index=0, image="d" * 64)])]
            complete = dict(cryptographic_failures=0)
            report = supply.reconcile(db, self.context, complete, [case], witnesses)
            self.assertEqual(report["errors"], [])
            self.assertTrue(report["all_actual_spends_bound_to_owner_proofs"])
            self.assertEqual(report["assets"]["SAL1"]["circulating_output_supply"], "900")
            self.assertEqual(report["assets"]["SAL1"]["public_unspent_issuance"], "25")
            self.assertEqual(supply.reconcile(db, self.context, complete, [case], [])["status"], "FAIL")
            public = json.loads(db.execute("SELECT data FROM outputs WHERE idx=1").fetchone()[0])
            public["public_key"] = "a" * 64
            db.execute("UPDATE outputs SET data=? WHERE idx=1", (json.dumps(public),))
            self.assertEqual(supply.reconcile(db, self.context, complete, [case], witnesses)["status"], "FAIL")
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
