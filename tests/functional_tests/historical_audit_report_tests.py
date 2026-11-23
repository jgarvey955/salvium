#!/usr/bin/env python3
"""Historical amnesty false positives, accounting and evidence integrity."""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("historical", Path(__file__).resolve().parents[2] / "utils/historical_audit_report.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class HistoricalAudit(unittest.TestCase):
    def setUp(self):
        self.context = dict(record_type="context", schema_version=1, network=3, genesis="a" * 64,
            scan_start_height=1, scan_end_height=2, ending_block_hash="c" * 64,
            opening_height=0, opening_block_hash="a" * 64)
        self.policy = dict(network=3, genesis="a" * 64, snapshot_height=2, snapshot_hash="c" * 64,
            historical_cutoff_height=2, policy_version="test-1", eligible_assets=["SAL", "SAL1"], approved=False)
        self.output = dict(record_type="output", height=1, transaction="d" * 64, output_index=0,
            global_output_id=0, asset="SAL1", category="TRANSFER", structural_status="PASS",
            monetary_status="PASS", provenance="UNKNOWN_PROVENANCE", block_hash="b" * 64,
            public_key="e" * 64, commitment="f" * 64, public_amount_atomic=m.NV)

    def test_private_ancestry_and_missing_exchange_records_clear(self):
        for metadata in ({}, {"exchange_records": "MISSING"}, {"ring_contains_illicit_decoy": True}):
            row = dict(self.output, **metadata)
            self.assertEqual(m.classify(row, self.policy)[0], "POLICY_CLEAR")

    def test_affirmative_invalid_origin_is_denied_even_before_opening(self):
        row = dict(self.output, monetary_status="CONFIRMED_INVALID", height=0)
        self.assertEqual(m.classify(row, self.policy)[0], "DENY")

    def test_mandatory_failure_and_actual_conflict_require_review(self):
        self.assertEqual(m.classify(dict(self.output, structural_status="REVIEW"), self.policy)[0], "REVIEW")
        self.assertEqual(m.classify(self.output, self.policy, authorization_ok=False)[0], "REVIEW")
        self.assertEqual(m.classify(self.output, self.policy, conflict=True)[0], "REVIEW")

    def test_cutoff_and_asset_scope_cannot_clear_future_outputs(self):
        self.assertEqual(m.classify(dict(self.output, height=3), self.policy)[0], "UNKNOWN")
        self.assertEqual(m.classify(dict(self.output, asset="unregistered"), self.policy)[0], "UNKNOWN")

    def test_network_genesis_snapshot_and_approval_are_not_self_assertions(self):
        m.checked_policy(self.policy, self.context)
        for field, value in (("network", 0), ("genesis", "b" * 64), ("snapshot_hash", "d" * 64),
                             ("snapshot_height", 1), ("historical_cutoff_height", 3), ("approved", True)):
            with self.assertRaises(ValueError):
                m.checked_policy(dict(self.policy, **{field: value}), self.context)

    def records(self):
        records = [self.context]
        for h in range(3):
            records.append(dict(record_type="accounting_block", height=h, block_hash=chr(97 + h) * 64,
                reward_asset="SAL1", base_reward_atomic=100, treasury_mint_atomic=0, verification="PASS"))
        for h in range(3):
            records.append(dict(record_type="block", height=h, block_hash=chr(97 + h) * 64))
        records.append(dict(record_type="transaction", height=1, transaction="d" * 64,
            block_hash="b" * 64, category="TRANSFER", source_asset="SAL1", destination_asset="SAL1",
            crypto_status="PASS", rules_status="PASS", duplicate_key_image="no", amount_burnt_atomic=0,
            cross_asset_origin="no", invalid_issuance_asset="", invalid_issuance_atomic=m.NV))
        records += [self.output, dict(record_type="complete", scan_end_height=2, ending_block_hash="c" * 64,
            transactions=1, outputs=1, cryptographic_failures=0)]
        return copy.deepcopy(records)

    def ingest(self, records):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "evidence.jsonl"
            path.write_text("".join(json.dumps(r) + "\n" for r in records))
            db = sqlite3.connect(":memory:"); db.executescript(m.SCHEMA)
            try:
                return m.ingest(path, db)
            finally:
                db.close()

    def test_incomplete_or_duplicate_evidence_is_not_a_complete_audit(self):
        self.ingest(self.records())
        rows = self.records()
        for damaged in (rows[:-1], rows + [rows[-2]], rows[:1] + rows,
                        rows[:-1] + [dict(rows[-1], outputs=2)]):
            with self.assertRaises((ValueError, sqlite3.IntegrityError)):
                self.ingest(damaged)

    def test_duplicate_transaction_and_output_identity_rejected(self):
        rows = self.records()
        for item in (rows[-2], rows[-3]):
            with self.assertRaises((ValueError, sqlite3.IntegrityError)):
                self.ingest(rows[:-1] + [item] + rows[-1:])

    def test_same_block_token_issuance_is_not_a_forward_stake_return(self):
        rows = self.records()
        source = next(r for r in rows if r["record_type"] == "transaction")
        source["category"] = "CREATE_TOKEN"
        next(r for r in rows if r["record_type"] == "output")["category"] = "CREATE_TOKEN"
        protocol = dict(source, transaction="e" * 64, category="PROTOCOL")
        output = dict(self.output, transaction="e" * 64, category="PROTOCOL",
                      asset="salTEST", public_amount_atomic=100, global_output_id=1)
        payout = dict(record_type="payout", transaction="e" * 64, output_index=0,
            height=1, asset="salTEST", source_transaction="d" * 64, source_height=1,
            source_type=9, expected_atomic=100, actual_atomic=100, verification="PASS",
            authorization="token-creation")
        rows[-1].update(transactions=2, outputs=2)
        rows[-1:-1] = [protocol, output, payout]
        self.ingest(rows)
        for source_type in (6, 7):
            damaged = copy.deepcopy(rows)
            next(r for r in damaged if r["record_type"] == "payout")["source_type"] = source_type
            with self.assertRaises(ValueError):
                self.ingest(damaged)

    def test_duplicate_accepted_payout_authorization_rejected(self):
        rows = self.records()
        rows[-3]["category"] = "CREATE_TOKEN"
        rows[-2]["category"] = "CREATE_TOKEN"
        protocol = dict(rows[-3], transaction="e" * 64, category="PROTOCOL")
        first = dict(self.output, transaction="e" * 64, category="PROTOCOL",
                     public_amount_atomic=100, global_output_id=1)
        second = dict(first, output_index=1, global_output_id=2)
        payout = dict(record_type="payout", transaction="e" * 64, output_index=0,
            height=1, asset="SAL1", source_transaction="d" * 64, source_height=1,
            source_type=9, expected_atomic=100, actual_atomic=100, verification="PASS",
            authorization="one-obligation")
        rows[-1:-1] = [protocol, first, second, payout, dict(payout, output_index=1)]
        rows[-1].update(transactions=2, outputs=3)
        with self.assertRaises(ValueError): self.ingest(rows)

    def test_arbitrary_precision_and_no_transfer_or_denial_supply_creation(self):
        value = 2**80 + 17
        self.assertEqual(m.amount(str(value)), value)
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); source = root / "native.jsonl"; policy = root / "policy.json"
            rows = self.records()
            rows[1]["base_reward_atomic"] = str(value)
            source.write_text("".join(json.dumps(r) + "\n" for r in rows)); policy.write_text(json.dumps(self.policy))
            report = m.generate(source, policy, root / "report", "test-commit")
            asset = report["assets"]["SAL1"]
            self.assertEqual(asset["components_atomic"]["opening_authorized_schedule"], str(value))
            self.assertEqual(asset["components_atomic"]["mining_emissions"], "200")
            self.assertEqual(asset["confirmed_illicit_issuance_atomic"], "0")
            self.assertEqual(asset["outputs"]["POLICY_CLEAR"], 1)
            self.assertEqual(asset["approved_current_monetary_value_atomic"], m.NV)
            self.assertEqual(report["issued_clearance_certificates"], 0)
            for name in ("audit_supply_report.json", "audit_illicit_outputs.csv", "audit_approved_outputs.csv",
                         "audit_supply_reconciliation.csv", "audit_final_summary.md", "audit_salyahu_report.md",
                         "audit_other_bad_actor_report.md"):
                self.assertTrue((root / "report" / name).is_file())

    def test_invalid_output_amount_is_not_an_invented_exact_issuance(self):
        rows = self.records()
        tx = next(r for r in rows if r["record_type"] == "transaction")
        tx.update(hard_fork=11, rules_reason="")
        output = next(r for r in rows if r["record_type"] == "output")
        output.update(monetary_status="CONFIRMED_INVALID",
                      protocol_violation="NONZERO_CONFIDENTIAL_OUTPUT_AMOUNT")
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "native.jsonl"; policy = root / "policy.json"
            source.write_text("".join(json.dumps(r) + "\n" for r in rows))
            policy.write_text(json.dumps(self.policy))
            report = m.generate(source, policy, root / "report", "test-commit")
            asset = report["assets"]["SAL1"]
            self.assertEqual(asset["outputs"]["DENY"], 1)
            self.assertEqual(asset["confirmed_known_illicit_issuance_atomic"], "0")
            self.assertEqual(asset["confirmed_illicit_issuance_atomic"], m.NV)
            self.assertEqual(report["confirmed_incidents"][0]["event_class"], "INVALID_OUTPUT_AMOUNT")
            summary = (root / "report/audit_final_summary.md").read_text()
            self.assertIn("1 confirmed invalid-output transaction/asset events", summary)
            self.assertIn("audit_other_bad_actor_report.md", summary)
            self.assertIn(tx["transaction"], (root / "report/audit_other_bad_actor_report.md").read_text())

    def test_stake_principal_is_not_burned_or_issued_again(self):
        rows = self.records()
        tx = rows[-3]; tx["category"] = "STAKE"; tx["amount_burnt_atomic"] = 70
        rows[-2]["category"] = "STAKE"
        payout_id = "9" * 64
        rows.insert(-1, dict(rows[-3], category="PROTOCOL", height=2, block_hash="c" * 64, transaction=payout_id))
        rows.insert(-1, dict(self.output, category="PROTOCOL", height=2, block_hash="c" * 64,
            transaction=payout_id, global_output_id=1, public_amount_atomic="77"))
        rows[-1].update(transactions=2, outputs=2)
        rows.insert(1, dict(record_type="payout", transaction=payout_id, output_index=0,
            authorization="stake-unique", height=2, asset="SAL1", source_asset="SAL1", source_type=6,
            source_transaction="d" * 64, source_height=1,
            principal_atomic=70, expected_atomic=77, actual_atomic=77, verification="PASS"))
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); source = root / "native.jsonl"; policy = root / "policy.json"
            source.write_text("".join(json.dumps(r) + "\n" for r in rows)); policy.write_text(json.dumps(self.policy))
            r = m.generate(source, policy, root / "report", "test-commit")
            a = r["assets"]["SAL1"]["components_atomic"]
            self.assertEqual(a["staking_principal_returned"], "70")
            self.assertEqual(a["staking_rewards_paid"], "7")
            self.assertEqual(a["verified_burns"], "0")
            self.assertEqual(r["assets"]["SAL1"]["public_authorized_schedule_net_atomic"], "300")
            self.assertEqual(r["stake_principal_classifications"]["POLICY_CLEAR"], 1)
            self.assertEqual(r["assets"]["SAL1"]["outputs"]["POLICY_CLEAR"], 2)
            plan = [json.loads(line) for line in (root / "report/audit_clearance_plan.jsonl").read_text().splitlines()]
            stakes = [p for p in plan if p["stake"]]
            self.assertEqual(len(stakes), 1)
            self.assertEqual(stakes[0]["transaction"], "d" * 64)
            self.assertEqual(stakes[0]["payout_inheritance"], "NATIVE_EXACT_AUTHORIZED_RETURN")
            self.assertEqual(stakes[0]["certificate_status"], "UNSIGNED_PLAN_ONLY")

    def test_unreturned_stake_is_eligible_but_failed_proof_needs_review(self):
        for crypto, state in (("PASS", "POLICY_CLEAR"), ("REVIEW", "REVIEW")):
            rows = self.records()
            rows[-3].update(category="STAKE", amount_burnt_atomic=70, crypto_status=crypto)
            rows[-2]["category"] = "STAKE"
            with tempfile.TemporaryDirectory() as root:
                root = Path(root); source = root / "native.jsonl"; policy = root / "policy.json"
                source.write_text("".join(json.dumps(r) + "\n" for r in rows)); policy.write_text(json.dumps(self.policy))
                r = m.generate(source, policy, root / "report", "test-commit")
                self.assertEqual(r["stake_principal_classifications"][state], 1)
                import csv
                with (root / "report/audit_stake_clearances.csv").open() as handle:
                    principal = list(csv.DictReader(handle))
                self.assertEqual(principal[0]["payout_status"], "NO_RETURN_AT_SNAPSHOT")
                self.assertEqual(principal[0]["principal_atomic"], "70")
                self.assertEqual(r["assets"]["SAL1"]["public_authorized_schedule_net_atomic"], "300")

    def test_noncanonical_accounting_or_payout_cannot_authorize_outputs(self):
        rows = self.records()
        for index in (1, -3, -2):
            damaged = copy.deepcopy(rows)
            damaged[index]["block_hash"] = "0" * 64
            with self.assertRaises(ValueError): self.ingest(damaged)
        orphan = dict(record_type="payout", transaction="1" * 64, output_index=0,
            authorization="missing", source_transaction="d" * 64, source_height=1,
            height=2, asset="SAL1", expected_atomic=1, actual_atomic=1, verification="PASS")
        with self.assertRaises(ValueError): self.ingest(rows[:-1] + [orphan] + rows[-1:])

    def test_missing_or_null_canonical_references_rejected(self):
        for kind in ("transaction", "output", "accounting_block"):
            for value in (None, "missing"):
                rows = self.records()
                row = next(r for r in rows if r["record_type"] == kind)
                if value == "missing": del row["block_hash"]
                else: row["block_hash"] = value
                with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                    self.ingest(rows)

    def test_completion_must_name_the_same_endpoint(self):
        rows = self.records()
        rows[-1]["scan_end_height"] = 1
        with self.assertRaises(ValueError): self.ingest(rows)

    def test_funding_proof_context_must_match_canonical_records(self):
        rows = self.records()
        child = dict(rows[-3], transaction="9" * 64, height=2, block_hash="c" * 64)
        output = dict(self.output, transaction=child["transaction"], height=2,
                      block_hash="c" * 64, global_output_id=1)
        proof = dict(record_type="proven_input", transaction=child["transaction"], input_index=0,
            source_transaction=self.output["transaction"], source_output_index=0,
            source_height=1, height=2, asset="SAL1", verification="ONE_MEMBER_RING_CRYPTOGRAPHICALLY_VERIFIED")
        rows[-1:-1] = [child, output, proof]
        rows[-1].update(transactions=2, outputs=2)
        self.ingest(rows)
        for field, value in (("source_height", 0), ("height", 3), ("asset", "SAL")):
            damaged = copy.deepcopy(rows)
            next(r for r in damaged if r["record_type"] == "proven_input")[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.ingest(damaged)

    def test_atomic_values_and_ambiguous_json_rejected(self):
        for value in (True, -1, 1.0, "01", "+1", "1e3", "１"):
            with self.assertRaises(ValueError): m.amount(value)
        for value in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError): m.load(value)


if __name__ == "__main__":
    unittest.main()
