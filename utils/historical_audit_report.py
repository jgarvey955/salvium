#!/usr/bin/env python3
"""Stream canonical native evidence into historical-amnesty and supply reports.

This tool neither signs nor publishes certificates. Classification under a proposed
policy is an eligibility assessment; only canonical v4 certificates grant spendability.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess

NV = "NOT VERIFIABLE"
SALYAHU_TX = "9353dd3288e20618596085228ea6faf5bf2a9d01cd98c36ea5ceeef2c2d4eb1e"
STATES = ("VERIFIED_CLEAR", "POLICY_CLEAR", "REVIEW", "DENY", "UNKNOWN")


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON field: {key}")
        value[key] = item
    return value


def load(text):
    return json.loads(text, object_pairs_hook=strict_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def amount(value):
    if value == NV:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("Amounts must be exact nonnegative integers")
    text = str(value)
    if not text.isascii() or not text.isdecimal() or str(int(text)) != text:
        raise ValueError("Noncanonical atomic amount")
    return int(text)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def checked_policy(policy, context):
    for field, expected in (("network", context["network"]), ("genesis", context["genesis"]),
                            ("snapshot_height", context["scan_end_height"]),
                            ("snapshot_hash", context["ending_block_hash"])):
        if policy.get(field) != expected:
            raise ValueError(f"Policy has different canonical {field}")
    cutoff = policy.get("historical_cutoff_height")
    if type(cutoff) is not int or not 0 <= cutoff <= context["scan_end_height"]:
        raise ValueError("Historical cutoff must be inside the bound snapshot")
    assets = policy.get("eligible_assets")
    if (not isinstance(policy.get("policy_version"), str) or not policy["policy_version"] or
            not isinstance(assets, list) or not assets or
            any(not isinstance(a, str) or not a for a in assets) or len(set(assets)) != len(assets)):
        raise ValueError("Policy version and exact eligible asset list required")
    # A JSON boolean is not main-developer authorization. A release must supply
    # authenticated policy binding and native revalidation before signing.
    if policy.get("approved") is not False:
        raise ValueError("This report tool accepts proposed policies only; JSON cannot authorize mainnet")
    return hashlib.sha256(canonical(policy).encode()).hexdigest()


def classify(row, policy, authorization_ok=True, conflict=False):
    if row["monetary_status"] == "CONFIRMED_INVALID":
        return "DENY", "CONFIRMED_REPRODUCIBLE_ORIGIN_VIOLATION"
    if row.get("proven_disqualifying_funding") and policy.get("deny_proven_illicit_funding") is True:
        return "DENY", "CRYPTOGRAPHICALLY_PROVEN_DISQUALIFYING_FUNDING"
    if conflict:
        return "REVIEW", "CONFLICTING_AUTHENTICATED_EVIDENCE"
    if row["structural_status"] != "PASS" or row["monetary_status"] != "PASS" or not authorization_ok:
        return "REVIEW", "MANDATORY_VALIDATION_UNRESOLVED"
    if row["height"] > policy["historical_cutoff_height"] or row["asset"] not in policy["eligible_assets"]:
        return "UNKNOWN", "OUTSIDE_HISTORICAL_AMNESTY_SCOPE"
    if row["category"] == "MINER" or row["provenance"] == "ACCEPTED_OPENING":
        return "VERIFIED_CLEAR", "VERIFIED_ISSUANCE_OR_ACCEPTED_OPENING"
    if row["category"] == "PROTOCOL" and row.get("payout_source_type") != 6:
        return "VERIFIED_CLEAR", "VERIFIED_PROTOCOL_AUTHORIZATION"
    return "POLICY_CLEAR", "VALID_HISTORICAL_OUTPUT_UNKNOWN_ANCESTRY"


SCHEMA = """
CREATE TABLE verification_checks(name TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE stored_supply(asset TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE accounting(height INTEGER PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE transactions(id TEXT PRIMARY KEY, height INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX transaction_height ON transactions(height,id);
CREATE TABLE payouts(tx TEXT, idx INTEGER, authorization TEXT, source_tx TEXT, data TEXT NOT NULL, PRIMARY KEY(tx,idx));
CREATE INDEX payout_source ON payouts(source_tx);
CREATE TABLE proven_inputs(child TEXT, idx INTEGER, parent TEXT, parent_idx INTEGER, data TEXT, PRIMARY KEY(child,idx));
CREATE INDEX proven_parent ON proven_inputs(parent,parent_idx);
CREATE TABLE disqualified(tx TEXT, idx INTEGER, root_tx TEXT, method TEXT, PRIMARY KEY(tx,idx));
CREATE TABLE stake_clearances(tx TEXT PRIMARY KEY, asset TEXT, state TEXT, data TEXT NOT NULL);
CREATE TABLE outputs(tx TEXT, idx INTEGER, height INTEGER, asset TEXT, category TEXT, state TEXT,
 reason TEXT, monetary TEXT, data TEXT NOT NULL, PRIMARY KEY(tx,idx));
CREATE INDEX output_monetary ON outputs(monetary);
CREATE INDEX output_height ON outputs(height,tx,idx);
"""


def ingest(path, db):
    context = complete = None
    counts = {"transactions": 0, "outputs": 0, "blocks": 0, "accounting": 0}
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for number, raw in enumerate(iter(lambda: source.readline(1024 * 1024 + 1), b""), 1):
            hasher.update(raw)
            if len(raw) > 1024 * 1024:
                raise ValueError("Evidence record exceeds 1 MiB")
            r = load(raw)
            kind = r["record_type"]
            if complete is not None:
                raise ValueError("Trailing evidence after completion marker")
            data = canonical(r)
            if kind == "context":
                if context is not None or number != 1 or r["schema_version"] != 1:
                    raise ValueError("Invalid or repeated native context")
                context = r
            elif context is None:
                raise ValueError("Evidence must begin with canonical context")
            elif kind == "stored_supply":
                db.execute("INSERT INTO stored_supply VALUES(?,?)", (r["asset"], data))
            elif kind == "verification_check":
                db.execute("INSERT INTO verification_checks VALUES(?,?)", (r["name"], data))
            elif kind == "block":
                if r["height"] != counts["blocks"]:
                    raise ValueError("Block coverage contains a gap or duplicate")
                db.execute("INSERT INTO blocks VALUES(?,?,?)", (r["height"], r["block_hash"], data))
                counts["blocks"] += 1
            elif kind == "accounting_block":
                if r["height"] != counts["accounting"]:
                    raise ValueError("Accounting coverage contains a gap or duplicate")
                db.execute("INSERT INTO accounting VALUES(?,?)", (r["height"], data))
                counts["accounting"] += 1
            elif kind == "transaction":
                db.execute("INSERT INTO transactions VALUES(?,?,?)", (r["transaction"], r["height"], data))
                counts["transactions"] += 1
            elif kind == "payout":
                db.execute("INSERT INTO payouts VALUES(?,?,?,?,?)",
                           (r["transaction"], r["output_index"], r["authorization"], r.get("source_transaction", ""), data))
            elif kind == "proven_input":
                if r["verification"] != "ONE_MEMBER_RING_CRYPTOGRAPHICALLY_VERIFIED" or r["source_height"] >= r["height"]:
                    raise ValueError("Unproven or forward funding relationship")
                db.execute("INSERT INTO proven_inputs VALUES(?,?,?,?,?)", (r["transaction"], r["input_index"],
                           r["source_transaction"], r["source_output_index"], data))
            elif kind == "output":
                if r["global_output_id"] != counts["outputs"]:
                    raise ValueError("Global output inventory contains a gap or duplicate")
                db.execute("INSERT INTO outputs VALUES(?,?,?,?,?,?,?,?,?)", (r["transaction"], r["output_index"],
                           r["height"], r["asset"], r["category"], "", "", r["monetary_status"], data))
                counts["outputs"] += 1
            elif kind == "complete":
                complete = r
            else:
                raise ValueError(f"Unsupported native evidence record: {kind}")
            if number % 100000 == 0:
                db.commit()
                print(f"INGEST records={number} outputs={counts['outputs']}", flush=True)
    if not context or not complete:
        raise ValueError("Native scan incomplete: no complete context and terminal marker")
    if any(complete[k] != counts[k] for k in ("transactions", "outputs")):
        raise ValueError("Native completion counts do not match evidence")
    if counts["blocks"] != context["scan_end_height"] + 1 or counts["accounting"] != counts["blocks"]:
        raise ValueError("Historical accounting or inventory coverage incomplete")
    ending = db.execute("SELECT hash FROM blocks WHERE height=?", (context["scan_end_height"],)).fetchone()[0]
    if ending != context["ending_block_hash"] or complete["ending_block_hash"] != ending:
        raise ValueError("Terminal canonical block hash mismatch")
    opening = db.execute("SELECT hash FROM blocks WHERE height=?", (context["opening_height"],)).fetchone()[0]
    if opening != context["opening_block_hash"]:
        raise ValueError("Trusted opening hash mismatch")
    if db.execute("SELECT COUNT(*) FROM outputs o LEFT JOIN transactions t ON t.id=o.tx WHERE t.id IS NULL").fetchone()[0]:
        raise ValueError("Inventory contains orphan output rows")
    if db.execute("""SELECT COUNT(*) FROM transactions t LEFT JOIN blocks b ON b.height=t.height
        WHERE b.height IS NULL OR json_extract(t.data,'$.block_hash')!=b.hash""").fetchone()[0]:
        raise ValueError("Transaction belongs to a noncanonical block")
    if db.execute("""SELECT COUNT(*) FROM accounting a JOIN blocks b ON b.height=a.height
        WHERE json_extract(a.data,'$.block_hash')!=b.hash""").fetchone()[0]:
        raise ValueError("Accounting belongs to a noncanonical block")
    if db.execute("""SELECT COUNT(*) FROM outputs o JOIN transactions t ON t.id=o.tx JOIN blocks b ON b.height=o.height
        WHERE o.height!=t.height OR json_extract(o.data,'$.block_hash')!=b.hash
        OR o.category!=json_extract(t.data,'$.category')""").fetchone()[0]:
        raise ValueError("Output belongs to a different transaction or canonical block")
    if db.execute("""SELECT COUNT(*) FROM payouts p LEFT JOIN outputs o ON o.tx=p.tx AND o.idx=p.idx
        LEFT JOIN transactions s ON s.id=p.source_tx
        WHERE o.tx IS NULL OR s.id IS NULL OR o.category!='PROTOCOL' OR s.height>o.height
        OR (s.height=o.height AND NOT(json_extract(p.data,'$.source_type')=9
            AND json_extract(s.data,'$.category')='CREATE_TOKEN'))
        OR json_extract(p.data,'$.height')!=o.height OR json_extract(p.data,'$.asset')!=o.asset
        OR json_extract(p.data,'$.source_height')!=s.height""").fetchone()[0]:
        raise ValueError("Payout authorization contains noncanonical output or source")
    for data, output in db.execute("SELECT p.data,o.data FROM payouts p JOIN outputs o ON o.tx=p.tx AND o.idx=p.idx"):
        payout, output = load(data), load(output)
        if amount(payout["actual_atomic"]) != amount(output["public_amount_atomic"]):
            raise ValueError("Payout value differs from canonical public output")
        if payout["verification"] == "PASS" and amount(payout["expected_atomic"]) != amount(payout["actual_atomic"]):
            raise ValueError("Verified payout does not equal its authorization")
    if db.execute("""SELECT COUNT(*) FROM proven_inputs p LEFT JOIN outputs o ON o.tx=p.parent AND o.idx=p.parent_idx
        LEFT JOIN transactions t ON t.id=p.child WHERE o.tx IS NULL OR t.id IS NULL OR o.height>=t.height""").fetchone()[0]:
        raise ValueError("Funding proof contains noncanonical or forward output")
    db.commit()
    return context, complete, counts, hasher.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def stake_clearances(db, out, context, policy, policy_digest, stats):
    """Stake principal is a certificate identity, not an extra monetary output."""
    fields = ["network", "block_height", "block_hash", "transaction", "output_index", "stake", "asset",
              "principal_atomic", "decision", "reason_code", "payout_status", "canonical_payouts",
              "policy_version", "policy_digest", "evidence_sha256", "certificate_status"]
    counts = {state: 0 for state in STATES}
    with (out / "audit_stake_clearances.csv").open("w", newline="") as target, \
         (out / "audit_clearance_plan.jsonl").open("a") as plan:
        writer = csv.DictWriter(target, fieldnames=fields); writer.writeheader()
        for (data,) in db.execute("SELECT data FROM transactions WHERE json_extract(data,'$.category')='STAKE' ORDER BY height,id"):
            source = load(data); tx = source["transaction"]; asset = source["source_asset"]
            principal = amount(source["amount_burnt_atomic"])
            returned = [load(p) for (p,) in db.execute("SELECT data FROM payouts WHERE source_tx=? ORDER BY tx,idx", (tx,))]
            own_outputs = [load(o) for (o,) in db.execute("SELECT data FROM outputs WHERE tx=?", (tx,))]
            proven_bad_funding = db.execute("SELECT 1 FROM disqualified WHERE tx=? AND method!='ORIGINAL_ISSUANCE' LIMIT 1", (tx,)).fetchone() is not None
            mandatory = (source["crypto_status"] == "PASS" and source["rules_status"] == "PASS" and
                source["duplicate_key_image"] == "no" and source["cross_asset_origin"] == "no" and
                principal is not None and principal > 0 and bool(own_outputs) and
                all(o["structural_status"] == "PASS" and o["monetary_status"] == "PASS" for o in own_outputs) and
                all(p["verification"] == "PASS" and p["source_type"] == 6 and
                    p["source_asset"] == asset and p["asset"] == asset and
                    amount(p["principal_atomic"]) == principal for p in returned))
            if any(o["monetary_status"] == "CONFIRMED_INVALID" for o in own_outputs):
                state, reason = "DENY", "CONFIRMED_INVALID_STAKE_TRANSACTION"
            elif proven_bad_funding and policy.get("deny_proven_illicit_funding") is True:
                state, reason = "DENY", "CRYPTOGRAPHICALLY_PROVEN_DISQUALIFYING_STAKE_FUNDING"
            elif not mandatory:
                state, reason = "REVIEW", "STAKE_MANDATORY_VALIDATION_UNRESOLVED"
            elif source["height"] > policy["historical_cutoff_height"] or asset not in policy["eligible_assets"]:
                state, reason = "UNKNOWN", "OUTSIDE_HISTORICAL_AMNESTY_SCOPE"
            elif source["height"] < context["scan_start_height"]:
                state, reason = "VERIFIED_CLEAR", "ACCEPTED_OPENING_STAKE_PRINCIPAL"
            else:
                state, reason = "POLICY_CLEAR", "VALID_HISTORICAL_STAKE_UNKNOWN_ANCESTRY"
            counts[state] += 1
            stats[asset].setdefault("stake_principals", {s: 0 for s in STATES})[state] += 1
            row = dict(network=context["network"], block_height=source["height"], block_hash=source["block_hash"],
                transaction=tx, output_index=0, stake=True, asset=asset,
                principal_atomic=str(principal) if principal is not None else NV,
                decision=state, reason_code=reason, payout_status="CANONICAL_RETURN_RECORDED" if returned else "NO_RETURN_AT_SNAPSHOT",
                canonical_payouts=canonical([dict(transaction=p["transaction"], output_index=p["output_index"],
                    height=p["height"], verification=p["verification"]) for p in returned]),
                policy_version=policy["policy_version"], policy_digest=policy_digest,
                evidence_sha256=hashlib.sha256(data.encode()).hexdigest(), certificate_status="UNSIGNED_PLAN_ONLY")
            writer.writerow(row)
            db.execute("INSERT INTO stake_clearances VALUES(?,?,?,?)", (tx, asset, state, canonical(row)))
            if state in ("VERIFIED_CLEAR", "POLICY_CLEAR") and asset == "SAL1":
                plan.write(canonical(dict(transaction=tx, output_index=0, stake=True, asset=asset,
                    classification=state, decision=1, network=context["network"], genesis=context["genesis"],
                    snapshot_height=policy["snapshot_height"], snapshot_hash=policy["snapshot_hash"],
                    cutoff_height=policy["historical_cutoff_height"], policy_digest=policy_digest,
                    certificate_status="UNSIGNED_PLAN_ONLY", payout_inheritance="NATIVE_EXACT_AUTHORIZED_RETURN")) + "\n")
    return counts


def generate(evidence, policy_path, outdir, source_commit=None):
    os.umask(0o077)
    out = Path(outdir)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    db = sqlite3.connect(out / "audit_inventory.sqlite3")
    # Bound the cache to 1 GiB. Ordered indexes avoid sorting multi-gigabyte
    # JSON rows and keep the full-chain report usable on disk-backed inventories.
    db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-1048576;" + SCHEMA)
    context, complete, counts, native_digest = ingest(evidence, db)
    policy = load(Path(policy_path).read_text())
    policy_digest = checked_policy(policy, context)
    write_json(out / "audit_policy.json", policy)
    assets = sorted(set(r[0] for r in db.execute("SELECT DISTINCT asset FROM outputs")) | {"SAL", "SAL1"})
    ledger = {asset: {"opening_authorized_schedule": 0, "mining_emissions": 0,
                     "treasury_issuance": 0, "conversion_issuance": 0, "conversion_reductions": 0,
                     "token_issuance": 0, "verified_burns": 0, "staking_rewards_paid": 0,
                     "staking_principal_returned": 0, "confirmed_illicit_issuance": 0,
                     "illicit_amount_unknown_events": 0, "unresolved_accounting_blocks": 0,
                     "unresolved_transactions": 0} for asset in assets}
    def add(asset, field, value, height):
        if asset not in ledger:
            raise ValueError(f"Event names asset absent from inventory: {asset}")
        if height < context["scan_start_height"] and field not in ("staking_rewards_paid", "staking_principal_returned"):
            sign = -1 if field in ("verified_burns", "conversion_reductions") else 1
            ledger[asset]["opening_authorized_schedule"] += sign * value
        else:
            ledger[asset][field] += value
    for (data,) in db.execute("SELECT data FROM accounting ORDER BY height"):
        r = load(data); a = r["reward_asset"]
        add(a, "mining_emissions", amount(r["base_reward_atomic"]), r["height"])
        add(a, "treasury_issuance", amount(r["treasury_mint_atomic"]), r["height"])
        if r["verification"] != "PASS":
            ledger[a]["unresolved_accounting_blocks"] += 1
    paid_authorizations = set()
    for (data,) in db.execute("SELECT data FROM payouts ORDER BY tx,idx"):
        r = load(data)
        if r["verification"] != "PASS" or r["authorization"] in paid_authorizations:
            continue
        paid_authorizations.add(r["authorization"])
        typ, a, h = r["source_type"], r["asset"], r["height"]
        value = amount(r["actual_atomic"])
        if typ == 6:  # STAKE: return principal and draw rewards from existing reserves.
            principal = amount(r["principal_atomic"])
            if value < principal:
                raise ValueError("Authorized stake payout smaller than principal")
            if h >= context["scan_start_height"]:
                add(a, "staking_principal_returned", principal, h)
                add(a, "staking_rewards_paid", value - principal, h)
        elif r["source_asset"] != a:
            add(a, "token_issuance" if typ == 9 else "conversion_issuance", value, h)
    incidents = []
    for (data,) in db.execute("SELECT data FROM transactions ORDER BY height,id"):
        r = load(data); a = r["source_asset"]; h = r["height"]
        if r["category"] in ("MINER", "PROTOCOL"):
            continue
        if r["crypto_status"] != "PASS" or r["rules_status"] != "PASS" or r["duplicate_key_image"] == "yes":
            if a in ledger: ledger[a]["unresolved_transactions"] += 1
        # A verified commitment burn has a public exact value. Stake deposits
        # and fee rollups move existing supply and are never issuance/burn events.
        value = amount(r["amount_burnt_atomic"])
        if r["crypto_status"] == "PASS" and r["rules_status"] == "PASS":
            if r["category"] in ("BURN", "CREATE_TOKEN"):
                add(a, "verified_burns", value, h)
            elif r["category"] == "AUDIT":
                add(a, "conversion_reductions", value, h)
            elif r["category"] == "CONVERT":
                # Conversion price/slippage rules need a separate verified
                # destination amount; keep this out of exact totals for now.
                ledger[a]["unresolved_transactions"] += 1
        affected = [(i, load(d)) for i, d in db.execute("SELECT idx,data FROM outputs WHERE tx=? AND monetary='CONFIRMED_INVALID' ORDER BY idx", (r["transaction"],))]
        if affected:
            by_asset = sorted({v["asset"] for _, v in affected})
            for invalid_asset in by_asset:
                violation = "+".join(sorted({v["protocol_violation"] for _, v in affected if v["asset"] == invalid_asset}))
                exact = amount(r["invalid_issuance_atomic"]) if r["invalid_issuance_asset"] == invalid_asset else None
                if exact is None: ledger[invalid_asset]["illicit_amount_unknown_events"] += 1
                else: ledger[invalid_asset]["confirmed_illicit_issuance"] += exact
                incidents.append(dict(transaction=r["transaction"], block_height=h, block_hash=r["block_hash"],
                    asset=invalid_asset, confirmed_illicit_atomic=str(exact) if exact is not None else NV,
                    event_class={"NONZERO_CONFIDENTIAL_OUTPUT_AMOUNT": "INVALID_OUTPUT_AMOUNT",
                        "ORDINARY_OUTPUT_ASSET_DIFFERS_FROM_SOURCE": "INVALID_ASSET_ISSUANCE",
                        "DUPLICATE_CANONICAL_KEY_IMAGE": "INVALID_KEY_IMAGE_REUSE"}.get(violation, "MULTIPLE_CONFIRMED_VIOLATIONS"),
                    affected_outputs=[i for i, v in affected if v["asset"] == invalid_asset],
                    violation=violation,
                    historical_hard_fork=r["hard_fork"], historical_rules_status=r["rules_status"],
                    historical_rule_reason=r["rules_reason"],
                    verification="Canonical serialized asset labels plus reconstructed ring/range/balance verification",
                    evidence_sha256=hashlib.sha256(canonical(r).encode()).hexdigest(),
                    proven_descendants=[], identity_attribution="NOT ESTABLISHED",
                    incident="salYAHU" if r["transaction"] == SALYAHU_TX else "ADDITIONAL_CONFIRMED_INVALID_OUTPUT"))
    # Traverse only native-verified one-member rings and exact protocol
    # obligations. Sixteen-member candidate rings never enter this graph.
    from collections import deque
    frontier = deque()
    for tx, idx in db.execute("SELECT tx,idx FROM outputs WHERE monetary='CONFIRMED_INVALID'"):
        db.execute("INSERT INTO disqualified VALUES(?,?,?,?)", (tx, idx, tx, "ORIGINAL_ISSUANCE"))
        frontier.append((tx, idx, tx))
    while frontier:
        parent, parent_idx, root_tx = frontier.popleft()
        children = list(db.execute("SELECT child FROM proven_inputs WHERE parent=? AND parent_idx=?", (parent, parent_idx)))
        for (child,) in children:
            targets = [(child, idx, "VERIFIED_ONE_MEMBER_RING") for (idx,) in db.execute("SELECT idx FROM outputs WHERE tx=?", (child,))]
            for (data,) in db.execute("SELECT data FROM payouts WHERE source_tx=?", (child,)):
                payout = load(data)
                if payout.get("source_transaction") == child and payout["verification"] == "PASS":
                    targets.append((payout["transaction"], payout["output_index"], "VERIFIED_PROTOCOL_OBLIGATION"))
            for target, idx, method in targets:
                if db.execute("INSERT OR IGNORE INTO disqualified VALUES(?,?,?,?)", (target, idx, root_tx, method)).rowcount:
                    frontier.append((target, idx, root_tx))
    for incident in incidents:
        incident["proven_descendants"] = [dict(transaction=tx, output_index=idx, verification=method)
            for tx, idx, method in db.execute("SELECT tx,idx,method FROM disqualified WHERE root_tx=? AND method!='ORIGINAL_ISSUANCE' ORDER BY tx,idx", (incident["transaction"],))]
    # One ordered join, bounded memory. Counts describe historical output
    # identities, never current unspent balances or circulating monetary value.
    fields = ["network", "block_height", "block_hash", "transaction", "output_index", "asset", "category",
              "public_key", "commitment", "public_amount_atomic", "finding_status", "provenance", "decision",
              "reason_code", "policy_version", "policy_digest", "evidence_digest", "authorization_status", "proven_root_transaction", "relationship_verification"]
    stats = {a: {**{s: 0 for s in STATES}, "categories": {}, "unknown_ancestry_outputs": 0,
                 "native_clearance_supported": a == "SAL1" or a.startswith("sal"), "issued_certificates": 0,
                 "known_historical_approved_output_value_atomic": 0, "mature_decoy_candidates_before": 0,
                 "mature_decoy_candidates_after_proposed_clearance": 0, "proven_disqualifying_descendant_outputs": 0} for a in assets}
    with (out / "audit_illicit_outputs.csv").open("w", newline="") as illicit_file, \
         (out / "audit_approved_outputs.csv").open("w", newline="") as approved_file, \
         (out / "audit_clearance_plan.jsonl").open("w") as plan:
        bad = csv.DictWriter(illicit_file, fieldnames=fields); bad.writeheader()
        good = csv.DictWriter(approved_file, fieldnames=fields); good.writeheader()
        rows = db.execute("""SELECT o.data,p.data,a.data,d.method,d.root_tx FROM outputs o
            LEFT JOIN payouts p ON p.tx=o.tx AND p.idx=o.idx
            LEFT JOIN accounting a ON a.height=o.height
            LEFT JOIN disqualified d ON d.tx=o.tx AND d.idx=o.idx ORDER BY o.height,o.tx,o.idx""")
        updates = []
        for data, payout_data, accounting_data, relationship, root_tx in rows:
            r = load(data); payout = load(payout_data) if payout_data else None
            accounting = load(accounting_data) if accounting_data else None
            if payout: r["payout_source_type"] = payout["source_type"]
            r["proven_disqualifying_funding"] = relationship is not None and relationship != "ORIGINAL_ISSUANCE"
            authorization_ok = r["category"] not in ("MINER", "PROTOCOL") or (
                accounting is not None and accounting["verification"] == "PASS" and (
                    r["category"] == "MINER" or (payout is not None and payout["verification"] == "PASS")))
            state, reason = classify(r, policy, authorization_ok)
            a = r["asset"]; stats[a][state] += 1
            stats[a]["proven_disqualifying_descendant_outputs"] += r["proven_disqualifying_funding"]
            if r.get("mature_at_snapshot") == "yes":
                stats[a]["mature_decoy_candidates_before"] += 1
                stats[a]["mature_decoy_candidates_after_proposed_clearance"] += state in ("VERIFIED_CLEAR", "POLICY_CLEAR")
            stats[a]["categories"].setdefault(r["category"], {s: 0 for s in STATES})[state] += 1
            stats[a]["unknown_ancestry_outputs"] += r["provenance"] == "UNKNOWN_PROVENANCE"
            updates.append((state, reason, r["transaction"], r["output_index"]))
            if len(updates) == 10000:
                db.executemany("UPDATE outputs SET state=?,reason=? WHERE tx=? AND idx=?", updates); updates.clear()
            row = dict(network=context["network"], block_height=r["height"], block_hash=r["block_hash"],
                transaction=r["transaction"], output_index=r["output_index"], asset=a, category=r["category"],
                public_key=r["public_key"], commitment=r["commitment"], public_amount_atomic=r["public_amount_atomic"],
                finding_status="CONFIRMED_INVALID" if r["monetary_status"] == "CONFIRMED_INVALID" else
                    "VERIFIED_VALID" if state == "VERIFIED_CLEAR" else "POLICY_CLEARED" if state == "POLICY_CLEAR" else "UNKNOWN_PROVENANCE",
                provenance=r["provenance"], decision=state, reason_code=reason, policy_version=policy["policy_version"],
                policy_digest=policy_digest, evidence_digest=hashlib.sha256(data.encode()).hexdigest(),
                authorization_status="ELIGIBILITY_ONLY_POLICY_NOT_APPROVED", proven_root_transaction=root_tx or "",
                relationship_verification=relationship or "UNKNOWN")
            if r["monetary_status"] == "CONFIRMED_INVALID" or r["proven_disqualifying_funding"]: bad.writerow(row)
            if state in ("VERIFIED_CLEAR", "POLICY_CLEAR"):
                good.writerow(row)
                public = amount(r["public_amount_atomic"])
                if public is not None: stats[a]["known_historical_approved_output_value_atomic"] += public
                if stats[a]["native_clearance_supported"]:
                    plan.write(canonical(dict(transaction=r["transaction"], output_index=r["output_index"],
                        stake=False, asset=a, classification=state, decision=1, network=context["network"],
                        genesis=context["genesis"], snapshot_height=policy["snapshot_height"], snapshot_hash=policy["snapshot_hash"],
                        cutoff_height=policy["historical_cutoff_height"], policy_digest=policy_digest,
                        certificate_status="UNSIGNED_PLAN_ONLY")) + "\n")
        db.executemany("UPDATE outputs SET state=?,reason=? WHERE tx=? AND idx=?", updates)
    db.commit()
    stake_counts = stake_clearances(db, out, context, policy, policy_digest, stats)
    db.execute("CREATE INDEX outputs_asset_state ON outputs(asset,state)")
    db.commit()
    stored_supply = {a: load(data) for a, data in db.execute("SELECT asset,data FROM stored_supply")}
    hard_forks = [dict(version=version, canonical_first_height=height, block_hash=db.execute("SELECT hash FROM blocks WHERE height=?", (height,)).fetchone()[0])
        for version, height in db.execute("SELECT json_extract(data,'$.hard_fork'),MIN(height) FROM blocks GROUP BY json_extract(data,'$.hard_fork') ORDER BY MIN(height)") if version is not None]
    summary_assets = {}
    for a in assets:
        l, s = ledger[a], stats[a]
        known_schedule = l["opening_authorized_schedule"] + l["mining_emissions"] + l["treasury_issuance"] + \
            l["conversion_issuance"] + l["token_issuance"] - l["conversion_reductions"] - l["verified_burns"]
        # Public issuance arithmetic is reproducible, but a reserved reward is
        # not necessarily a paid output. A hidden spend cannot be identified
        # globally. Do not relabel this arithmetic current outstanding supply.
        summary_assets[a] = dict(stored_db_supply_observation=stored_supply.get(a, {"amount_atomic": NV, "verification": "NOT AVAILABLE"}), components_atomic={k: str(v) if not k.endswith(("blocks", "transactions", "events")) else v for k, v in l.items()},
            public_authorized_schedule_net_atomic=str(known_schedule), expected_valid_supply_atomic=NV,
            verified_outstanding_supply_atomic=NV, confirmed_illicit_issuance_atomic=
                str(l["confirmed_illicit_issuance"]) if not l["illicit_amount_unknown_events"] else NV,
            confirmed_known_illicit_issuance_atomic=str(l["confirmed_illicit_issuance"]),
            historical_gross_issuance_atomic=NV, total_valid_monetary_supply_atomic=NV,
            confirmed_invalid_current_supply_atomic=NV, approved_current_monetary_value_atomic=NV,
            denied_current_monetary_value_atomic=NV, unresolved_monetary_discrepancy_atomic=NV,
            proven_disqualifying_descendant_outputs=s["proven_disqualifying_descendant_outputs"], verified_exchange_clearances=0,
            authenticated_exchange_evidence="NOT PROVIDED", outputs=s)
    commit = source_commit or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    checks = [load(data) for (data,) in db.execute("SELECT data FROM verification_checks ORDER BY name")]
    report = dict(schema_version=1, source_commit=commit, context=context, policy=policy, supplementary_checks=checks,
        policy_sha256=policy_digest, native_evidence_sha256=native_digest, counts=counts,
        completion=complete, stake_principal_classifications=stake_counts,
        hard_fork_boundaries=hard_forks, stored_supply_observations=stored_supply, status="INCOMPLETE_RELEASE_VALIDATION_AND_SUPPLY_RECONCILIATION",
        classifications_status="PROPOSED_POLICY_ELIGIBILITY_ONLY", issued_clearance_certificates=0,
        confirmed_incidents=incidents, assets=summary_assets,
        coverage=dict(canonical_public_inventory="COMPLETE", historical_rule_checks="RAN_PER_TRANSACTION",
            ring_range_balance_verification="RAN_PER_ORDINARY_TRANSACTION; SEE_FAILURE_COUNTS",
            independent_issuance_and_staking="RAN_FROM_GENESIS_ACCOUNTING_CONTEXT",
            complete_historical_pow_consensus_replay="NOT RUN BY THIS TOOL", authenticated_exchange_records="NOT PROVIDED",
            private_downstream_funding="NOT PROVIDED", current_unspent_output_inventory="NOT VERIFIABLE FROM PUBLIC RINGS"),
        limitations=["Historical output counts and public output sums are not current circulating supply.",
            "Denied outputs are not burned; neither clearance nor denial changes supply.",
            "Mining schedule includes reward reserves. Stake reward payouts draw those reserves; principal returns are not issuance.",
            "Fee rollups are supply movements, not new issuance or permanent burns.",
            "Full outstanding-supply accounting, conversion liabilities and unclaimed reward reserves require further reconciliation.",
            "Ring membership is not a proven spend; no descendant or human identity is inferred from decoys.",
            "Missing ancestry and missing exchange records do not disqualify otherwise valid historical outputs.",
            "No authenticated purchase exceptions were applied because no private exchange evidence was provided.",
            "The native v4 draft authenticates the policy digest, version and cutoff; legacy SAL clearance remains unsupported. This unsigned plan cannot authorize mainnet.",
            "No main-developer-approved amnesty snapshot, production activation or signing authority was supplied."])
    write_json(out / "audit_supply_report.json", report)
    write_json(out / "audit_illicit_registry.json", dict(context=context, findings=incidents, policy_sha256=policy_digest))
    with (out / "audit_supply_reconciliation.csv").open("w", newline="") as f:
        writer = csv.writer(f); writer.writerow(["asset", "metric", "atomic_value", "scope"])
        for a, values in summary_assets.items():
            for metric, value in values.items():
                if metric.endswith("_atomic") and not isinstance(value, dict):
                    writer.writerow([a, metric, value, "PUBLIC_EVIDENCE_ONLY"])
            for metric, value in values["components_atomic"].items():
                writer.writerow([a, metric, value, "OPENING_CONTEXT_OR_AUDIT_PERIOD_AS_NAMED"])
    write_markdown(out, report)
    db.close()
    manifest = {p.name: digest(p) for p in sorted(out.iterdir()) if p.is_file()}
    write_json(out / "audit_report_manifest.json", manifest)
    return report


def incident_text(incidents):
    if not incidents:
        return "No confirmed invalid-output events in this category were established by the completed scan."
    lines = []
    for i in incidents:
        lines += [f"- Transaction `{i['transaction']}`; height **{i['block_height']}**; block `{i['block_hash']}`; "
                  f"asset `{i['asset']}`; exact excess issuance **{i['confirmed_illicit_atomic']} atomic**; "
                  f"outputs {', '.join(map(str, i['affected_outputs']))}.",
                  f"  Violation: `{i['violation']}`. Historical HF {i['historical_hard_fork']}; "
                  f"historical rule-engine result `{i['historical_rules_status']}`. Evidence SHA256 `{i['evidence_sha256']}`.",
                  f"  Proposed DENY; no issued certificate. Proven descendants: {len(i['proven_descendants'])}. Human attribution: not established."]
    return "\n".join(lines)


def write_markdown(out, report):
    c, assets = report["context"], report["assets"]
    salyahu = [i for i in report["confirmed_incidents"] if i["incident"] == "salYAHU"]
    additional = [i for i in report["confirmed_incidents"] if i["incident"] != "salYAHU"]
    for name, title, incidents in (("audit_salyahu_report.md", "salYAHU issuance evidence", salyahu),
                                   ("audit_other_bad_actor_report.md", "Additional invalid-output and bad actor evidence", additional)):
        (out / name).write_text(f"# {title}\n\n" + incident_text(incidents) +
            "\n\nInvalid output creation is distinct from a measured net increase in supply. An unknown excess amount is not zero and is not assigned an invented value. "
            "Incident labels identify protocol events. They do not establish a person's identity or implicate a wallet, exchange, or ring decoy.\n")
    metrics = [("Expected valid supply", "expected_valid_supply_atomic"),
               ("Verified outstanding supply", "verified_outstanding_supply_atomic"),
               ("Known excess issuance", "confirmed_known_illicit_issuance_atomic"),
               ("Confirmed illicit issuance (atomic)", "confirmed_illicit_issuance_atomic"),
               ("Denied monetary value", "denied_current_monetary_value_atomic"),
               ("Approved current monetary value", "approved_current_monetary_value_atomic"),
               ("Unresolved monetary discrepancy", "unresolved_monetary_discrepancy_atomic")]
    lines = ["# Salvium historical financial and forensic report", "",
        "**Status: complete public inventory; supply reconciliation and release validation remain incomplete.**", "",
        f"Source commit: `{report['source_commit']}`. Network `{c['network']}`; genesis `{c['genesis']}`.",
        f"Accepted opening: {c['opening_height']} (`{c['opening_block_hash']}`). "
        f"Forensic audit period: {c['scan_start_height']}–{c['scan_end_height']}; ending block `{c['ending_block_hash']}`.",
        f"Inventory includes genesis–{c['scan_end_height']} as opening context. Policy `{report['policy']['policy_version']}`; "
        f"cutoff {report['policy']['historical_cutoff_height']}; digest `{report['policy_sha256']}`.",
        "Production activation remains disabled. Every clearance below is proposed eligibility; **zero certificates issued**.", "",
        "| Asset | " + " | ".join(title for title, _ in metrics) + " |", "|---|" + "---|" * len(metrics)]
    for asset, values in assets.items():
        lines.append("| " + asset + " | " + " | ".join(str(values[key]) for _, key in metrics) + " |")
    lines += ["", "| Asset | Verified clear | Policy clear | Denied | Review | Outside scope |",
              "|---|---:|---:|---:|---:|---:|"]
    for asset, values in assets.items():
        lines.append("| " + asset + " | " + " | ".join(str(values["outputs"][state]) for state in
            ("VERIFIED_CLEAR", "POLICY_CLEAR", "DENY", "REVIEW", "UNKNOWN")) + " |")
    from collections import Counter
    incident_classes = Counter(i["violation"] for i in additional)
    additional_summary = (f"**{len(additional)} confirmed invalid-output transaction/asset events**. "
        "These counts do not establish a net monetary issuance amount or a number of people. "
        "Full transaction references and evidence digests are in [the additional incident report](audit_other_bad_actor_report.md) "
        "and `audit_illicit_registry.json`.") if additional else incident_text([])
    if incident_classes:
        additional_summary += "\n\n" + "\n".join(f"- `{kind}`: {count} events." for kind, count in sorted(incident_classes.items()))
    lines += ["", "All monetary figures are atomic units per asset. No cross-asset monetary total is used.", "",
        "## Stake funds", "",
        "Stake principals are separately inventoried in `audit_stake_clearances.csv` and eligible SAL1 principals appear with `stake: true` in the unsigned clearance plan. "
        "Principal clearance authorizes the exact native protocol return; an already-created return and a future scheduled return inherit that authorization, subject to ordinary maturity. "
        "The principal and its return are not counted twice as monetary issuance or as additional canonical outputs.",
        "Proposed principal classifications: " + canonical(report["stake_principal_classifications"]) + ".", "",
        "## salYAHU findings", "", incident_text(salyahu), "", "## Additional invalid outputs / other bad actor findings", "", additional_summary, "",
        "## Accounting and coverage", "",
        f"Canonical transactions inventoried: {report['counts']['transactions']}; canonical outputs: {report['counts']['outputs']}. "
        f"Native cryptographic failures requiring investigation: {report['completion']['cryptographic_failures']}.",
        "Exact known original issuance amounts are counted once per source transaction and asset. Descendant outputs never add new issuance.",
        "Authorized mining schedules, treasury creation, conversion issuance/reductions, token issuance, burns, stake rewards paid "
        "and principal returns are itemized per asset in the JSON and reconciliation CSV. Staking and conversions are not added twice.",
        "The public authorized schedule arithmetic is reported separately from verified outstanding supply. "
        "The latter cannot be inferred by summing historical outputs or by treating denied funds as destroyed.", "",
        "## Required financial answers", "",
        "1. Legitimate SAL/SAL1 supply: NOT VERIFIABLE until opening balances, reward reserves and all supply reductions reconcile.",
        "2. Verified outstanding supply: NOT VERIFIABLE from this public output inventory.",
        "3. Demonstrably illicit creation: see the per-asset table and source-transaction registry.",
        "4. salYAHU original issuance: see the separate salYAHU finding above.",
        f"5. Additional confirmed source transaction/asset events: {len(additional)}.",
        f"6. Proposed denied outputs: {sum(a['outputs']['DENY'] for a in assets.values())}; no consensus denials issued.",
        f"7. Outputs eligible for approval: {sum(a['outputs']['VERIFIED_CLEAR'] + a['outputs']['POLICY_CLEAR'] for a in assets.values())}; zero certificates issued.",
        "8. Current monetary value approved: NOT VERIFIABLE; historical output values may represent repeated movement of the same coins.",
        f"9. Outputs with mandatory checks unresolved: {sum(a['outputs']['REVIEW'] for a in assets.values())}; unresolved monetary value NOT VERIFIABLE.",
        "10. Verified supply reconciliation: INCOMPLETE; available public schedule arithmetic is reproducible but does not establish exact current supply.", "",
        "## Limits and remaining release requirements", ""]
    lines += ["- " + item for item in report["limitations"]]
    lines += ["", "The separate salYAHU and additional bad actor reports are included in this same report bundle. "
        "Build, fakechain, wallet, certificate, replay, migration and privacy qualification must be recorded against the final source and binaries.", ""]
    (out / "audit_final_summary.md").write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--outdir", required=True, type=Path)
    args = parser.parse_args()
    r = generate(args.evidence, args.policy, args.outdir)
    print(f"REPORT_COMPLETE directory={args.outdir} outputs={r['counts']['outputs']} status={r['status']}")


if __name__ == "__main__":
    main()
