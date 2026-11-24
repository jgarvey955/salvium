#!/usr/bin/env python3
"""Funded exchange and independent-owner subaddresses, without upstream history."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_complex_regtest import CoinbaseReader
from audit_clearance_regtest import PrivateChain, rejected
from audit_tokens_regtest import COIN, relay as relay_transaction


def relay(chain, response, token=False):
    # A batch can contain several SAL1 fee transactions and token transfers.
    # Read each transaction's real input asset instead of treating every
    # transaction before the final one as an SAL1 fee authorization.
    for txid, blob in zip(response["tx_hash_list"], response["tx_blob_list"], strict=True):
        reader = CoinbaseReader(bytes.fromhex(blob))
        assert reader.integer() == 5
        reader.integer()
        assert reader.integer() > 0 and reader.byte() == 2 and reader.integer() == 0
        length = reader.integer()
        asset = reader.blob[reader.pos:reader.pos + length].decode("ascii")
        assert asset in ("SAL1", "salYAHU") and (token or asset == "SAL1"), asset
        relay_transaction(chain, {"tx_hash_list": [txid], "tx_blob_list": [blob]},
                          token=asset == "salYAHU")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True,
                        help="Completed audit_token_security_regtest fixture; copied before use")
    parser.add_argument("--verify-supply", action="store_true",
                        help="Reconcile all owners, miner, sink and canonical per-asset circulating supply")
    args = parser.parse_args()
    source, bins = args.fixture.resolve(), args.binaries.resolve()
    original = json.loads((source / "result.json").read_text())
    assert source.name.startswith("salvium-token-security-")
    assert original["status"] == "TOKEN_SECURITY_PASS" and original["root"] == str(source)
    root = Path(tempfile.mkdtemp(prefix="salvium-exchange-subaddresses-"))
    print(root, flush=True)
    for name in ("chain", "miner", "alice", "bob", "observer"):
        shutil.copytree(source / name, root / name)
    tool = bins / "salvium-audit-review"

    def command(*arguments):
        result = subprocess.run([str(tool), *map(str, arguments)], capture_output=True,
                                text=True, timeout=300)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    secret = root / "developer.key"
    public = command("--keygen", secret).split()[-1]
    activation = original["completion"]["scan_end_height"] + 200

    def launch():
        chain = PrivateChain(bins, root)
        chain.activation, chain.authority = activation, public
        try:
            chain.launch()
            for wallet in chain.wallets:
                chain.refresh_wallet(wallet)
            return chain
        except BaseException:
            chain.close()
            raise

    chain = launch()
    paths, checks, spends = {}, [], []

    def balance(owner, account, minor, asset):
        response = chain.wallets[owner].call("get_balance", {
            "account_index": account, "asset_type": asset})
        row = next((r for r in response.get("balances", []) if r["asset_type"] == asset), {})
        return next((r for r in row.get("per_subaddress", []) if r["address_index"] == minor),
                    {"balance": 0, "unlocked_balance": 0})

    def transfer(owner, destinations, asset, account=0, minors=None):
        return chain.wallets[owner].call("transfer_split", {
            "destinations": [{"address": address, "amount": amount, "asset_type": asset}
                             for address, amount in destinations],
            "source_asset": asset, "dest_asset": asset, "tx_type": 3,
            "account_index": account, "subaddr_indices": [] if minors is None else minors,
            "priority": 1, "ring_size": 16, "get_tx_hex": True, "do_not_relay": True})

    def export(owner, name, **scope):
        request = {"export_evidence": True, "snapshot_height": activation, **scope}
        response = chain.wallets[owner].call("audit", request)
        evidence = json.loads(response["private_evidence"])
        while response["evidence_more"]:
            response = chain.wallets[owner].call("audit", {
                **request, "export_id": response["export_id"],
                "evidence_offset": response["next_evidence_offset"]})
            evidence["packages"].extend(json.loads(response["private_evidence"])["packages"])
        path = root / (name + ".json")
        path.write_text(json.dumps(evidence))
        status = chain.wallets[owner].call("audit", {"status_only": True, **scope})
        assert not status["outputs_more"], status
        return path, status["outputs"]

    def review(name, evidence, public_work_limit=0):
        folder = root / name
        inputs = evidence if isinstance(evidence, list) else [evidence]
        command("--data-dir", root / "chain/fake", "--network", "fakechain", "--opening", "0",
                "--activation-height", activation, "--clearance-authority", public,
                "--public-work-limit", public_work_limit, "--input", *inputs,
                "--sign-key", secret, "--outdir", folder)
        report = json.loads((folder / "case.json").read_text())
        assert report["outputs"] and all(r["state"] == "CLEARED" and not r.get("decision")
                                         for r in report["outputs"]), report
        assert not json.loads((folder / "review-queue.json").read_text()).get("decisions", [])
        if not public_work_limit:
            assert any(r["reason"] == "OWNERSHIP_VERIFIED_NO_PROVEN_ILLICIT_ORIGIN"
                       for r in report["outputs"]), report
        return folder

    def publish(folder):
        manifest = json.loads((folder / "clearances.public").read_text())
        assert manifest["batches"]
        for batch in manifest["batches"]:
            chain.daemon.call("submit_audit_clearance", {"data": batch})

    def balances():
        return {(owner, account, minor, asset): balance(owner, account, minor, asset)["unlocked_balance"]
                for owner, entries in paths.items() for account, minor, _ in entries
                for asset in ("SAL1", "salYAHU")}

    def check_inventory(owner):
        wallet = chain.wallets[owner]
        inventory = wallet.call("audit", {"status_only": True})
        assert not inventory["outputs_more"], inventory
        totals = {}
        for row in inventory["outputs"]:
            if not row["spent"] and not row["stake"]:
                asset = row["asset_type"]
                totals[asset] = totals.get(asset, 0) + row["amount"]
        expected = wallet.call("get_balance", {"all_accounts": True, "all_assets": True})
        expected = {r["asset_type"]: r["balance"] for r in expected.get("balances", []) if r["balance"]}
        assert {asset: amount for asset, amount in totals.items() if amount} == expected, (totals, expected)
        reported = {r["asset_type"]: r["good"] + r["bad"] + r["unresolved"]
                    for r in inventory.get("balances", [])}
        assert {asset: amount for asset, amount in reported.items() if amount} == expected, (reported, expected)

    try:
        assert chain.tip() == original["completion"]["scan_end_height"]
        for owner, label in ((1, "exchange-customer"), (2, "independent-owner")):
            wallet = chain.wallets[owner]
            account = wallet.call("create_account", {"label": label})["account_index"]
            for major in (0, account):
                wallet.call("create_address", {"account_index": major, "count": 2, "label": label})
            entries = []
            for major, minor in ((0, 1), (0, 2), (account, 0), (account, 1)):
                rows = wallet.call("get_address", {"account_index": major,
                    "address_index": [minor], "carrot": True})["addresses"]
                assert len(rows) == 1 and rows[0]["address_index"] == minor, rows
                entries.append((major, minor, rows[0]["address_carrot"]))
            paths[owner] = entries
        destinations = [(address, 10 * COIN) for entries in paths.values() for _, _, address in entries]
        # Separate outputs keep scoped SAL1 withdrawals and token fee inputs
        # available even when their change is sent to a different subaddress.
        for _ in range(5):
            relay(chain, transfer(0, destinations, "SAL1")); chain.mine(11)
        # Provide enough cleared token outputs for full sixteen-member rings.
        for _ in range(3):
            relay(chain, transfer(0, [(address, 5 * COIN) for address, _ in destinations],
                                  "salYAHU"), token=True)
            chain.mine(11)
        for owner, entries in paths.items():
            for account, minor, _ in entries:
                assert balance(owner, account, minor, "SAL1")["unlocked_balance"] == 50 * COIN
                assert balance(owner, account, minor, "salYAHU")["unlocked_balance"] == 15 * COIN
        checks.append("SAL1 and salYAHU funded on eight actual exchange and independent-owner addresses across four accounts")
        print("FUNDED_SUBADDRESSES_PASS", flush=True)

        # The recipient later proves this withdrawal without the exchange,
        # token issuer or original fee-funding owner's evidence.
        account, minor, _ = paths[1][0]
        withdrawal = transfer(1, [(paths[2][-1][2], 2 * COIN)], "salYAHU", account, [minor])
        relay(chain, withdrawal, token=True); chain.mine(11)
        assert chain.tip() < activation
        chain.mine(activation - chain.tip())
        assert not any(balances().values()), balances()
        for owner in paths:
            check_inventory(owner)
        checks.append("audit per-asset totals and every unspent output reconcile exactly to all-account wallet balances")
        rejected(lambda: transfer(1, [(paths[2][0][2], COIN)], "salYAHU", 0, [1]))
        checks.append("private audit activation freezes both assets on every funded account and subaddress")

        exports = {}
        for owner in paths:
            exports[owner], rows = export(owner, f"owner-{owner}")
            expected = {(major, minor, asset) for major, minor, _ in paths[owner]
                        for asset in ("SAL1", "salYAHU")}
            actual = {(r["account"], r["subaddress"], r["asset_type"]) for r in rows if not r["spent"]}
            assert expected <= actual, (owner, expected - actual)
            assert all(not r["key_image"] for r in rows), rows
        checks.append("default private export discovers all funded accounts, subaddresses and assets")

        issuer, _ = export(0, "issuer-and-original-funding-owner")
        ancestry = review("all-available-history", [issuer, exports[1], exports[2]], 50000)
        report = json.loads((ancestry / "case.json").read_text())
        reasons = {r["reason"] for r in report["outputs"]}
        assert "ALL_FUNDING_VERIFIED" in reasons and "VERIFIED_ISSUANCE" in reasons, reasons
        checks.append("available owner proofs trace exchange deposits, withdrawal, token creation and SAL1 funding back to canonical issuance")

        account, minor, _ = paths[1][-1]
        scope = {"all_accounts": False, "account_index": account, "subaddr_indices": [minor]}
        rows = chain.wallets[1].call("audit", {"status_only": True, **scope})["outputs"]
        assert rows and all((r["account"], r["subaddress"]) == (account, minor) for r in rows), rows
        assert {r["asset_type"] for r in rows} == {"SAL1", "salYAHU"}, rows
        rejected(lambda: chain.wallets[1].call("audit", {"export_evidence": True, **scope}))
        rejected(lambda: chain.wallets[1].call("audit", {
            "export_evidence": True, "account_index": account}))
        checks.append("scoped status reports exactly both assets at the selected subaddress; partial private exports are rejected to preserve full-wallet coverage")

        for owner, name in ((1, "exchange-without-depositor-history"),
                            (2, "owner-without-exchange-or-issuer-history")):
            folder = review(name, exports[owner])
            receipts = [p for p in folder.glob("*.json") if p.name not in ("case.json", "review-queue.json")]
            assert receipts
            rejected(lambda: chain.wallets[3 - owner].call("audit", {
                "review_result": receipts[0].read_text(), "developer_public_key": public}))
            publish(folder); chain.mine(1)
            if owner == 1:
                for key, amount in balances().items():
                    assert (amount > 0) == (key[0] == 1), (key, amount)
        assert all(amount > 0 for amount in balances().values()), balances()
        assert chain.balance(0)["unlocked_balance"] == 0
        checks.append("exchange and other owner clear independently without issuer, depositor, counterparty or exchange history and without manual decisions")
        checks.append("exchange clearance does not unlock another owner's funds; wrong-owner receipts are rejected and absent issuer remains frozen")
        print("RECIPIENT_ONLY_CLEARANCE_PASS", flush=True)

        for owner, entries in paths.items():
            for account, minor, _ in entries:
                destination = paths[3 - owner][-1][2]
                for asset in ("SAL1", "salYAHU"):
                    sent = transfer(owner, [(destination, COIN)], asset, account, [minor])
                    relay(chain, sent, token=asset == "salYAHU"); chain.mine(11)
                    txid = sent["tx_hash_list"][-1]
                    _, height = chain.transaction(txid)
                    spends.append({"owner": owner, "account": account, "subaddress": minor,
                                   "asset": asset, "transaction": txid, "height": height})
        assert len(spends) == 16
        for owner in paths:
            check_inventory(owner)
        checks.append("all eight funded customer/owner addresses spend SAL1 and salYAHU using explicit account/subaddress selection after clearance")
        print("ALL_SCOPED_SPENDS_PASS", flush=True)

        expected_balances = balances()
        saved = [chain.daemon.call("get_block", {"height": h})["blob"]
                 for h in range(activation + 1, chain.tip() + 1)]
        chain.daemon.request("/pop_blocks", {"nblocks": chain.tip() - activation})
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        assert not any(balances().values()), balances()
        for blob in saved:
            chain.daemon.call("submit_block", [blob])
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        assert balances() == expected_balances
        checks.append("reorg revokes every scoped clearance; canonical replay restores balances and all sixteen spends")
        height = chain.tip()
    finally:
        chain.close()
    chain = launch()
    try:
        assert chain.tip() == height and balances() == expected_balances
        for owner in paths:
            check_inventory(owner)
        for sent in spends:
            assert chain.transaction(sent["transaction"])[1] == sent["height"]
        checks.append("daemon and wallet restart preserve funded subaddress balances and both-asset spend history")
        if args.verify_supply:
            from audit_supply_regtest import verify_supply
            supply = verify_supply(chain, tool, public, secret, root)
            checks.extend(supply["checks"])
    finally:
        chain.close()
    result = dict(status="EXCHANGE_SUBADDRESSES_PASS", fixture=str(root), source_fixture=str(source),
        activation=activation, final_height=height, funded_addresses=8, scoped_spends=spends, checks=checks,
        binary_sha256={name: hashlib.sha256((bins / name).read_bytes()).hexdigest()
                       for name in ("salviumd", "salvium-wallet-rpc", "salvium-audit-review")})
    if args.verify_supply:
        result["supply"] = supply
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
