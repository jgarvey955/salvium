#!/usr/bin/env python3
"""Private ownership review and clearance of canonical token generation and transfers."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_clearance_regtest import PrivateChain, rejected
from audit_tokens_regtest import COIN, relay, wait_for_template
from audit_complex_regtest import CoinbaseReader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True,
                        help="Completed audit_token_security_regtest fixture; copied before use")
    args = parser.parse_args()
    source = args.fixture.resolve()
    assert source.name.startswith("salvium-token-security-")
    original = json.loads((source / "result.json").read_text())
    assert original["status"] == "TOKEN_SECURITY_PASS" and original["root"] == str(source)
    root = Path(tempfile.mkdtemp(prefix="salvium-token-clearance-"))
    print(root, flush=True)
    for name in ("chain", "miner", "alice", "bob", "observer"):
        shutil.copytree(source / name, root / name)
    bins = args.binaries.resolve()
    tool = bins / "salvium-audit-review"

    def command(*arguments):
        result = subprocess.run([str(tool), *map(str, arguments)], capture_output=True,
                                text=True, timeout=300)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    secret = root / "developer.key"
    public = command("--keygen", secret).split()[-1]
    activation = original["completion"]["scan_end_height"] + 90

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
    checks = []

    def token_balance(index):
        rows = chain.wallets[index].call("get_balance", {"account_index": 0, "all_assets": True})
        return next((r for r in rows.get("balances", []) if r["asset_type"] == "salYAHU"),
                    {"balance": 0, "unlocked_balance": 0})

    def transfer(sender, recipient, amount):
        # Account-wide fee selection includes SAL1 change subaddresses.
        return chain.wallets[sender].call("transfer_split", {
            "destinations": [{"address": chain.addresses[recipient], "amount": amount,
                              "asset_type": "salYAHU"}],
            "source_asset": "salYAHU", "dest_asset": "salYAHU", "tx_type": 3,
            "account_index": 0, "subaddr_indices": [], "priority": 1, "ring_size": 1,
            "get_tx_hex": True, "do_not_relay": True})

    try:
        assert chain.tip() == original["completion"]["scan_end_height"]
        assert token_balance(1)["balance"] == 0 and token_balance(2)["balance"] == 0
        for recipient in (1, 2):
            funding = chain.transfer(0, recipient, 20 * COIN, relay=False)
            chain.submit(funding, True); chain.mine(11)
        first = transfer(0, 1, 100 * COIN)
        relay(chain, first, token=True); chain.mine(11)
        onward = transfer(1, 2, 20 * COIN)
        relay(chain, onward, token=True); chain.mine(11)
        stake = chain.transfer(0, 0, 12 * COIN, tx_type=6, relay=False)
        chain.submit(stake, True); chain.mine(11)
        prepaid = transfer(1, 2, COIN)
        relay(chain, {key: prepaid[key][:1] for key in ("tx_hash_list", "tx_blob_list")})
        assert chain.tip() < activation
        chain.mine(activation - chain.tip())
        assert token_balance(1)["balance"] == 80 * COIN and token_balance(1)["unlocked_balance"] == 0
        assert token_balance(2)["balance"] == 20 * COIN and token_balance(2)["unlocked_balance"] == 0
        rejected(lambda: transfer(1, 2, COIN))
        response = chain.daemon.request("/send_raw_transaction", {
            "tx_as_hex": prepaid["tx_blob_list"][-1], "source_asset_type": "salYAHU",
            "do_not_relay": True, "do_sanity_checks": False})
        assert response["status"] != "OK", response
        checks.append("wallet and consensus freeze a prepaid historical token spend at activation")
        snapshot = chain.tip()
        evidence, identities = [], []
        for index, wallet in enumerate(chain.wallets):
            response = wallet.call("audit", {"export_evidence": True, "snapshot_height": snapshot})
            request = json.loads(response["private_evidence"])
            while response["evidence_more"]:
                response = wallet.call("audit", {"export_evidence": True, "snapshot_height": snapshot,
                    "export_id": response["export_id"], "evidence_offset": response["next_evidence_offset"]})
                request["packages"].extend(json.loads(response["private_evidence"])["packages"])
            path = root / f"owner-{index}.json"
            path.write_text(json.dumps(request)); evidence.append(path)
            rows = wallet.call("audit", {"status_only": True})["outputs"]
            identities.append({(r["transaction"], r["output_index"], r["stake"]) for r in rows})

        def review(name, inputs):
            folder = root / name
            print(name, command("--data-dir", root / "chain/fake", "--network", "fakechain",
                "--opening", "0", "--activation-height", activation, "--clearance-authority", public,
                "--public-work-limit", "0", "--input", *inputs, "--sign-key", secret,
                "--outdir", folder).strip(), flush=True)
            return folder, json.loads((folder / "case.json").read_text())

        missing_folder, missing = review("missing-issuer", evidence[1:])
        tokens = [r for r in missing["outputs"] if r["asset_type"] == "salYAHU"]
        assert tokens and all(r["state"] == "CLEARED" and r["reason"] == "OWNERSHIP_VERIFIED_NO_PROVEN_ILLICIT_ORIGIN" for r in tokens), missing
        complete, report = review("all-owners", evidence)
        assert report["outputs"] and all(r["state"] == "CLEARED" for r in report["outputs"]), report
        tokens = [r for r in report["outputs"] if r["asset_type"] == "salYAHU"]
        assert any(r["spent"] for r in tokens) and any(not r["spent"] for r in tokens), tokens
        assert any(r["stake"] and r["transaction"] == stake["tx_hash"] for r in report["outputs"])
        checks.append("native proofs reconcile token issuance, spent ancestry, two owners and pending SAL1 stake")
        checks.append("missing issuer or funding owner needs no manual clearance without proven illicit origin")
        receipts = [p for p in complete.glob("*.json") if p.name not in ("case.json", "review-queue.json")]
        for index, wallet in enumerate(chain.wallets):
            for receipt in receipts:
                data = json.loads(receipt.read_text())
                if not all((r["transaction"], r["output_index"], r["stake"]) in identities[index]
                           for r in data["outputs"]):
                    continue
                if any(r["asset_type"] == "salYAHU" for r in data["outputs"]):
                    forged = copy.deepcopy(data)
                    next(r for r in forged["outputs"] if r["asset_type"] == "salYAHU")["amount"] += 1
                    rejected(lambda: wallet.call("audit", {"review_result": json.dumps(forged),
                                                           "developer_public_key": public}))
        # Publish only the two recipient owners' case. The issuer's and
        # exchange funding history is deliberately absent from this decision.
        manifest = json.loads((missing_folder / "clearances.public").read_text())
        assert manifest["batches"]
        for batch in manifest["batches"]:
            chain.daemon.call("submit_audit_clearance", {"data": batch})
        assert token_balance(1)["unlocked_balance"] == 0
        confirmed = chain.mine(1)["height"]
        assert token_balance(1)["unlocked_balance"] == 80 * COIN
        assert token_balance(2)["unlocked_balance"] == 20 * COIN
        assert chain.balance(1)["unlocked_balance"] > 0 and chain.balance(2)["unlocked_balance"] > 0
        checks.append("recipient-only no-history case publishes actual SAL1 and token clearance without issuer evidence")
        # A signature prepared before activation may contain now-frozen
        # decoys. Confirm that the gate rejects those members; a fresh wallet
        # spend must select the cleared population without the issuer's help.
        eligible = set()
        query = {"asset_type": "salYAHU"}
        while True:
            page = chain.daemon.call("get_private_audit_outputs", query)
            eligible.update(row["index"] for row in page.get("outputs", []))
            if not page["more"]:
                break
            query["from_index"] = page["outputs"][-1]["index"] + 1
        reader = CoinbaseReader(bytes.fromhex(prepaid["tx_blob_list"][-1]))
        reader.integer(); reader.integer()
        members = set()
        for _ in range(reader.integer()):
            assert reader.byte() == 2 and reader.integer() == 0
            length = reader.integer()
            assert reader.blob[reader.pos:reader.pos + length] == b"salYAHU"
            reader.pos += length
            absolute = 0
            for _ in range(reader.integer()):
                absolute += reader.integer(); members.add(absolute)
            reader.pos += 32
        response = chain.daemon.request("/send_raw_transaction", {
            "tx_as_hex": prepaid["tx_blob_list"][-1], "source_asset_type": "salYAHU",
            "do_not_relay": True, "do_sanity_checks": False})
        if members <= eligible:
            assert response["status"] == "OK", response
            wait_for_template(chain, prepaid["tx_hash_list"][-1]); chain.mine(1)
            spent = prepaid
            assert chain.tip() == confirmed + 1
        else:
            assert response["status"] != "OK", response
            spent = transfer(1, 2, COIN)
            relay(chain, spent, token=True)
            assert chain.tip() == confirmed + 2
            checks.append("uncleared pre-activation decoys require a fresh ring, not issuer history or manual clearance")
        spend_height = chain.tip()
        assert spent["tx_hash_list"][-1] in chain.block(spend_height)["tx_hashes"]
        chain.mine(11)
        assert token_balance(2)["unlocked_balance"] == 21 * COIN
        checks.append("forged token receipt rejected; recipient-only clearance permits a real token spend with ordinary fee authorization")
        saved = [chain.daemon.call("get_block", {"height": height})["blob"]
                 for height in range(snapshot + 1, chain.tip() + 1)]
        chain.daemon.request("/pop_blocks", {"nblocks": chain.tip() - snapshot})
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        assert token_balance(1)["unlocked_balance"] == 0 and token_balance(2)["unlocked_balance"] == 0
        rejected(lambda: transfer(1, 2, COIN))
        for block in saved:
            chain.daemon.call("submit_block", [block])
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        assert token_balance(2)["unlocked_balance"] == 21 * COIN
        height = chain.tip()
        checks.append("reorg revokes token clearance and canonical replay restores it")
    finally:
        chain.close()
    chain = launch()
    try:
        assert chain.tip() == height and token_balance(2)["unlocked_balance"] == 21 * COIN
        assert chain.transaction(spent["tx_hash_list"][-1])[1] == spend_height
        checks.append("daemon and wallet restart preserve token clearance and inherited transfer")
    finally:
        chain.close()
    result = dict(status="TOKEN_PRIVATE_CLEARANCE_PASS", fixture=str(root), source_fixture=str(source),
        activation=activation, final_height=height, checks=checks,
        binary_sha256={name: hashlib.sha256((bins / name).read_bytes()).hexdigest()
                       for name in ("salviumd", "salvium-wallet-rpc", "salvium-audit-review")})
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
