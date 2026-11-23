#!/usr/bin/env python3
"""Current token creation, fee-backed transfer and metadata checks on an isolated chain."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from audit_release_regtest import LocalChain, RpcError
from audit_tokens_regtest import relay, token_transfer
from audit_complex_regtest import CoinbaseReader

COIN = 100_000_000


class TokenSecurityChain(LocalChain):
    def start(self, name, command, rpc, ready_method):
        if name == "daemon": command += ["--keep-fakechain"]
        return super().start(name, command, rpc, ready_method)


def asset_balance(wallet, asset):
    result = wallet.call("get_balance", {"account_index": 0, "all_assets": True})
    return next((x for x in result.get("balances", []) if x["asset_type"] == asset),
                {"balance": 0, "unlocked_balance": 0})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, default=Path("build/audit/release/bin"))
    parser.add_argument("--fixture", type=Path, help="Resume this test's own isolated token fixture")
    args = parser.parse_args()
    root = args.fixture.resolve() if args.fixture else Path(tempfile.mkdtemp(prefix="salvium-token-security-"))
    if args.fixture:
        assert root.name.startswith("salvium-token-security-") and (root / "isolated.conf").is_file()
    print(root, flush=True)
    chain = TokenSecurityChain(args.binaries.resolve(), root)
    checks = []
    try:
        chain.launch()
        if args.fixture:
            assert chain.tip() >= 21601
            chain.daemon.call("flush_txpool", {"confirm_all": True})
            for wallet in chain.wallets:
                wallet.call("rescan_blockchain", {"hard": False})
                chain.refresh_wallet(wallet)
        else:
            chain.mine(100, fund_miner=True)
        empty = chain.wallets[2].call("get_balance", {"account_index": 0, "all_assets": True})
        assert not empty.get("balances", []), empty
        checks.append("account-wide asset inventory works for empty and token-only wallets")
        try:
            chain.daemon.call("get_output_distribution", {"amounts": [0] * 65})
        except RpcError as error:
            assert "Too many amounts" in str(error), error
        else:
            raise AssertionError("Unbounded output distribution request accepted")
        population = chain.daemon.call("get_output_distribution", {"amounts": [0] * 64,
            "binary": False, "cumulative": False, "rct_asset_type": "SAL1"})
        assert len(population["distributions"]) == 1, population
        checks.append("output distribution work bounded and duplicate amounts normalized")
        for text in ("[]", "null", '"metadata"', '{"hash":"invalid"}'):
            try:
                chain.wallets[0].call("create_token", dict(ticker="TSTQ", supply=1000, account_index=0,
                    subaddr_indices=[0], token_metadata_hex=text.encode().hex(), do_not_relay=True))
            except RpcError as error:
                assert "metadata" in str(error).lower(), error
            else:
                raise AssertionError("Invalid metadata accepted")
            chain.wallets[0].call("get_version")
        checks.append("invalid metadata rejected and wallet remains responsive")
        if not args.fixture:
            while chain.tip() < 21601:
                chain.mine(min(500, 21601 - chain.tip()), refresh=False)
            for wallet in chain.wallets: chain.refresh_wallet(wallet)
            creation = chain.wallets[0].call("create_token", dict(ticker="YAHU", supply=1_000_000,
                account_index=0, subaddr_indices=[0], name='Metadata with "quotes" and \\ characters',
                url="https://example.invalid/token", get_tx_hex=True, do_not_relay=True))
            relay(chain, creation); chain.mine(61)
            checks.append("canonical metadata and protocol-authorized token issuance")
        else:
            checks.append("resumed canonical token issuance on this isolated chain")
        previous_token = asset_balance(chain.wallets[1], "salYAHU")
        previous_balance = previous_token["balance"]
        previous_unlocked = previous_token["unlocked_balance"]
        payment = token_transfer(chain, 0, 1, 100 * COIN)
        assert len(payment["tx_blob_list"]) == 2
        original = bytes.fromhex(payment["tx_blob_list"][-1])
        reader = CoinbaseReader(original)
        assert reader.integer() == 5
        reader.integer()
        n_inputs = reader.integer()
        pieces = original.split(b"\x07salYAHU")
        assert len(pieces) >= n_inputs + 5
        malformed = pieces[0] + b"".join(
            (b"\x04SAL1" if index == n_inputs else b"\x07salYAHU") + piece
            for index, piece in enumerate(pieces[1:]))
        invalid = chain.daemon.request("/send_raw_transaction", {
            "tx_as_hex": malformed.hex(), "source_asset_type": "salYAHU", "do_not_relay": True})
        assert invalid["status"] != "OK", invalid
        checks.append("historical salYAHU-to-SAL1 creation defect rejected by current admission")
        relay(chain, payment, token=True); chain.mine(11)
        result = token = asset_balance(chain.wallets[1], "salYAHU")
        assert token["balance"] == previous_balance + 100 * COIN, result
        assert token["unlocked_balance"] == previous_unlocked + 100 * COIN, result
        checks.append("SAL1 rollup fee and token transfer preserve per-asset balances")
        # Exercise fee dependencies in all token builders: transfer, return
        # payment and sweep. The wallet must return the SAL1 authorization first.
        funding = chain.transfer(0, 1, 100 * COIN, relay=False)
        response = chain.daemon.request("/send_raw_transaction", {
            "tx_as_hex": funding["tx_blob"], "do_not_relay": True})
        assert response["status"] == "OK", response
        chain.mine(11)
        before_return_sal1 = asset_balance(chain.wallets[1], "SAL1")["balance"]
        returned = chain.wallets[1].call("return_payment", {
            "txid": payment["tx_hash_list"][-1], "get_tx_hex": True, "do_not_relay": True})
        print(json.dumps(dict(phase="token_return", fees=returned["fee_list"], amounts=returned["amount_list"])), flush=True)
        assert len(returned["tx_blob_list"]) == 2, returned
        relay(chain, returned, token=True); chain.mine(11)
        assert asset_balance(chain.wallets[1], "salYAHU")["balance"] == previous_balance
        assert asset_balance(chain.wallets[1], "SAL1")["balance"] == before_return_sal1 - sum(returned["fee_list"])
        second = token_transfer(chain, 0, 1, 50 * COIN)
        relay(chain, second, token=True); chain.mine(11)
        before_sweep_sal1 = asset_balance(chain.wallets[1], "SAL1")["balance"]
        swept = chain.wallets[1].call("sweep_all", dict(address=chain.addresses[0],
            asset_type="salYAHU", account_index=0, subaddr_indices=[], priority=1,
            ring_size=1, get_tx_hex=True, do_not_relay=True))
        assert len(swept["tx_blob_list"]) == 2, swept
        relay(chain, swept, token=True); chain.mine(11)
        assert asset_balance(chain.wallets[1], "salYAHU")["balance"] == 0
        assert asset_balance(chain.wallets[1], "SAL1")["balance"] == before_sweep_sal1 - sum(swept["fee_list"])
        checks.append("token returns and sweeps preserve SAL1 change exactly after both fees")
        checks.append("token transfer, return and sweep expose and mine fee authorizations first")
    finally:
        chain.close()
    verifier = args.binaries.resolve() / "salvium-blockchain-verification"
    export_dir = Path(tempfile.mkdtemp(prefix="historical-export-", dir=root))
    evidence_path = export_dir / "historical-evidence.jsonl"
    with (export_dir / "export.log").open("w") as log:
        subprocess.run([str(verifier), "--regtest", "--db-path", str(root / "chain/fake/lmdb"),
            "--historical-records", str(evidence_path), "--log-level", "0"],
            check=True, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    with evidence_path.open() as records:
        completion = None
        for raw in records:
            row = json.loads(raw)
            if row["record_type"] == "output":
                assert row["structural_status"] == "PASS" and row["monetary_status"] == "PASS", row
            if row["record_type"] == "complete": completion = row
    assert completion and completion["cryptographic_failures"] == 0
    checks.append("complete native historical export of token fixture")
    result = dict(status="TOKEN_SECURITY_PASS", root=str(root), checks=checks, completion=completion,
        historical_records=str(evidence_path),
        binary_sha256={name: hashlib.sha256((args.binaries.resolve() / name).read_bytes()).hexdigest()
            for name in ("salviumd", "salvium-wallet-rpc", "salvium-blockchain-verification")},
        verifier_sha256=hashlib.sha256(verifier.read_bytes()).hexdigest())
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__": main()
