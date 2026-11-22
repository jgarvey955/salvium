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

COIN = 100_000_000


class TokenSecurityChain(LocalChain):
    def start(self, name, command, rpc, ready_method):
        if name == "daemon": command += ["--keep-fakechain"]
        return super().start(name, command, rpc, ready_method)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, default=Path("build/audit/release/bin"))
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="salvium-token-security-"))
    print(root, flush=True)
    chain = TokenSecurityChain(args.binaries.resolve(), root)
    checks = []
    try:
        chain.launch(); chain.mine(100, fund_miner=True)
        for text in ("[]", "null", '"metadata"', '{"hash":"invalid"}'):
            try:
                chain.wallets[0].call("create_token", dict(ticker="YAHU", supply=1000, account_index=0,
                    subaddr_indices=[0], token_metadata_hex=text.encode().hex(), do_not_relay=True))
            except RpcError as error:
                assert "metadata" in str(error).lower(), error
            else:
                raise AssertionError("Invalid metadata accepted")
            chain.wallets[0].call("get_version")
        checks.append("invalid metadata rejected and wallet remains responsive")
        while chain.tip() < 21601:
            chain.mine(min(1000, 21601 - chain.tip()), refresh=False)
        for wallet in chain.wallets: chain.refresh_wallet(wallet)
        creation = chain.wallets[0].call("create_token", dict(ticker="YAHU", supply=1_000_000,
            account_index=0, subaddr_indices=[0], name='Metadata with "quotes" and \\ characters',
            url="https://example.invalid/token", get_tx_hex=True, do_not_relay=True))
        relay(chain, creation); chain.mine(61)
        checks.append("canonical metadata and protocol-authorized token issuance")
        payment = token_transfer(chain, 0, 1, 100 * COIN)
        assert len(payment["tx_blob_list"]) == 2
        relay(chain, payment, token=True); chain.mine(11)
        result = chain.wallets[1].call("get_balance", {"account_index": 0, "asset_type": "salYAHU"})
        token = next(x for x in result["balances"] if x["asset_type"] == "salYAHU")
        assert token["balance"] == 100 * COIN and token["unlocked_balance"] == 100 * COIN, result
        checks.append("SAL1 rollup fee and token transfer preserve per-asset balances")
    finally:
        chain.close()
    verifier = args.binaries.resolve() / "salvium-blockchain-verification"
    with (root / "historical-export.log").open("w") as log:
        subprocess.run([str(verifier), "--regtest", "--db-path", str(root / "chain/fake/lmdb"),
            "--historical-records", str(root / "historical-evidence.jsonl"), "--log-level", "0"],
            check=True, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    with (root / "historical-evidence.jsonl").open() as records:
        completion = None
        for raw in records:
            row = json.loads(raw)
            if row["record_type"] == "output":
                assert row["structural_status"] == "PASS" and row["monetary_status"] == "PASS", row
            if row["record_type"] == "complete": completion = row
    assert completion and completion["cryptographic_failures"] == 0
    checks.append("complete native historical export of token fixture")
    result = dict(status="TOKEN_SECURITY_PASS", root=str(root), checks=checks, completion=completion,
        verifier_sha256=hashlib.sha256(verifier.read_bytes()).hexdigest())
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__": main()
