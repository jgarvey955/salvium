#!/usr/bin/env python3
"""Independent complete fakechain supply with locked principal or a matured stake."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_clearance_regtest import PrivateChain
from audit_gate_regtest import COIN
from audit_supply_regtest import verify_supply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--fixture", type=Path,
                        help="Copy a completed full-window audit_clearance_regtest fixture")
    args = parser.parse_args()
    bins = args.binaries.resolve()
    root = Path(tempfile.mkdtemp(prefix="salvium-supply-stakes-"))
    print(root, flush=True)
    tool, secret = bins / "salvium-audit-review", root / "developer.key"
    activation = 180
    if args.fixture:
        source = args.fixture.resolve()
        manifest = json.loads((source / "result.json").read_text())
        assert manifest["passed"] and manifest["full_window"] and manifest["fixture"] == str(source)
        activation = manifest["activation"]
        for name in ("chain", "miner", "alice", "bob", "observer"):
            shutil.copytree(source / name, root / name)
        shutil.copy2(source / "developer.key", secret)
        public = json.loads((source / "complete/case.json").read_text())["signer"]
    else:
        keygen = subprocess.run([str(tool), "--keygen", str(secret)], capture_output=True,
                                text=True, timeout=60, check=True)
        public = keygen.stdout.split()[-1]
    chain = PrivateChain(bins, root)
    chain.activation, chain.authority = activation, public
    try:
        chain.launch()
        for wallet in chain.wallets:
            chain.refresh_wallet(wallet)
        if not args.fixture:
            chain.mine(100, fund_miner=True)
            for recipient, amount in ((1, 50), (2, 10)):
                funding = chain.transfer(0, recipient, amount * COIN, relay=False)
                chain.submit(funding, True); chain.mine(11)
            stake = chain.transfer(1, 1, 12 * COIN, tx_type=6, relay=False)
            chain.submit(stake, True); chain.mine(11)
        else:
            assert chain.tip() >= activation + 30000
        result = verify_supply(chain, tool, public, secret, root, ("SAL1",))
        expected_principal = COIN if args.fixture else 12 * COIN
        assert int(result["assets"]["SAL1"]["locked_stake_principal"]) == expected_principal
        if args.fixture:
            assert int(result["assets"]["SAL1"]["staking_rewards_paid"]) > 0
            result["checks"].append("matured principal and paid rewards count once; final reporting works after the audit closes")
        else:
            result["checks"].append("all locked stake principal reconciles to authenticated owner proofs before payout")
        result.update(fixture=str(root), activation=activation, resumed_full_window=bool(args.fixture),
            binary_sha256={name: hashlib.sha256((bins / name).read_bytes()).hexdigest()
                           for name in ("salviumd", "salvium-wallet-rpc", "salvium-audit-review")})
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print("AUDIT_SUPPLY_STAKES_PASS", json.dumps(result), flush=True)
    finally:
        chain.close()


if __name__ == "__main__":
    main()
