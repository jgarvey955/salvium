#!/usr/bin/env python3
"""Restart only a completed isolated clearance fixture and spend its inherited funds."""
import argparse
import hashlib
import json
from pathlib import Path

from audit_clearance_regtest import PrivateChain
from audit_gate_regtest import COIN


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    root = args.fixture.resolve()
    # Refuse an arbitrary wallet or daemon directory. This test resumes only
    # a successful fixture made by audit_clearance_regtest, using its own keys.
    assert root.name.startswith('salvium-private-clearance-')
    result = json.loads((root / 'result.json').read_text())
    assert result['passed'] and str(root) == result['fixture']
    assert any('payout itself spends' in check for check in result['checks'])
    report = json.loads((root / 'complete/case.json').read_text())
    assert report['network'] == 3 and report['signer']
    binaries = args.binaries.resolve()

    def restart():
        chain = PrivateChain(binaries, root)
        chain.authority = report['signer']
        try:
            chain.launch()
            for wallet in chain.wallets:
                chain.refresh_wallet(wallet)
            status = chain.daemon.call('get_private_audit_status', {})
            assert status['activation_height'] == chain.activation
            assert status['authority'] == report['signer']
            return chain
        except BaseException:
            chain.close()
            raise

    chain = restart()
    try:
        first_height = chain.tip()
        assert first_height >= 21724
        assert chain.balance(1)['balance'] > 0 and chain.balance(2)['balance'] > 0
        chain.mine(11)
        before = chain.balance(2)['balance']
        transfer = chain.transfer(1, 2, COIN, relay=False)
        chain.submit(transfer, True)
        chain.mine(1)
        assert chain.transaction(transfer['tx_hash'])[1] == chain.tip()
        assert chain.balance(2)['balance'] == before + COIN
        height = chain.tip()
        balances = [chain.balance(i) for i in range(3)]
    finally:
        chain.close()

    chain = restart()
    try:
        assert chain.tip() == height
        assert [chain.balance(i) for i in range(3)] == balances
        assert chain.transaction(transfer['tx_hash'])[1] == height
    finally:
        chain.close()
    evidence = dict(status='AUDIT_CLEARANCE_RESTART_PASS', fixture=str(root),
        first_height=first_height, final_height=height, restarts=2,
        inherited_payout_spend=transfer['tx_hash'],
        binary_sha256={name: hashlib.sha256((binaries / name).read_bytes()).hexdigest()
            for name in ('salviumd', 'salvium-wallet-rpc')})
    (root / 'restart-result.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence), flush=True)


if __name__ == '__main__':
    main()
