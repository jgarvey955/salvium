#!/usr/bin/env python3
"""Mature canonical mining rewards spend without audit evidence in every phase."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_clearance_regtest import PrivateChain, rejected
from audit_gate_regtest import COIN
from audit_complex_regtest import CoinbaseReader


class MiningChain(PrivateChain):
    def start(self, name, command, rpc, ready_method):
        if name == 'daemon':
            command[command.index('--log-level') + 1] = '*:WARNING,verify:DEBUG,stacktrace:INFO'
        return super().start(name, command, rpc, ready_method)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--closing-fixture', type=Path,
                        help='Copy an existing completed full-window fakechain for the closing phase')
    args = parser.parse_args()
    bins = args.binaries.resolve()
    root = Path(tempfile.mkdtemp(prefix='salvium-mining-rewards-'))
    print(root, flush=True)
    key = root / 'developer.key'
    public = subprocess.run([str(bins / 'salvium-audit-review'), '--keygen', str(key)],
                            capture_output=True, text=True, check=True).stdout.split()[-1]
    (root / 'authority.public').write_text(public)
    checks = []
    chain = MiningChain(bins, root)
    # Every decoy of the prebuilt transaction must also reach normal mining
    # maturity before launch; the real spend alone is insufficient.
    chain.activation = 240
    chain.authority = public

    def spend(amount=COIN):
        tx = chain.transfer(0, 2, amount, relay=False)
        chain.submit(tx, True)
        chain.mine(1)
        assert chain.transaction(tx['tx_hash'])[1] == chain.tip()
        return tx

    def freeze_except(wallet, image):
        for output in chain.outputs(0):
            if not output['spent'] and output['key_image'] != image:
                wallet.call('freeze', {'key_image': output['key_image']})

    try:
        chain.launch()
        chain.mine(100, fund_miner=True)
        # Build the boundary transaction while every available ring member is
        # a mining output. Keep its actual input unspent in the before-phase
        # test, so an ordinary pre-audit decoy cannot change this assertion.
        before = chain.transfer(0, 2, COIN, relay=False)
        (root / 'boundary-transaction.json').write_text(json.dumps(before))
        reader = CoinbaseReader(bytes.fromhex(before['tx_blob']))
        assert reader.integer() == 5
        reader.integer()  # unlock time
        count = reader.integer()
        assert 0 < count <= 256
        images = []
        for _ in range(count):
            assert reader.byte() == 2 and reader.integer() == 0
            asset_length = reader.integer()
            reader.pos += asset_length
            for _ in range(reader.integer()):
                reader.integer()
            images.append(reader.blob[reader.pos:reader.pos + 32].hex())
            reader.pos += 32
        owned = {row['key_image'] for row in chain.outputs(0)}
        assert set(images) <= owned
        for image in images:
            chain.wallets[0].call('freeze', {'key_image': image})
        initial = spend()
        for image in images:
            chain.wallets[0].call('thaw', {'key_image': image})
        for output in chain.outputs(0):
            if output['tx_hash'] == initial['tx_hash'] and not output['spent']:
                chain.wallets[0].call('freeze', {'key_image': output['key_image']})
        checks.append('mature mining reward spends before activation without an audit')
        chain.mine(chain.activation - 2 - chain.tip())
        chain.mine(1, fund_miner=True)
        orphan = next(row for row in chain.outputs(0) if row['block_height'] == chain.tip())['tx_hash']
        assert chain.daemon.call('get_private_audit_status')['candidate_height'] == chain.activation
        chain.daemon.call('get_private_audit_outputs', {'asset_type': 'SAL1', 'from_index': 0, 'limit': 1000})
        chain.daemon.request('/pop_blocks', {'nblocks': 1})
        chain.mine(1, fund_miner=True)
        replacement = next(row for row in chain.outputs(0) if row['block_height'] == chain.tip())['tx_hash']
        assert replacement != orphan
        # This transaction spends only a canonical miner output: no owner
        # export, review report or clearance has been submitted in this chain.
        response = chain.daemon.request('/send_raw_transaction', {
            'tx_as_hex': before['tx_blob'], 'do_not_relay': True, 'do_sanity_checks': False})
        (root / 'activation-status.json').write_text(json.dumps({'response': response, 'balance': chain.balance(0), 'catalog': chain.daemon.call('get_private_audit_outputs', {'asset_type': 'SAL1', 'from_index': 0, 'limit': 1000})}))
        assert response['status'] == 'OK', response
        chain.mine(1)
        assert chain.transaction(before['tx_hash'])[1] == chain.activation
        checks.append('pre-launch mature mining reward stays spendable exactly at activation without a certificate')
        chain.mine(1, fund_miner=True)
        origin = chain.tip()
        rows = [row for row in chain.outputs(0) if row['block_height'] == origin]
        assert len(rows) == 1
        reward = rows[0]
        freeze_except(chain.wallets[0], reward['key_image'])
        rejected(lambda: chain.transfer(0, 2, COIN, relay=False))
        chain.mine(58)
        # candidate origin+59 is still immature; origin+60 is the first valid candidate.
        assert chain.daemon.call('get_private_audit_status')['candidate_height'] == origin + 59
        rejected(lambda: chain.transfer(0, 2, COIN, relay=False))
        chain.mine(1)
        assert chain.daemon.call('get_private_audit_status')['candidate_height'] == origin + 60
        tx = spend()
        decoded, _ = chain.transaction(tx['tx_hash'])
        assert [entry['key']['k_image'] for entry in decoded['vin']] == [reward['key_image']]
        checks.append('during-audit reward preserves normal maturity and spends at its first mature candidate without audit')
        catalog = chain.daemon.call('get_private_audit_outputs', {
            'asset_type': 'SAL1', 'from_index': 0, 'limit': 1000})
        assert not catalog.get('more', False)
        records = chain.daemon.request('/get_outs', {
            'outputs': [{'amount': 0, 'index': row['index']} for row in catalog.get('outputs', [])],
            'asset_type': 'SAL1', 'get_txid': True})
        identities = {row['txid'] for row in records.get('outs', [])}
        assert orphan not in identities and replacement in identities
        checks.append('a reorg immediately before activation removes orphaned miner eligibility and admits its canonical replacement')
    finally:
        chain.close()

    if args.closing_fixture:
        source = args.closing_fixture.resolve()
        assert source.name.startswith('salvium-private-clearance-')
        manifest = json.loads((source / 'result.json').read_text())
        assert manifest['passed'] and manifest['full_window']
        closed = root / 'closing'
        closed.mkdir()
        for name in ('chain', 'miner', 'alice', 'bob', 'observer'):
            shutil.copytree(source / name, closed / name)
        chain = MiningChain(bins, closed)
        chain.activation = manifest['activation']
        chain.authority = json.loads((source / 'complete/case.json').read_text())['signer']
        try:
            chain.launch()
            for wallet in chain.wallets:
                chain.refresh_wallet(wallet)
            assert chain.tip() >= chain.activation + 30000
            chain.mine(1, fund_miner=True)
            origin = chain.tip()
            reward = next(row for row in chain.outputs(0) if row['block_height'] == origin)
            # Restore spendability of the miner's prior inputs only to freeze
            # every input except this new post-close reward deterministically.
            for row in chain.outputs(0):
                if chain.wallets[0].call('frozen', {'key_image': row['key_image']})['frozen']:
                    chain.wallets[0].call('thaw', {'key_image': row['key_image']})
            freeze_except(chain.wallets[0], reward['key_image'])
            chain.mine(58)
            rejected(lambda: chain.transfer(0, 2, COIN, relay=False))
            chain.mine(1)
            tx = spend()
            decoded, _ = chain.transaction(tx['tx_hash'])
            assert [entry['key']['k_image'] for entry in decoded['vin']] == [reward['key_image']]
            checks.append('post-close mining reward spends at its first normal mature candidate without new audit enrollment')
        finally:
            chain.close()
    result = dict(status='PASS',checks=checks,fixture=str(root),normal_coinbase_maturity=60,
        audit_evidence_submitted=False,binary_sha256={name:hashlib.sha256((bins/name).read_bytes()).hexdigest()
        for name in ('salviumd','salvium-wallet-rpc','salvium-audit-review')})
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('AUDIT_MINING_REWARDS_PASS',json.dumps(result),flush=True)


if __name__ == '__main__':
    main()
