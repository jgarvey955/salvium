# Owner-initiated audit and final output clearance

Owners start from the CLI `audit export` or the GUI **Request audit (export)** after activation. Requests go privately to the main developer. Neither daemon refresh nor background wallet activity creates private requests. Authenticated wallet RPC and the shared wallet library provide the same operation for other wallet implementations.

The main developer verifies ownership, exact amounts, canonical snapshot, asset issuance, actual funding across wallets, stake principal and scheduled payouts, conversions and token registration. Conclusive evidence clears automatically during developer processing. Missing or defective evidence enters a queue with its original finding, missing links and a CLEAR/DENY recommendation. A recommendation is not a final denial. The developer can resolve exceptions, including documented good-faith private sales or services, with a reasoned signed decision.

The trusted opening is **block 169100**, after the last scheduled first-audit payout. Earlier holdings are accepted unless positive evidence establishes invalid minting, unauthorized issuance or another substantiated defect. Subsequent funding is resolved to that opening or another verified issuance/policy root. The salYAHU malformed SAL1 origin and its actual descendants remain forensic findings. An illicit ring decoy alone does not establish misconduct.

## Consensus and finality

At the configured activation height, old supported outputs require clearance before spending. A version 4 developer certificate binds network, genesis, activation epoch, canonical snapshot, exact transaction/output (or stake principal), decision and revision. Public certificates contain no owner identifiers, amounts, ownership proofs, private purchase records or key images. They identify public output references and confirmation timing, so publication is not anonymous; batch publication can reduce owner-specific grouping.

The automatic processing service publishes these compact certificates directly to the daemon. Wallets discover confirmed clearance on refresh; owners do not need to import anything. Optional receipt import can retry publication. Nodes relay them through a separate bounded notification/queue; miners include bounded batches in coinbase extra. The withdrawn version 2 public ownership-proof route remains disabled. A local receipt or cache alone never authorizes consensus spending.

**CLEAR is final once confirmed on the canonical chain.** It cannot be amended to DENY or replaced with another disposition, even by the main developer. DENY/REVIEW can be resolved by a newer valid CLEAR. A certificate in block H permits spending in H+1, subject to ordinary maturity, stake locks and enough eligible outputs to construct the standard ring. There is no additional audit waiting period. A chain reorganization removes orphaned confirmation; replay reconstructs final clearance from the canonical chain.

All ring members must be eligible, so a cleared decoy cannot authorize an uncleared real input. Wallets select decoys from the public eligible population. Valid subsequent transfers and change inherit clearance after normal maturity, without a new owner audit. Canonical new issuance inherits clearance. Stake payouts inherit only through a unique authorized principal/payout mapping; ambiguous historical payouts need direct review. Clearance changes spend eligibility, never the output amount, destination, original issuance finding or historical supply accounting.

## Main developer release configuration

Production activation heights and public authority keys are deliberately unset. Configure the public keys in `src/cryptonote_core/audit_review_authority.h` and heights in `src/cryptonote_core/private_audit_policy.h`, then coordinate the consensus release across validating nodes and wallets. Private signing secrets never belong in Git or owner devices. The authority public key must be distributed independently and is safe to publish; another person's build with a different key cannot create valid certificates for the agreed network. Runtime test keys/heights are accepted only by isolated `--regtest` fakechains.

Core daemon, CLI and shared wallet code belong to core `audit` based on `main`. GUI code belongs to its own `audit` based on `master`, pinning that reviewed core. Build core audit with `make release-static builddir=build/audit topdir=../../..`; preserve normal `my-complete` binaries. Build GUI with its normal `make release-static` workflow.

Create a dedicated private key on the developer's processing machine:

```sh
salvium-audit-review --keygen /private/reviewer.key
```

After configuring the release, select a common canonical snapshot and verify/sign owner requests:

```sh
python3 utils/process_private_audit.py \
  --daemon-address http://127.0.0.1:19081 --verifier /path/to/salvium-audit-review -- \
  --data-dir /path/to/chain \
  --input /private/miner.json /private/alice.json /private/nonkyc.json \
  --sign-key /private/reviewer.key --outdir /private/new-case
```

Clearances are published automatically when processing succeeds; no manual review is needed for conclusive rows. Owners simply refresh their wallets after confirmation. Package receipts are optional private records; return only an owner's own receipts, never the combined `case.json` or other owners' files. The wallet must already hold its exported request. It checks the designated signature, network, exact proofs, snapshot and revision before import. Pending clearance remains locked until chain confirmation. Repeat import retries publication without repeating the audit.

For unresolved cases, edit the generated `review-queue.json` with reasoned decisions, then authenticate and revise the signed case:

```sh
python3 utils/process_private_audit.py \
  --daemon-address http://127.0.0.1:19081 --verifier /path/to/salvium-audit-review -- \
  --report /private/new-case/case.json \
  --decisions /private/decisions.json --sign-key /private/reviewer.key \
  --outdir /private/revised-case
```

A new case cannot override a previous final chain clearance. Revisions of unresolved decisions must increase. Unsigned or edited case reports must be reprocessed from original owner evidence; they cannot simply be signed as trusted findings.

## Exchange purchases

Any **verified exchange purchase** is licit under this clearance policy, including a withdrawal whose prior custody/funding has an illicit origin. A deposit or withdrawal alone does not prove a purchase. NonKYC is the first adapter; the normalized schema also supports historical exchange records and other wallet integrations. Preserve original illicit issuance and its forensic/supply totals even when the buyer receives policy clearance.

Obtain complete operator records independently, reconcile balances, custody, liabilities, trade groups, exact withdrawal receipts, duplicate credits and purchase coverage. Operator purchase attribution is an economic assertion, not something the chain alone proves. Manual adjustments, incomplete scope or reconciliation errors stay in developer review.

After independently authenticating the operator records, the main developer can approve their exact SHA256 and run automatic purchase processing:

```sh
python3 utils/reconcile_nonkyc_audit.py \
  --case /private/new-case/case.json --ledger /private/operator-ledger.json \
  --verifier /path/to/salvium-audit-review --developer-public-key PUBLIC_KEY \
  --output /private/reconciliation.json \
  --approved-ledger-sha256 INDEPENDENTLY_APPROVED_LEDGER_SHA256 \
  --sign-key /private/reviewer.key --outdir /private/purchase-results \
  --daemon-address http://127.0.0.1:19081
```

Only qualifying CLEAR recommendations are applied automatically. Other rows remain unresolved with recommendations; they are never automatically denied. Owner-supplied recommendation JSON or a self-asserted purchase does not authorize a certificate. The approved digest must come from the developer's independent authentication of the operator export.

## Verification and scope

Run native `audit_clearance_tests`, `audit_review_tests`, `lineage_audit_tests` and `wallet_audit_inventory_tests` from the isolated audit static build, plus `audit_nonkyc_reconciliation.py`, `audit_private_review_regtest.py` and `audit_clearance_regtest.py --binaries build/audit/release/bin`. Functional fixtures use explicit isolated configs, temporary fakechains and loopback ports. Never start or restart the production daemon for tests.

Private reports declare `SUBMITTED_OUTPUTS_ONLY`; they do not establish complete undisclosed exchange holdings, global monetary supply or a full historical consensus/PoW replay. Real owner evidence and authentic operator records are required for the real audit. Keep chain-wide monetary/forensic scans as a separate accounting requirement. Earlier validation artifacts describe earlier versions and must not be presented as qualification of new consensus changes.

Publication retries use `python3 utils/process_private_audit.py --daemon-address http://127.0.0.1:19081 --case-directory /private/new-case`. `clearances.public` contains only compact public certificates. The publisher never uploads case reports, ownership proofs or purchase ledgers. Configure an owner-only `--rpc-login-file` when daemon RPC authentication is enabled.
