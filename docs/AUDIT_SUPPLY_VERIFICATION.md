# Audit ownership and circulating supply verification

The active audit covers SAL1 and supported tokens. Retired SAL was covered by the previous SAL-to-SAL1 audit. Its historical conversion records are accounting context; current SAL balances and new SAL wallet enrollment are not required.

## Audit window

The requested mainnet activation is 630000. Enrollment includes candidate heights 630000 through 659999 and closes at 660000. New STAKE transactions are disabled for that interval in wallet creation and consensus validation. Existing stake obligations retain their normal principal and reward payouts. New staking resumes at 660000.

Closing stops new clearance enrollment. Existing clearance remains valid, and closing does not release uncleared or denied outputs. Private read-only evidence remains exportable for final supply reporting.

## Mining rewards

Canonical authorized SAL1 mining rewards need no wallet audit or certificate, including rewards mined before launch. They become spendable at normal coinbase maturity before, during and after the audit. Pre-launch issuance is independently verified against the accepted opening and public reward schedule. Reorganizations rebuild eligibility; a MINER label alone cannot authorize an invalid reward. Pruned nodes retain the public fee bases and transaction-hash bindings needed for this verification.

## Ownership evidence

A software wallet exports private cryptographic evidence across all supported accounts, subaddresses and assets. The owner submits that export to the authorized review workflow. The implementation does not provide an automatic central upload service. A scoped status query is supported; a partial scoped export cannot masquerade as a complete wallet submission.

Missing exchange history or private upstream ancestry alone does not establish illicit origin. Valid eligible ownership can clear without such history. An exchange withdrawal by itself does not establish a purchase. Confirmed disqualifying evidence and authentic evidence conflicts remain separate review decisions under the approved policy.

The native `salvium-audit-review --ownership-index` mode binds a private spend-witness index to an authenticated native report and its exact original proof packages. Its output contains private ownership mappings and must remain private. It grants no certificate or consensus authorization.

## Supply reconciliation

`utils/audit_supply_reconciliation.py` compares complete canonical native evidence with authenticated ownership reports. Supply is calculated independently from authorized output issuance, burns, conversion legs, distributed fees and stake obligations, then compared with owner balances and the database tally.

- Circulating output supply includes immature and audit-frozen existing outputs.
- Outstanding supply additionally includes locked stake principal.
- Returned principal is not new issuance; paid stake rewards are separated from reserved unpaid rewards.
- Undistributed prepaid fees are existing-value escrow, reported separately.
- Transfers and exchange movements are not issuance. Denial does not burn coins.
- Historical output counts and historical face-value sums are not circulating supply.
- SAL context is returned separately from the active SAL1/token asset totals.

The verifier accepts multiple native cases and deduplicates repeated ownership identities. Exact spend proofs can account for public treasury rewards outside user-wallet submissions without guessing a real input from a ring. Incomplete current-owner coverage cannot produce a successful complete-supply report. An incomplete global supply report does not itself disqualify an individual eligible holder.

Run the reconciliation privately with independently trusted authority configuration and a new output path:

```text
python3 utils/audit_supply_reconciliation.py \
  --evidence canonical-evidence.jsonl \
  --case authenticated-native-case.json \
  --verifier build/audit/release/bin/salvium-audit-review \
  --authority TRUSTED_PUBLIC_AUTHORITY \
  --wallet-evidence original-private-owner-export.json \
  --output new-private-supply-report.json
```

A case signature alone does not establish global owner coverage. The native evidence must have a complete snapshot-bound terminal record and must come from the canonical verification workflow. Production circulation remains unverified until the necessary owner evidence and monetary reconciliation are available.

## Isolated verification

Build each audit worktree with `make release-static builddir=build/audit topdir=../../..`. Keep the normal production binary directory separate.

`audit_clearance_regtest.py --full-window` verifies the entire 30000-block window, stake maturity and post-close behavior. `audit_exchange_subaddresses_regtest.py --verify-supply` adds funded exchange/independent-owner accounts and subaddresses plus complete SAL1/token supply reconciliation. It requires a completed isolated `audit_token_security_regtest.py` fixture, supplied with `--fixture`. `audit_supply_stakes_regtest.py` tests locked principal; its optional `--fixture` accepts a completed full-window fixture to test paid principal/rewards and closing supply. Each script accepts `--binaries` and copies its required fixture before use.

Accounting and incomplete-evidence regressions run with `python3 tests/functional_tests/audit_supply_reconciliation_tests.py`. Historical reporting regressions run with `python3 tests/functional_tests/historical_audit_report_tests.py`.

## Release qualification

Production authority keys, approved policy digest and historical cutoff remain unconfigured. The requested nonzero mainnet activation therefore fails closed at initialization until approved release configuration is supplied. These branches are not a production-qualified release.

Full historical PoW/chain-selection replay, real authenticated exchange records, hardware/watch-only/multisignature proof creation and existing-index migration require further qualification. The local verification bundle records actual passes, unavailable tests, exact source/binary fingerprints and remaining limits. It contains the six requested `salvium_*` audit and supply reports. Private proof packages and signing keys are not included in public reports or commits.
