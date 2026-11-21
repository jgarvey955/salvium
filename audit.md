# SAL1 and token audit

All daemon, CLI, wallet-library and reviewer changes live on the core `audit`
branch, which contains `origin/main`. GUI changes live on a separate `audit`
branch created from the GUI repository's `master`. Default branches are unchanged.

The audit verifies issuance and funding, clears conclusive cases automatically,
and gives the main developer a private queue with CLEAR or DENY recommendations.
It covers malformed origins such as salYAHU creating SAL1, cross-wallet transfers,
exchange custody, token registration funding, and stake principal and payouts.

The wallet owner initiates each request with an explicit export. The main
developer processes it, runs automatic verification and signs the results.
Background refresh and the daemon never initiate wallet requests. The developer
will supply the public authority key during private release review; production-network
results cannot be signed or accepted while it is unset.

Clearance is an audit verdict. Ordinary transaction validation and maturity remain
authoritative. Findings and decisions do not publish ownership links, freeze ring
decoys, change stake payouts, or authorize invalid transactions. Public v2
enrollment and consensus lineage enforcement remain disabled.

## Wallet workflow

Run `audit` in the CLI to inspect every account and subaddress. The GUI provides
the same review, private export, and signed-result import when built with this core.
For an investigation, use the coordinator's common snapshot height:

~~~text
audit export /private/new-evidence.json SNAPSHOT_HEIGHT
audit import /private/signed-result.json DEVELOPER_PUBLIC_KEY
audit
~~~

Exported files contain confidential amounts and spend-linking evidence. Share
them only with the main developer. Seeds, spend secrets, and reusable viewing
secrets are never exported. A new export supersedes the previous export session.
Obtain the developer public key independently; imports pin it and reject stale
revisions or orphaned snapshots.

## Clearance and review

An output clears automatically when its origin is verified and every funding
input is established by either an exact source proof with valid ancestry, or
verified ancestry for every possible member of its ring. The latter path avoids
requiring participation by earlier owners. An illicit decoy does not override
an exact proof of legitimate funding.

Missing evidence, bounded public verification work, proven illicit funding,
malformed origins, and unavailable payout authorization remain review cases.
Invalid ownership proofs, conflicting identities, and snapshot mismatches reject
the evidence. The queue retains automatic findings, recommendations, and missing
inputs separately from the developer's signed decision and explanation.

`salvium-audit-review` reads a canonical database without starting a daemon.
Signed recipient files contain only the relevant package's results. No private
evidence enters P2P relay or coinbase extra.

NonKYC reconciliation checks balances, custody, receipt amounts, duplicate
deposit credits, and trade/internal-transfer totals. Reconciled purchase records
can support a CLEAR recommendation for an unresolved receipt. The developer must
confirm the exchange's scope and purchase attribution. A purchase recommendation
preserves the original funding finding; confirmed malformed origins retain DENY
recommendations.

## Scope and validation

The mainnet opening remains block 154749. Accepted SAL-to-SAL1 conversions are
matched to their original authorizations; their SAL history is not audited again.
Assets remain separate. Returned stake principal is excluded from locked
principal to avoid counting it again alongside its payout.

Private case coverage is explicitly `SUBMITTED_OUTPUTS_ONLY`. It does not
establish complete owner participation, exchange liabilities, full historical
consensus replay, or the current global unauthorized balance. The 40 million SAL1
origin value at block 465074 is not today's unspent unauthorized balance.

The chain-wide forensic and historical replay work remains a separate required
part of the supply audit. Run `utils/full_chain_audit.sh` on a snapshot and retain
its exact range, completion records, failures, and binary hashes.

Build only with `make release-static builddir=build/audit topdir=../../.. -j2`.
The normal build directory remains reserved for `my-complete`. Never start or
restart production for an audit test. See
[reviewer commands and wallet integration](docs/AUDIT_PRIVATE_REVIEW.md).
The [main developer handoff](docs/AUDIT_DEVELOPER_HANDOFF.md) explains owner
initiation, processing authority and signing-key setup before release.
