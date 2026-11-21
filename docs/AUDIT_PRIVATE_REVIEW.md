# Private audit review and wallet integration

The native verifier clears conclusive funding paths and gives the main developer
unresolved cases with reasons. NonKYC records establish economic attribution
after pooled custody; pooling alone does not establish customer misconduct.

The wallet owner initiates a request through an explicit private export. The
daemon and background refresh never initiate, sign or submit that request.
Only the main developer processes requests and signs results, including results
that clear automatically after verification. The owner imports the result.

The main developer must supply the public signing key in
`src/cryptonote_core/audit_review_authority.h` during private release review. Keys are
intentionally empty in this branch. Exports and unsigned analysis work, but
production-network signing and result acceptance fail until an authority is
designated. An arbitrary key supplied by an owner cannot authorize clearance.
Ephemeral keys are limited to isolated fakechain tests; a regtest wallet flag
alone cannot bypass authority on a production daemon.

## Reviewer workflow

Choose a common canonical snapshot height and hash. Wallets may export against
that height after synchronizing further. Create a dedicated signing key and
retain its secret privately, configure its public key in the release, and
distribute that public key independently. This is a main developer command:

~~~sh
build/audit/release/bin/salvium-audit-review --keygen /private/reviewer.key
~~~

Verify wallet files and sign automatic results:

~~~sh
build/audit/release/bin/salvium-audit-review \
  --data-dir /path/to/chain \
  --input /private/miner.json /private/alice.json /private/nonkyc.json \
  --sign-key /private/reviewer.key --outdir /private/new-case
~~~

The new private directory contains `case.json`, `review-queue.json` and one
result per package. Return only the relevant package files to each wallet.
Unsigned reports cannot clear wallet inventory through import.
Existing cases must have an authentic developer signature before they can be
revised or signed again. To sign an earlier unsigned analysis, rerun the original
`--input` evidence against the canonical database with `--sign-key`. Recipient
identities, report fields and JSON allocation are checked before processing;
private output files never replace an existing file.

Review the queue, retain only decisions being made, choose `CLEAR` or `DENY`,
and supply a nonempty `reason`. The original `report_hash` must match:

~~~sh
build/audit/release/bin/salvium-audit-review \
  --report /private/new-case/case.json \
  --decisions /private/reviewed-decisions.json \
  --sign-key /private/reviewer.key --outdir /private/decided-case
~~~

Decisions increase the revision. When rerunning a case with new evidence, use a
newer `--revision`. Older revisions and conflicting results at the same revision
are rejected. Verify a signed result independently:

~~~sh
build/audit/release/bin/salvium-audit-review \
  --report /private/recipient-result.json --verify-key PUBLIC_KEY
~~~

## Verification rules

| Finding | Automatic result | Recommendation |
| --- | --- | --- |
| Verified issuance or accepted opening | CLEARED | CLEAR |
| All exact funding sources verified | CLEARED | CLEAR |
| All possible sources in every ring verified | CLEARED | CLEAR |
| Malformed origin or proven illicit funding | REVIEW_REQUIRED | DENY |
| Incomplete funding or payout authorization | REVIEW_REQUIRED | DENY pending evidence |
| Reconciled purchase with incomplete ancestry | Remains under review | Adapter may recommend CLEAR |
| Forgery, conflicting identity, wrong snapshot, duplicate audited spend | Evidence rejected | No clearance |

Checks include canonical hashes/indices, legacy and Carrot commitments, finite
T-CLSAG ownership, asset labels, funding signatures/value proofs, miner emission,
accepted conversion authorizations, unique token issuance, registration funding,
maturity, and scheduled stake payout authorization. Missing historical
yield/authorization evidence remains unresolved.

Public ancestry uses an explicit stack and shared cache. The default limit is
50000 examined outputs; `--public-work-limit` allows up to 500000. Zero selects
private-proof diagnostics. Work exhaustion cannot produce clearance. Limits are
4096 packages, 512 proofs per package, 250000 submitted proofs and 256 MiB per file.
An immature possible source also prevents public-only clearance. An exact proof
of the mature real source can resolve that ambiguity without blaming the decoy.

## NonKYC evidence

Use an operator export covering all accounts, custody wallets, opening/closing
balances and chronological events for declared assets. Map exchange ticker SAL
explicitly to native SAL1. Missing accounts, wallets, events and external-asset
proceeds require separate accounting.

The version 1 JSON ledger contains `network`, `genesis`, `snapshot_height`,
`snapshot_hash`, `scope_complete`, `assets_in_scope`, `custody_package_ids`,
`balances`, `events` and optional `exchange_equity`.

- Balance rows: `account`, `asset`, `opening_atomic`, `closing_atomic`.
- Event rows: unique `id`, `kind`, `account`, `asset`, signed `delta_atomic`.
- Kinds: deposit, withdrawal, trade, fee, internal, adjustment.
- Trade/internal rows also identify `group`; each group's net per asset is zero.
- Deposits/withdrawals identify `transaction` and `output_index` and match exact
  native receipt/amount evidence.
- A purchase withdrawal uses `acquisition: "market_purchase"` and must be covered
  by earlier trade credits.
- Equity rows: `asset` and `amount_atomic`.

Amounts are canonical decimal integer strings in atomic units. Accounts must
reconcile through events to closing balances. Unique unspent custody plus locked
principal must equal liabilities and equity per asset. Duplicate proofs, sweeps,
spent history and returned principal never add reserves. Adjustments require review.

~~~sh
python3 utils/reconcile_nonkyc_audit.py \
  --case /private/new-case/case.json --ledger /private/nonkyc-ledger.json \
  --verifier build/audit/release/bin/salvium-audit-review \
  --developer-public-key PUBLIC_KEY \
  --output /private/reconciliation.json \
  --decisions-output /private/recommendations.json
~~~

The adapter verifies the case signature and binds recommendations to its hash
and the ledger SHA256. The developer reviews the exchange assertions before
signing decisions. The adapter never clears funds itself. Custody arithmetic does
not certify legitimate issuance. Assets outside declared native scope, such as
USDT proceeds, need their own accounting and evidence.

## Wallet interfaces

CLI `audit` and C++ `Wallet::audit()` consume saved authenticated results.
`exportAuditReview()` returns a private request; `importAuditReview(result, key)`
verifies and persists results. File variants support the GUI. Signing currently
requires a full software wallet. Hardware, multisig and third-party software need
compatible signing support; missing context never justifies exporting a seed.

Authenticated unrestricted wallet RPC `audit` supports:

| Request | Behavior |
| --- | --- |
| `status_only: true` | Inventory and saved decisions |
| `output_offset`, `output_limit` | Up to 1000 output rows |
| `export_evidence: true`, optional `snapshot_height` | All-account export |
| `export_id`, `evidence_offset`, `evidence_limit` | Resume up to four packages per page |
| `review_result`, `developer_public_key` | Import signed recipient results |

Responses include `total_outputs`, `outputs_more`, `next_output_offset`,
`export_id`, `evidence_more` and `next_evidence_offset`. Resume with the returned
session ID. Combine page `packages` in a version 3 request or pass each page as
a separate verifier input. Session changes are errors. Export and import require
separate requests; status-only calls create no proofs and export rejects narrower
account scopes. No ownership/future-spend key-image query goes to the daemon.

The GUI uses the same asynchronous API. Its CMake `SALVIUM_CORE_SOURCE_DIR`
can point to this core with `MANUAL_SUBMODULES=ON` for development. Packaging
requires a reviewed audit core; older embedded cores retain earlier behavior.
All builds still use `make release-static`.

## Third party porting

Version 3 transport is defined in `src/cryptonote_core/audit_review.h`.
Packages bind network/genesis, exact snapshot, a random 32-byte nonce as lowercase
hex, and finite proof blobs. No reusable viewing key is accepted. Binary proofs
contain transaction hash, output index, stake flag, amount, offset-mask selector,
key image and one-member T-CLSAG proof. See `lineage_output_proof` for encoding.
The v3 signing domain differs from withdrawn public v2 enrollment.

Exact domains and field order are defined by `audit_review_proof_message`,
`audit_review_package_id` and `audit_review_report_hash`. Hash with CryptoNote
Keccak-256, not SHA3-256. Each field is its decimal UTF-8 byte length, a colon,
and UTF-8 value. Integers use canonical decimal text, booleans 0 or 1, and arrays
include their count. Report hashes exclude the signature and include signer,
revision, coverage, work bounds, findings and decisions. Signatures use the core
`crypto::generate_signature` and `check_signature` format.

JSON property order and whitespace do not affect verification. Preserve uint64
quantities with arbitrary-precision parsing; JavaScript integrations must avoid
floating point rounding. Integrations can use the native wallet library for
cryptography.

## Supply audit coverage

Run independent chain-wide monetary/forensic scans and historical consensus/PoW
replay separately. Private case coverage is `SUBMITTED_OUTPUTS_ONLY` and assumes
a canonical database. It does not establish complete liabilities, owner
participation, full historical replay or global illicit balances. A ring candidate
is not a real-spend proof, and an exchange assertion is not a funding proof.
Developer decisions retain the original findings.
