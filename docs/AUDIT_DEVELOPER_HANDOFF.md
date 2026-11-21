# Developer handoff: owner-initiated audit with main developer processing

Review the implementation on the core `audit` PR and the separate GUI `audit`
branch. Wallet evidence, NonKYC ledgers and signing secrets stay private. Owners
send their requests privately to the main developer, who processes and signs the
results. The older carrier/enrollment packaging tools are historical; use the
private version 3 workflow described here.

## Description

Wallet owners explicitly request an audit by exporting a finite, signed evidence
package from the CLI or GUI. The main developer receives that request privately,
verifies issuance and funding against a common canonical snapshot, and signs the
results. Conclusively verified outputs clear automatically during that processing.
Unresolved or defective funding enters the developer's queue with its original
finding, missing evidence and a CLEAR or DENY recommendation. The developer can
record a reasoned decision and sign a newer revision. The owner imports only
their recipient-specific result.

The checks include the salYAHU-to-SAL1 malformed origin, cross-wallet funding
paths, ring ambiguity, issuance, asset separation, token registration funding,
stake principal and payout authorization, and duplicate audited spends. NonKYC
ledger reconciliation adds custody/liability arithmetic, receipt matching,
duplicate-credit checks and purchase-attribution recommendations for human review.
An illicit decoy alone does not establish an illicit real spend. Missing evidence
does not establish misconduct, and exchange pooling does not identify a customer
as the creator of unauthorized coins.

The daemon and background wallet refresh never initiate or submit private audit
requests. An export requires the owner's explicit action or authenticated wallet
RPC access delegated by the owner. Imports require that wallet's prior export,
the designated main developer's signature, matching network/genesis/snapshot and
a current revision. Owners cannot select a replacement signing authority to
self-clear. Audit decisions preserve ordinary consensus validation and stake
locks; public v2 enrollment and consensus lineage enforcement remain disabled.

## Main developer: required before release

The signing authority is intentionally **unset**. Supply the public key during
private release review; the branch does not invent an authority on the developer's
behalf. Exports and unsigned analysis work before designation. Production-network
signing and result acceptance fail until the authority is configured.

1. On the main developer's private processing machine, create a dedicated audit
   signing key with `salvium-audit-review --keygen /private/reviewer.key`, or use
   an independently managed compatible signing key.
2. Keep the private key outside Git, release artifacts and wallet-owner devices.
   Set only its public key in `src/cryptonote_core/audit_review_authority.h` for
   each supported production network. Empty entries remain disabled.
3. Confirm that public key through an independent channel. Build the
   daemon, CLI and shared wallet library from core `audit`, then update the GUI
   `audit` branch's `salvium` submodule pin to the reviewed core commit and rebuild.
   The core branch contains `main`; the separate GUI branch starts from `master`.
4. Publish the common snapshot height/hash and accepted scope. Owners export
   requests and send them privately to the main developer. Do not collect seeds,
   spend secrets or reusable viewing secrets.
5. Run verification, reconcile NonKYC's operator export, and examine unresolved
   recommendations. Confirm exchange scope and purchase attribution independently.
   Sign automatic results and any reasoned manual CLEAR/DENY decisions, then
   return only the relevant package results to each owner.

Unsigned results, owner-generated keys, changed snapshots and stale/conflicting
revisions cannot authorize clearance. Ephemeral signing keys exist only for
isolated fakechain tests. A wallet regtest flag does not bypass authority when
connected to a production daemon.

## Review and validation scope

The mainnet opening remains block 154749; accepted SAL-to-SAL1 authorizations are
preserved. Private reports declare `SUBMITTED_OUTPUTS_ONLY`. Wallet evidence does
not establish complete exchange liabilities, undisclosed holdings, a complete
historical consensus/PoW replay or the current global unauthorized balance.
Retain chain-wide monetary/forensic scans and historical replay as separate supply
audit requirements. Actual NonKYC records and owner requests are needed to perform
the real investigation.

Use `docs/AUDIT_PRIVATE_REVIEW.md` for exact processing commands, exchange schema,
wallet RPC paging, third-party transport and signature domains. The final
validation record must identify the tested source, binaries, tests and remaining
release limitations; historical audit validation files describe earlier versions.
The current record is [AUDIT_PRIVATE_REVIEW_VALIDATION.json](AUDIT_PRIVATE_REVIEW_VALIDATION.json).

## Reproduce the private workflow checks

Enable `SALVIUM_BUILD_LINEAGE_TESTS=ON` in `build/audit/release` when configuring
the static core build, then build with
`make release-static builddir=build/audit topdir=../../..`. Run these commands
from the core repository, one at a time:

~~~sh
bash tests/functional_tests/run_audit_limited.sh build/audit/release/src/cryptonote_core/audit_review_tests tests/data/sal1-bad-origin-465074.hex
bash tests/functional_tests/run_audit_limited.sh build/audit/release/src/cryptonote_core/lineage_audit_tests tests/data/sal1-bad-origin-465074.hex
bash tests/functional_tests/run_audit_limited.sh build/audit/release/src/wallet/wallet_audit_inventory_tests
bash tests/functional_tests/run_audit_limited.sh python3 tests/functional_tests/audit_nonkyc_reconciliation.py
bash tests/functional_tests/run_audit_limited.sh python3 tests/functional_tests/audit_private_review_regtest.py --binaries build/audit/release/bin
~~~

The integration fixture uses fresh software wallets, a separate local fakechain,
private test directories and loopback ports. It never starts the production
daemon. Its NonKYC ledger is synthetic. The lineage unit executable also retains
tests of the withdrawn public prototype; their success does not activate it.
The GUI needs its own full static build and interactive export/import check
before release; source syntax and QML lint alone do not establish a working GUI
release artifact.
