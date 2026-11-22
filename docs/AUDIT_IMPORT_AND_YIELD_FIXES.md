# Import completion and stake yield corrections

The review addressed importer completion, the inclusive resume boundary and the
stake maturity height shared with the GUI. The companion GUI correction also
preserves payout asset labels and exact atomic amount formatting.

The bootstrap counter consumes complete chunk bodies and rejects partial chunk
headers, truncated metadata and truncated bodies. Zero-block seeks leave the
first requested chunk untouched. Source ranges use checked arithmetic. The
importer propagates errors to its process exit status, verifies its requested
ending height and resumes when the final source block is the next required block.

A stake return is produced at source height plus the network lock period plus
one. Wallet height counts scanned blocks, so that return block must be scanned
before the shared `stake_completed()` helper reports completion. Yield summaries
also reject duplicate or unordered history and bound accrual to the authorized
stake earning interval. Busy refresh callbacks fail recoverably.

Validation on 2026-11-22:

- The `audit` importer and exporter were built from that branch with
  `make release-static builddir=build/audit topdir=../../..` and focused targets.
- `tests/functional_tests/blockchain_import_completion.py` passed all 19 command
  checks: inclusive resume, complete no-op, default end, a source beginning at
  the next required block, missing/unavailable input, partial file metadata,
  all three partial chunk-header lengths and a truncated body. The counter and
  importer both reject damaged input, including when no end height is supplied.
- All four `wallet_yield_tests` passed on both branches, including the exact
  maturity boundary, network lock periods, height limits and amount overflow.
- The existing native `audit` wallet inventory regression passed.
- The companion GUI QML suite passed 14 checks on each branch. Its yield native
  bindings use the same interface and source on both branches; the instrumented
  GUI binding tests check exact amounts above 2^53 and snapshot ownership.

These checks use a read-only source snapshot and new isolated import databases.
They never start a daemon or write production chain or wallet data. Production
binary hashes remained unchanged. This correction is separate from completion
of the full historical audit and from any production clearance activation.
