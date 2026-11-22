# audit2 security review and historical audit handoff

This review is local work on `audit2`, based on upstream main `40c7a671ad96247335f9789e99e74463e2d4f298`. The existing audit implementation was carried over selectively. The separate `audit` importer/yield fixes were pushed as `565645e5c8b39d2dd32babb09249ee433e0df423`. The broader `audit2` changes remain local. Production activation heights and signing authorities remain unset. Production binaries, wallets and blockchain data are outside the audit build and test directories.

The financial results belong to the private, snapshot-bound report bundle under `build/audit2-historical-20261122`. Its final summary includes separate salYAHU and additional bad actor reports. Incident labels identify transactions, not people. Only affirmative, independently checked evidence supports denial. Private ancestry, unavailable exchange records and decoy references do not support denial.

## Issues and changes

| Area | Issue or verified limitation | Change and qualification |
|---|---|---|
| salYAHU issuance class | Historical ordinary transactions could escape source/output asset binding. | An explicit funded-source asset check applies to current HF13 validation independently of historical height exceptions, and to new mempool admissions. The actual historical transaction is a rejection regression. Historical consensus replay retains historical rules. |
| PR remainder proof | Scalar/point encoding and an unused proof field were not uniformly constrained. | Canonical scalar, subgroup and point encoding checks, including the unused-field constraint, apply to new mempool admissions and proposed HF14 consensus. Valid zero remainders remain accepted. Malformed point verification fails closed. This is encoding hardening; no new PR-based inflation was demonstrated. |
| RingCT verifier | Some direct verification paths indexed signature vectors assuming an earlier semantic check had run. | Validate nonempty input/output sets and matching signature vector sizes before indexing or parallel verification. |
| SPARC and spend authority proofs | Validation and generation checks differed, including a debug-only witness assertion in a legacy helper. | Validate canonical points/scalars, fail closed on malformed points, enforce witness consistency in release builds and wipe nonce buffers. Existing transcript domains remain unchanged for compatibility. |
| CARROT key derivation | A temporary scalar derivation buffer retained sensitive intermediate material. | Wipe the buffer on every exit. |
| CARROT enote loading | Reused result objects retained output-key entries; encrypted return-key data was not reconstructed. | Reset the result before decoding, recover encrypted return-key data and validate its presence. Repeated decoding is covered by regression tests. |
| CARROT proposal comparison | Optional ephemeral keys were compared through their storage representation. | Compare optional presence and the complete contained key value. |
| Token metadata | Metadata/version validation was inconsistent between builders and admission paths; several scalar fields lacked defaults. | Initialize metadata fields and apply canonical token names/versions to new admissions and proposed HF14. Keep existing token supply, price and uniqueness checks. |
| Token wallet/API/RPC | JSON metadata handling assumed an object, metadata text was assembled without JSON escaping, and character conversion accepted signed chars. | Check JSON object/encoding, validate supplied hashes, encode strings with JSON serialization and use explicit ASCII normalization. Align the RPC supply bound with consensus. |
| Rollups | A semantic item limit was checked after deserialization. | Enforce the existing 256-entry limit during serialization/deserialization too. Retain checked fee addition and full canonical fee authorization matching. |
| Clearance certificates | Signed authorizations lacked an authenticated historical policy digest, version and cutoff. | Bind all three into v4 signatures and serialization. Validate them against compiled policy settings and reject certificates for outputs after the cutoff. Real-network activation fails closed without a pinned approved policy. Canonical authority encodings are required. A CLEAR certificate cannot authorize an intrinsically wrong-asset or nonzero confidential-amount origin; explicit DENY records remain valid. Snapshot, network, authority, revision, finality, H+1 and reorg protections remain. This changes the unactivated v4 draft wire layout; all participating builds must agree before activation. |
| Forensic ancestry | The older auxiliary scanner recursively propagated possible decoy relationships. | Propagate only demonstrable relationships with valid spending proofs. The final historical report independently uses verified singleton inputs and explicit protocol obligations; possible decoy relationships never enter its denial graph. Legacy auxiliary candidate diagnostics are not evidence of bad actors. |
| Report integrity | Output counts, payout authorization and supply arithmetic could be misread or detached from canonical references. | Stream exact integer evidence into an indexed inventory; reject inconsistent canonical references, partial scans, duplicate identities and mismatched payouts. Keep original illicit issuance separate from descendants, and counts separate from current monetary value. |

## CARROT transition staking

Current main already contains exact legacy stake payout validation across the CARROT transition. A new regression exercises a pre-CARROT stake maturing after the transition and confirms exact amount authorization. Independent canonical accounting checked 795 pre-CARROT stakes paid at heights 334750 through 356350. Every payout matched its authorization, with zero excessive or duplicate payouts. Expected and actual totals both equal 3,084,569,266,417,080 atomic units, including 3,036,024,909,516,567 atomic units of principal. This establishes the public obligation checks for that window; it does not identify private spend ancestry. No attack procedure is included in this handoff.

## Additional hardening and tool integrity

Private file writes reject symlinks, multiple links, nonregular files and foreign
owners before truncation. Windows file-size/read results use explicit success
status and checked sizes. TLS callbacks retain their hostname safely and cannot
disable verification while requesting certificate pins. Hardware passphrases
have a secure API/GUI callback with wiped temporary buffers. Hardware signing
refuses ordinary unsigned transaction files. Reserve proofs reject identity or
non-subgroup key images. Logging, hexadecimal conversion and truncated JSON
Unicode parsing have additional bounds regressions.

Yield snapshots use checked totals, exact maturity settings and recoverable
refresh failures. The API and GUI preserve required HTTPS. Compiler hardening
raises fortified bounds checks to level 2 while retaining existing stack,
position-independent and linker protections. GUI-specific changes and dependency
coverage are documented in the companion GUI repository's security review.

The importer now propagates failures and checks the requested ending height.
Its isolated regression covers inclusive final-block resume, already completed
imports, missing/truncated input and an unavailable requested endpoint. A bulk
replay failure followed by a successful individual-block replay is retained as
a tool limitation, not an illicit-chain finding.

The first full inventory exposed three legacy transfers whose unused burn
header field was incorrectly included by the forensic verifier. The corrected
verification matches historical consensus; all three canonical proofs pass.
The fresh corrected inventory completed through height 624655: 1,366,138 transactions, 3,478,629 outputs and zero unresolved cryptographic failures. The report also accepts
authorized token creation and protocol issuance in the same block while
retaining strict earlier-height rules for stake returns. Its disposable SQLite
inventory now uses transactional journaling so rejected evidence does not leave
a corrupt diagnostic database.

## Completed public inventory and stake eligibility

The snapshot-bound report identifies the salYAHU wrong-asset source transaction
at height 465074, with exactly 4,000,000,000,000,000 atomic SAL1 of original
unauthorized issuance. It separately lists 7,208 nonzero confidential-output
amount events at heights 512240 through 513067, affecting 50,456 outputs.
Their net excess monetary issuance is **NOT VERIFIABLE** from this evidence.
Together, 50,458 direct outputs are proposed for denial; no proven descendants
or human identities are inferred from ring decoys.

The unsigned plan includes eligible SAL1 stake principals and exact native
return inheritance. At the snapshot, 525 such principals had no return yet,
with 4,365,667,019,963,977 atomic SAL1 of principal. These are historical
eligibility results, not issued certificates or extra supply. Already returned
principals and payouts are not counted twice. Production activation remains 0.

## Additional build and concurrency review

RandomX cache/seed and lazy setting reads required synchronization, and POSIX
background seed threads were left joinable after their handles were discarded.
The code now observes each cache/seed under its corresponding lock, serializes
settings initialization, and detaches unjoined background threads. The proof
algorithm and valid input semantics are unchanged. Qualification compares the
shared-cache wrapper with independent reference caches under concurrent seed
changes. This is a source concurrency finding; it does not establish the cause
of the retained intermittent importer verification failures.

The requested dependency baseline is OpenSSL **4.0.1**, with 23 official security
backports recorded in `contrib/depends/patches/openssl/security-20261122.json`.
QUIC, which neither core nor Qt 5 uses, is disabled; ten QUIC-only advisories are
recorded as excluded by configuration. The original release and applied patch
are digest-bound. The configured upstream SDK passed 4,095 tests in 363 files.
The static release build also uses static Unbound against that same SDK. The
resulting daemon has no shared OpenSSL dependency, including indirect dependencies
through Unbound.
Linux retains its supported operating-system runtime dependencies; this is the
repository's `release-static` configuration. The host selected a Kali compatibility
policy containing SSLv3, which OpenSSL 4 rejects. After explicit authentication,
the host was changed to its existing strong TLS 1.2 policy, with the original
configuration backed up. The daemon and four isolated wallet services then
started using the corrected default policy. No production daemon was restarted.

## Published advisory review

The review queried the official NVD Monero/Salvium records, OSV commit records for pinned submodules, and OSV records for the installed Debian dependency versions. Query inputs and raw results are retained privately with the run evidence. Recipe versions are inventoried separately from the libraries actually used by this host build. Empty query results describe database coverage, not a proof of absence of vulnerabilities.

- **CVE-2026-110655 and CVE-2026-110656:** applicable MiniUPnPc XML parser bounds defects. Updated the bundled client pin to upstream `64ef08a12aabab57be0bf7e40f047c8f14dedf9c`, which includes both client fixes, and adapted the include paths/API. [First upstream fix](https://github.com/miniupnp/miniupnp/commit/3cfb4fb78d5ac04ed0dadc8dd842fc9e448916db), [second upstream fix](https://github.com/miniupnp/miniupnp/commit/64ef08a12aabab57be0bf7e40f047c8f14dedf9c).
- **CVE-2025-26819:** applicable RPC connection/response resource limits. Backported the upstream limits for response queues and per-address/total connections, including operator configuration and isolated loopback regression tests. [Upstream correction](https://github.com/monero-project/monero/commit/ec74ff4a3d3ca38b7912af680209a45fd1701c3d).
- **CVE-2018-3972:** inspected the inherited Epee portable-storage bounds checks; the size/minimum-element checks are present. Additional audit JSON and certificate parsing retain explicit work/size limits. [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2018-3972).
- **CVE-2020-6861** concerns old Ledger application firmware; **CVE-2020-26947** concerns the separate Monero GUI loader configuration. They are not corrections to this core's CARROT/PR proof math. No current-directory RPATH was found in the reviewed core build configuration.
- MiniUPnP server advisories **CVE-2026-5720/CVE-2026-107159** concern the server component, which this client build does not compile. Monero forum **CVE-2025-34060** and Wireshark **CVE-2026-5409** concern separate products.

The post-update OSV submodule query retained one server-only MiniUPnP match and no client matches. The exact-version Debian query returned no matches for the ten queried source packages. This is an applicability review, not certification against every vulnerability ever published or vulnerabilities not yet disclosed.

## Validation and limits

Build with `make release-static builddir=build/audit topdir=../../..`. Tests use isolated fakechains, explicit empty configs, private temporary wallets and loopback ports. Production daemon startup/restart is never part of this work.

Final run results, hashes and durations are recorded in the local validation bundle.
The static OpenSSL 4.0.1 build passed 212 current-format cryptographic tests, the
HTTP resource-limit fixture, authority/clearance/review/lineage/wallet regressions
and a full 21,600-block cleared-stake cycle including payout spending.
The token lifecycle fixture also passed canonical metadata, registration,
fee-backed transfer, exact per-asset balances and a complete native export.
Importer completion regressions passed against a read-only source export. Tests cover current CARROT/SPARC, range proofs, PR/SA proofs, protocol payouts, actual historical malformed issuance, certificate policy tampering/replay/reorg, wallet inventory, report integrity, HTTP limits, token creation/fee-backed transfer and the complete cleared staking maturity cycle.

The imported upstream RingCT test file also contains retired Borromean RCTTypeFull/RCTTypeSimple wire-format fixtures. Ninety such tests fail at the baseline serializer's intentional format rejection; they are explicitly excluded from current-format qualification, rather than re-enabling retired transaction formats. Initial CARROT test fixtures also omitted initialized account catalogs, assets and source/carrier data; those fixtures were corrected for the current scanning interfaces. The unfinished FCMP proposal signing adapter is outside supported production signing coverage; scanning fixtures do not certify that adapter.

No main-developer-approved irreversible amnesty policy, production authority or activation is configured. Report classifications and clearance plans therefore describe eligibility; they issue no certificates. Legacy SAL inventory is reported, but the current native clearance mechanism supports SAL1 and supported tokens, not an additional SAL recovery conversion protocol. Full historical PoW/chain-selection replay, external exchange authentication, private actual-spend reconstruction and production deployment are not claimed by the public-chain inventory.

Exact current outstanding supply and approved current monetary value must remain **NOT VERIFIABLE** wherever public evidence cannot establish them. Staking principal, conversions, transfers and exchange custody movements are not extra issuance. Denial is not a burn. The final supply report must retain unresolved discrepancies rather than manufacture a fully reconciled total.
