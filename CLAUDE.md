# Treska — Fast Forensic Parser
Fast forensic parser for zipped logical extractions in CTF competitions.
by ShadowStrike. Proprietary — all rights reserved.

## Dual delivery mode
CLI: treska challenge.zip [options]
Web: python -m treska  or  treska-web → 127.0.0.1:7332

Port 7332 ALWAYS for web mode — single PORT constant in web/main.py (distinct from Sarissa 7331, Poligon 7333).

## Core library (src/treska/core/) — shared, no duplication
ingestion.py — zip extraction, temp dir (try/finally cleanup, --keep)
magic_check.py — python-magic, mismatch detection
inventory.py — file inventory (path, size, extension, zip timestamp)
heuristics.py — 8 interesting-file flags
hashing.py — MD5/SHA-256 per file (ThreadPoolExecutor > 100 files; --no-hash → None)
sqlite_probe.py — SQLite schema extraction (magic bytes, not extension)
output.py — ParseResult dataclass consumed by both CLI and web
pipeline.py — parse_zip() entry point; triage_file() magic-byte dispatch (EVTX / deferred / iOS artifacts)
detect.py — detect_extraction_type(): IOS_FFS / ANDROID_LOGICAL / UNKNOWN by name only

## Parsers (src/treska/parsers/)
evtx.py — EVTX triage via python-evtx; HIGH_VALUE_IDS, SAMPLE_CAP module constants
sqlite_triage.py — shared read-only SQLite triage helpers + WAL staging (Phase 9/10)
ios.py — iOS FFS artifact triage; IOS_ARTIFACTS dispatch table (Phase 9)
android.py — Android logical artifact triage; ANDROID_ARTIFACTS dispatch table (Phase 10)

## CLI: treska/cli.py (thin wrapper over core)
## Web: src/treska/web/main.py (FastAPI, thin wrapper over core)
## Web frontend: src/treska/web/static/index.html (drag-drop, inline results, one Export JSON button)
## CORS: loopback-only — http://127.0.0.1:7331 and http://localhost:7331 (Sarissa integration); never "*"

## Tech stack
Python 3.11, python-magic (+ python-magic-bin Windows), rich, FastAPI, uvicorn, python-evtx,
concurrent.futures.ThreadPoolExecutor (hash parallelism > 100 files — NEVER
ProcessPoolExecutor, fork-bombs on Windows under PyInstaller), stdlib only elsewhere.

## Key invariants
- Core library: NO duplication between cli.py and web/main.py
- Port: 7332 ALWAYS for web mode
- --out: ALL output to file, nothing to console except "Written to:" line
- Mismatch flagging: NEVER suppressed by any flag
- --no-hash: hash columns always present, render as — (console/file) or null (JSON)
- ThreadPoolExecutor only — NEVER ProcessPoolExecutor
- Temp dir: ALWAYS cleaned on exit, even on error (try/finally)
- JSON schema: stable at v1.4.0, schema_version field in every output

## WHAT NOT TO DO
- Never duplicate parsing logic between cli.py and web/main.py
- Never use ProcessPoolExecutor (fork-bomb under PyInstaller on Windows)
- Never split output between console and file when --out is set
- Never suppress mismatch flags
- Never drop hash columns when --no-hash — render — / null instead
- Never break JSON schema without bumping schema_version
- Never use git add -A — always path-scoped adds

## Phase 6 (v1.1.0)
- EVTX triage: python-evtx (pure Python, imports as `Evtx`), HIGH_VALUE_IDS module-level constant (16 IDs), SAMPLE_CAP = 3
- Per-file result on FileEntry.triage: status parsed / empty / corrupt
- record_errors: count of unparseable records or truncated chunks within an otherwise valid log — does not mark the log corrupt.
- Detect-and-defer: E01 (EVF magic), VHDX (vhdxfile), AD1 (ADSEGMENTEDFILE), DD/IMG/BIN by extension only when libmagic says application/octet-stream → status: deferred, listed in ParseResult.deferred_files
- Legacy .evt ("LfLe" at offset 4) → its own deferred type (format "evt"), message says convert to .evtx with Event Viewer or wevtutil — not a disk image
- Magic byte takes precedence over extension; a .evtx without ElfFile magic is reported corrupt, never skipped
- Schema 1.0.0 → 1.1.0 (additive: FileEntry.triage, ParseResult.deferred_files)
- Tests: 42 → 55 (tests/test_phase6_evtx.py builds synthetic EVTX in-test; no real case data)

## Phase 7 (v1.2.0) — extraction type detection
- New file src/treska/core/detect.py: detect_extraction_type(tree_root: Path) -> str
- Return values (module constants): "IOS_FFS", "ANDROID_LOGICAL", "UNKNOWN"
- iOS FFS markers — any one anywhere in the tree → IOS_FFS:
  1. directory named HomeDomain
  2. directory matching AppDomain-* (any suffix)
  3. file named sms.db
  4. file named KnowledgeC.db
  5. file named AddressBook.sqlitedb
- Android logical markers — no Android detection existed before Phase 7, so detect.py
  defines it (any one anywhere in the tree → ANDROID_LOGICAL):
  1. file named mmssms.db
  2. file named contacts2.db
  3. file named calllog.db
  4. directory matching com.android.* (any suffix, e.g. com.android.providers.telephony)
- Order: iOS check runs FIRST over the whole tree; IOS_FFS returned as soon as a marker
  is found. Android check only runs when no iOS marker exists. Neither → UNKNOWN.
- Names match case-insensitively (casefold) — extraction tools capitalise
  inconsistently and a miss mid-CTF is a false negative (R, M/1.1.8).
- Filename/dirname only — NEVER opens, reads or stats file contents.
- Recursive walk (os.walk, followlinks=False) — no hardcoded depth.
- Missing or non-directory tree_root → UNKNOWN (never raises).
- Integration: parse_zip() returns a ParseResult dataclass (not a dict). Add
  ParseResult.extraction_type: str = "UNKNOWN" as a top-level field, set from
  detect_extraction_type(temp_dir) after extraction, before temp-dir cleanup.
  It appears top-level in the JSON from CLI --json and the web /api/parse
  response via dataclasses.asdict. Additive — no existing field changes.
- Schema 1.1.0 → 1.2.0 (additive: ParseResult.extraction_type), per the
  "never change JSON schema without bumping schema_version" invariant.
- Console summary line and web summary bar show the extraction type.
- Package version 1.1.0 → 1.2.0 in pyproject.toml (new capability = MINOR).
- Tests: tests/test_detect.py builds synthetic trees in tmp_path; no real case data.
  Minimum 8: homedomain, appdomain, sms_db, knowledgec, addressbook, android_logical,
  unknown, ios_priority_over_android; plus case_insensitive and parse_zip integration.
- Tests: 55 → 65
- Status: COMPLETE — merged to main (ShadowStrike-CTF/Treska#7), tagged v1.2.0, on PyPI.

## v1.2.1 — classifier fix (patch)
- treska 1.2.0 shipped to PyPI with "Development Status :: 1 - Planning"; PyPI metadata
  is immutable per release, so the fix needs a new version.
- pyproject.toml classifier → "Development Status :: 3 - Alpha"
- Package version 1.2.0 → 1.2.1 (metadata-only fix = PATCH)
- No code or output change: JSON schema_version stays 1.2.0
- Tests: 65 → 65 (no new tests)

## PACKAGING (PyInstaller)
Spec: treska.spec (onefile, console=False, pathex=['src'])
Datas: src/treska/web/static/index.html → treska/web/static/
Static dir: web/main.py resolves _STATIC from Path(__file__).parent / "static"; when frozen, __file__ is under sys._MEIPASS/treska/web/, so it lands on the bundled datas path.
Devnull guard: __main__.py redirects sys.stdout/stderr to devnull when None (windowed exe crash fix).
Build: pyinstaller treska.spec
Output: dist/treska (Linux ELF)
python-magic: hook-magic.py from pyinstaller-hooks-contrib handles it automatically.

## F04 — licence: MIT → Proprietary
- LICENSE: all rights reserved, no reproduction/distribution without ShadowStrike's written permission
- pyproject: `license = {text = "Proprietary"}`, classifier `License :: Other/Proprietary License`
- Every package .py carries `# © 2026 ShadowStrike. All rights reserved.` in its header
- README footer: `© 2026 ShadowStrike. All rights reserved. Aut Viam Inveniam Aut Faciam`
- MIT releases already on PyPI stay MIT; the proprietary licence applies from this version on
- Version 1.2.1 → 1.3.0. No tag pushed

## v1.3.1 — F02 TrustedHostMiddleware (patch)
v1.3.1 (F02 — M/1.1.12): TrustedHostMiddleware added. Restricts accepted Host
headers to 127.0.0.1 and localhost only. tests/conftest.py base_url patched to
http://127.0.0.1 — do not revert.
- Tests: 65 → 68 (confirmed at M/1.1.13 recon)

## Security Middleware — TrustedHostMiddleware (F02 — M/1.1.12)

TrustedHostMiddleware is active on this tool. It restricts accepted Host headers
to 127.0.0.1 and localhost only (allowed_hosts=["127.0.0.1", "localhost"]).
This is a deliberate security control — not a bug.

WHAT NOT TO DO:
- Do not remove TrustedHostMiddleware
- Do not widen allowed_hosts (no "*", no "testserver", no other hosts)
- Do not remove the tests/conftest.py TestClient patch or revert its default
  base_url to Starlette's "http://testserver"

Test suite: tests/conftest.py patches TestClient's default base_url to
"http://127.0.0.1" to match the middleware. If tests fail with 400 Invalid host
header, check base_url first.

## Phase 8 (v1.4.0) — CLI parity + Sarissa contract pinning
New CLI flags (cli.py stays a thin wrapper — all parsing still in parse_zip()):
- `--out FILE` (INV-03): parse FIRST, open FILE only after a successful parse — a
  parse error (exit 2) never creates or truncates FILE. Writes `FILE.partial` in the
  same dir, then `os.replace` onto FILE; `.partial` unlinked in a finally block.
  With `--json` the file is byte-identical to `--json` stdout (`_render_json`).
  Pretty mode renders through the same `_pretty_print(result, console, ...)` with
  `Console(file=fh, force_terminal=False, color_system=None, width=OUT_WIDTH,
  highlight=False)`; `OUT_WIDTH = 120` module constant. Stdout is exactly
  `Written to: <absolute path>` (plain print). Exit 3 when FILE can't be written:
  stderr `treska: cannot write output: <path>: <reason>`.
- `--no-hash` (INV-05): pass-through to `compute_hashes(skip=True)`; md5/sha256 keys
  always present — null in JSON, — in pretty. Mismatch flags unchanged (INV-04).
- `--keep` (INV-07 opt-out of temp-dir cleanup): `parse_zip(keep=True)`; CLI prints
  `Kept: <path>` to STDERR (diagnostic channel — stdout / --out untouched). CLI only.
- Exit codes: 1 input not found/unreadable · 2 parse error · 3 --out unwritable.

on_extract callback: `parse_zip(..., on_extract: Callable[[Path], None] | None = None)`
is called with temp_dir right after extraction (inside the try, so cleanup still
runs). It's how the caller learns the temp path — no ParseResult schema change.

Contract test (tests/test_contract.py): stdlib-only `CONTRACT[schema_version]` maps
result / file_entry / deferred keys → types (nullable = `T | None`). Exact key-set and
exact type equality via CLI subprocess and web TestClient `/api/parse` (sample.zip +
an in-test EVF zip so deferred_files is exercised). `test_contract_version_registered`
fails if SCHEMA_VERSION is bumped without a CONTRACT entry. Purpose: Sarissa reads this
JSON — any field drift fails loudly here before it ships.

- Schema: unchanged, stays 1.2.0. Package version 1.3.1 → 1.4.0 (new capability = MINOR)
- Tests: 68 → 83 (15 new: 12 in tests/test_cli.py, 3 in tests/test_contract.py)

WHAT NOT TO DO (Phase 8):
- Never add fields to ParseResult or FileEntry in Phase 8
- Never print to stdout except `Written to:` when `--out` is set
- Never let `--no-hash` drop or blank the hash fields (must be null/—)
- Never write `--out` directly to the final path (use .partial + os.replace)
- Never expose `--keep` in the web UI
- Never add jsonschema or any test/runtime dependency for the contract test

## Phase 9 (v1.5.0) — iOS FFS artifact triage
Read-only triage of the three key iOS databases, gated on extraction_type == IOS_FFS.
Results land on FileEntry.triage (same slot as EVTX), so CLI, web and Sarissa all get
them through parse_zip() — no iOS logic in cli.py or web/main.py.

New triage.format values:
- `ios_sms` — sms.db (required tables: message, handle, chat; attachment optional)
  summary: message_count, sent_count, received_count, chat_count, handle_count,
  attachment_count, first_message, last_message
  samples: ≤ SAMPLE_CAP most-recent messages {time, direction, handle, text}
- `ios_knowledgec` — KnowledgeC.db (required table: ZOBJECT)
  summary: total_rows, stream_counts [{stream, count}] (top TOP_N by ZSTREAMNAME),
  top_bundles [{bundle_id, count}] (top TOP_N /app/usage), first_event, last_event
  samples: ≤ SAMPLE_CAP most-recent /app/usage rows {bundle_id, start, end}
- `ios_addressbook` — AddressBook.sqlitedb (required table: ABPerson; ABMultiValue optional)
  summary: person_count, phone_count, email_count
  samples: ≤ SAMPLE_CAP persons {first_name, last_name, organization, first_phone_or_email}

Every iOS triage dict has the same key set (exact-key contract): filename, format,
status, error, warnings, wal_present, wal_applied, summary, samples.
- status: `corrupt` = can't open as SQLite OR none of the required tables exist
  (summary null); `empty` = required tables present, zero rows; `parsed` otherwise.
- Missing optional table/column → `warnings` entry and that key → null.
- Times: apple_to_iso() — Cocoa epoch (seconds since 2001-01-01 UTC); values > 1e11 are
  nanoseconds (iOS 11+); 0/None → null. Output `YYYY-MM-DDTHH:MM:SSZ`.

Files:
- src/treska/parsers/sqlite_triage.py — shared helpers for ios.py (Phase 9) and
  android.py (Phase 10). Constants SAMPLE_CAP = 3, TEXT_CAP = 200, TOP_N = 10.
  open_readonly (mode=ro&immutable=1), table_columns, safe_count, result_skeleton,
  truncate, WAL staging. Everything reusable lives here, not in ios.py.
- src/treska/parsers/ios.py — `IOS_ARTIFACTS` dispatch table keyed by casefolded
  filename → (format, parser): sms.db, knowledgec.db, addressbook.sqlitedb.
- Pipeline reorder: detect_extraction_type(temp_dir) now runs right after extract(),
  before the per-file triage loop, and its result is passed to triage_file(). detect.py
  itself is unchanged. The iOS branch sits after the EVTX/deferred checks (magic still
  wins) and checks the SQLite header (core.sqlite_probe.is_sqlite) before dispatch.
- Output: CLI `_print_ios(console, triage)` beside `_print_evtx`; web `renderIos()`
  (el()/textContent only).

WAL handling (Option A — locked M/1.1.13):
- If `<name>-wal` sits beside the DB: copy db + -wal + -shm (if present) to
  `temp_dir/.treska_wal/<uuid8>/`, open the COPY (no immutable — SQLite replays the WAL),
  triage gets `wal_present: true, wal_applied: true`.
- No WAL: open the original with mode=ro&immutable=1, `wal_present: false, wal_applied: false`.
- Copy/open of the copy fails → fall back to the original (immutable), wal_applied false
  + warning.
- Originals are never opened read-write and never modified. Hashes are computed on the
  originals before any WAL copy. .treska_wal/ lives under temp_dir, so the existing
  cleanup removes it (with --keep it stays in the kept dir).

- Schema 1.2.0 → 1.3.0 (additive: new triage.format values and their shapes).
  CONTRACT["1.3.0"] added to tests/test_contract.py; CONTRACT["1.2.0"] kept unchanged.
- Package version 1.4.0 → 1.5.0 (new capability = MINOR)
- Tests: baseline 82 collected (81 passed + Poligon integration module skipped —
  the Phase 8 line above says 83; that count is drift) → 98 collected (97 passed +
  Poligon module skipped). 16 new: 15 in tests/test_phase9_ios.py (synthetic DBs in
  tmp_path with real iOS table/column names), 1 in tests/test_contract.py
  (test_contract_1_3_0). tests/integration/test_poligon_template_f.py also asserts
  ios_* triage status "parsed" for every Template F seed/difficulty.
- Fixture: tests/fixtures/ios_sample.zip (regenerate with
  python tests/fixtures/make_ios_fixture.py) — sms.db ships an uncheckpointed -wal/-shm
  so the WAL path runs end to end; used by the contract test and the G.0 smoke gate.

WHAT NOT TO DO (Phase 9):
- Never open evidence read-write
- Never dispatch on extension alone without SQLite header check
- Never dump full tables or blobs — SAMPLE_CAP and TEXT_CAP apply
- Never let a parser exception escape `parse_zip`
- Never put iOS logic in `cli.py` or `web/main.py`
- Never render sample text with innerHTML
- Never add a third-party dependency (sqlite3 is stdlib)
- Never remove or rename existing triage keys or EVTX formats
- Never change `detect.py` markers or logic — only its call position moves
- Never use ProcessPoolExecutor

## Phase 10 (v1.6.0) — Android logical artifact triage
Read-only triage of the three key Android databases, gated on extraction_type ==
ANDROID_LOGICAL. Same slot (FileEntry.triage), same 9-key triage dict, same status rules
as Phase 9 — CLI, web and Sarissa get it through parse_zip(); no Android logic in cli.py
or web/main.py.

New triage.format values:
- `android_mmssms` — mmssms.db (required table: sms; pdu optional)
  summary: total, inbox (type=1), sent (type=2), other (any other type),
  mms_count (pdu rows; 0 when no pdu table), address_count (distinct sms.address),
  first_message / last_message (sms.date), first_mms / last_mms (pdu.date; null when
  no pdu table)
  samples: ≤ SAMPLE_CAP most-recent SMS {time, direction, address, body}
  (direction: type 1 → "received", type 2 → "sent", otherwise null)
- `android_contacts` — contacts2.db (required table: raw_contacts)
  summary: raw_contact_count, contact_count (contacts table), phone_count / email_count
  (data JOIN mimetypes, mimetype vnd.android.cursor.item/phone_v2 / email_v2),
  embedded_calls
  samples: ≤ SAMPLE_CAP raw contacts {display_name, first_phone_or_email} (phone preferred)
  embedded_calls (Q2 locked M/1.1.13): ALWAYS present in the summary — null when
  contacts2.db has no calls table, else {"count": int, "types": {type_label: count}}.
  One triage per FileEntry; never a separate triage dict for the calls table.
  Phone numbers in full (Q3 locked M/1.1.13 — CTF data, masking hides flags).
- `android_calllog` — calllog.db (required table: calls)
  summary: total, by_type {type_label: count} (CALL_TYPES; unknown → "other"),
  total_duration_seconds, first_call / last_call (calls.date)
  samples: ≤ SAMPLE_CAP most-recent calls {time, type, number, duration_seconds}
- CALL_TYPES: 1 incoming, 2 outgoing, 3 missed, 4 voicemail, 5 rejected, 6 blocked.

Timestamp units (INV-P10-1) — fixed per column in code, NEVER guessed from the value:
- `sms.date`, `calls.date` → Unix MILLISECONDS → unix_ms_to_iso()
- `pdu.date` (MMS) → Unix SECONDS → unix_s_to_iso()
- 0/None → null. Output `YYYY-MM-DDTHH:MM:SSZ` (same as Phase 9).

Files:
- src/treska/parsers/android.py — SQL and field mapping only. `ANDROID_ARTIFACTS`
  dispatch table keyed by casefolded filename → (format, parser): mmssms.db,
  contacts2.db, calllog.db.
- Every connection / count / sample / truncation / result-skeleton / status-frame helper
  lives in src/treska/parsers/sqlite_triage.py and is used by both ios.py and android.py.
- Pipeline: triage_file() gets an ANDROID_LOGICAL branch beside the IOS_FFS branch (one
  generic artifact-dispatch helper, SQLite-header gate, corrupt-on-exception). The two
  branches are mutually exclusive — extraction_type has one value. detect.py unchanged.

WAL handling: identical to Phase 9 Option A (Q1-A locked M/1.1.13) — `<name>-wal`
beside the DB → copy db + -wal + -shm to temp_dir/.treska_wal/<uuid8>/, open the copy,
`wal_present`/`wal_applied` on the triage. mmssms.db and contacts2.db commonly run in WAL.

Known limitation (by design, pinned by test_android_triage_gated_on_extraction_type):
iOS takes priority in detection. A zip with both iOS and Android markers is `IOS_FFS`,
and its Android DBs get NO Android triage. Changing this means a multi-valued
extraction_type — a breaking schema change, out of scope.

- Schema 1.3.0 → 1.4.0 (additive: three new triage.format values and their shapes).
  CONTRACT["1.4.0"] added to tests/test_contract.py; CONTRACT["1.2.0"] and
  CONTRACT["1.3.0"] kept unchanged.
- Package version 1.5.0 → 1.6.0 (new capability = MINOR)

sqlite_triage.py extensions (Phase 10 reuse — moved out of ios.py, no behaviour change):
`Schema`, `Body`, `has`, `need_column`, `count_table`, `fetch_rows`, `triage_sqlite`
(the shared open → required-tables → body → status frame), and `epoch_to_iso(epoch,
seconds)` (shared ISO formatting + None/blob/0/NaN/overflow guards). ios.py's
`apple_to_iso` and android.py's `unix_ms_to_iso` / `unix_s_to_iso` all call
`epoch_to_iso`; ios.py public names unchanged.

Pipeline: `_ios_triage` generalised to `_artifact_triage(artifacts, ...)`, picked from
`DEVICE_ARTIFACTS = {IOS_FFS: IOS_ARTIFACTS, ANDROID_LOGICAL: ANDROID_ARTIFACTS}`.
Output: CLI `_print_device(console, triage, platform)` (was `_print_ios`) renders both
platforms; summary line adds `N Android`. Web `renderDevice()` backs `renderIos()` and
`renderAndroid()` (el()/textContent only); summary bar adds the Android count.

Contract: `_check_contract(data, version=...)` can pin an older CONTRACT entry.
`test_contract_1_3_0` now checks iOS output against BOTH the unchanged
CONTRACT["1.3.0"] shapes and the current contract (the live schema_version is 1.4.0).
Android shapes add "objects" (embedded_calls) and "count_maps" (by_type,
embedded_calls.types → every value int).

- Tests: 98 collected (97 passed + Poligon module skipped) → 112 collected (111 passed +
  Poligon module skipped). 14 new: 13 in tests/test_phase10_android.py (synthetic DBs in
  tmp_path with real AOSP table/column names), 1 in tests/test_contract.py
  (test_contract_1_4_0). Literal schema "1.3.0" assertions in test_cli.py, test_web.py,
  test_core.py bumped to "1.4.0".
- Fixture: tests/fixtures/android_sample.zip (regenerate with
  python tests/fixtures/make_android_fixture.py; reuses make_db / zip_tree from
  make_ios_fixture.py) — mmssms.db and contacts2.db ship uncheckpointed -wal/-shm so the
  WAL path runs end to end; contacts2.db carries the embedded calls table. Used by the
  contract test and the G.0 smoke gate.

OPEN ITEM: Android template for Poligon — candidate for future Poligon phase. Poligon
had no Android logical template at M/1.1.13 recon, so Phase 10 has synthetic tests only
(no tests/integration/test_poligon_android.py).

WHAT NOT TO DO (Phase 10):
- Never copy-paste Phase 9 helpers into android.py — extend sqlite_triage.py instead
- Never change iOS priority in detect.py or make extraction_type multi-valued
- Never guess epoch units from the value — each column's unit is fixed in code
- Never read parts/attachment blobs — counts and text samples only
- Never follow paths stored inside DBs (e.g. part._data) to open other files
- Never write to evidence or run write-side PRAGMAs
- Never let a parser exception escape parse_zip
- Never add third-party dependencies
- Never remove or rename any 1.3.0 field — change must be additive only
- Never use git add -A
