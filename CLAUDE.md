# Treska — Fast Forensic Parser
Fast forensic parser for zipped logical extractions in CTF competitions.
by ShadowStrike. MIT.

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
pipeline.py — parse_zip() entry point; triage_file() magic-byte dispatch (EVTX / deferred)
detect.py — detect_extraction_type(): IOS_FFS / ANDROID_LOGICAL / UNKNOWN by name only

## Parsers (src/treska/parsers/)
evtx.py — EVTX triage via python-evtx; HIGH_VALUE_IDS, SAMPLE_CAP module constants

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
- JSON schema: stable at v1.2.0, schema_version field in every output

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
