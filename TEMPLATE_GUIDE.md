# stub_template_v1_0_10 — Substitution Guide

Replace all placeholders before use. Search-and-replace across all files.

| Placeholder  | Replace with                                     | Example                                   |
|-------------|--------------------------------------------------|-------------------------------------------|
| PACKAGENAME | PyPI slug (ASCII, lowercase, hyphens if needed)  | pechat                                    |
| DISPLAYNAME | Display name with diacritics if applicable       | Pečat                                     |
| REPONAME    | GitHub repo name (ASCII, lowercase, hyphens)     | pechat                                    |
| ONELINER    | One-line description from Product Directory      | Forensic file hashing and verification.   |
| YEAR        | Current year                                     | 2026                                      |

## What the template provides

These files are pre-built and ready to use — substitution only, no new content required:

| File | What it does |
|------|--------------|
| `pyproject.toml` | hatchling build backend, Proprietary licence, Python 3.11 floor, 3.11 + 3.12 classifiers, src layout wheel target, GitHub source URL |
| `src/PACKAGENAME/__init__.py` | Package entry point with copyright + motto header |
| `README.md` | v1.6 format — one-liner, GitHub link, copyright footer, Aut Viam motto |
| `LICENSE` | Proprietary licence under Strategos Pty Ltd (ACN 699 862 078) |
| `.gitignore` | Standard Python ignores (dist/, build/, __pycache__, *.egg-info) |
| `TEMPLATE_GUIDE.md` | This file |
| `.github/workflows/publish.yml` | Trusted OIDC publishing — fires on `git tag v*` push |

## What you must customise

1. Search-and-replace all five PLACEHOLDERS (table above) across every file
2. Set YEAR to the current year (do not hardcode — check the year at time of use)
3. README line 2: use the exact one-liner from the Product Directory in the brand attribution doc — verbatim, not paraphrased
4. README attribution suffix: `Part of the Strategos Suite.` (Tier 1) or `by Strategos.` (Tier 2) or `by ShadowStrike.` (Tier 3) — choose per tier
5. PyPI-side setup (one-time, per package): PyPI → Manage → Publishing → Add trusted publisher — Owner: ShadowStrike-CTF, Repository: REPONAME, Workflow: publish.yml, Environment: pypi
6. GitHub: create environment named `pypi` in repo Settings → Environments

## Classifier note — stubs vs live packages

**All stubs (all streams):** 3.11 + 3.12 classifiers are correct as shipped. Classifiers are metadata only — no runtime effect.

**Live SA tool packages (Phalanx, Prenos, Feniks, Pečat, Tolmač pyproject.toml):** hold 3.12 classifier until PyInstaller 3.12 Windows build verification is complete. Classifier must follow confirmed support, not advertise it in advance.

## What a valid stub is NOT

- Not a development package — no real code, no tests, no CLI
- Not a namespace redirect unless explicitly using the namespace-pointing README variant (svest→svest-unmark pattern)
- Not published with a pre-release version suffix (a, b, rc, .dev) — those go to TestPyPI only

## File structure

```
stub_template_v1_0_10/
├── pyproject.toml               ← hatchling, src layout, Proprietary, 3.11 + 3.12 classifiers
├── README.md                    ← v1.6 format (GitHub link, one-liner, attribution, footer)
├── LICENSE                      ← Proprietary
├── .gitignore
├── TEMPLATE_GUIDE.md            ← this file
├── src/
│   └── PACKAGENAME/
│       └── __init__.py          ← copyright + motto header
└── .github/
    └── workflows/
        └── publish.yml          ← trusted publishing via OIDC
```

## Suite-wide standards locked

- Build backend: hatchling (Suite-wide — D stream and SA stream)
- Package layout: src layout — `src/PACKAGENAME/`
- Licence: Proprietary
- Python floor: 3.11
- Python classifiers (stubs): 3.11 + 3.12
- Python classifiers (live SA tools): 3.11 only until PyInstaller 3.12 Windows verification done
- Publish method (target): trusted publishing via OIDC
- Publish method (interim): manual twine

## PyPI-side setup (one-time per package)

PyPI → Manage → Publishing → Add a trusted publisher:
  - Owner: ShadowStrike-CTF
  - Repository: REPONAME
  - Workflow: publish.yml
  - Environment: pypi

## Trigger for publish

```
git tag v0.0.1
git push origin v0.0.1
```

## Version history

### v1.0.10 changes
- pyproject.toml: `Programming Language :: Python :: 3.12` added to classifiers
- TEMPLATE_GUIDE.md: classifier note corrected — all stubs get 3.11 + 3.12 (metadata only);
  live SA tool packages defer 3.12 until PyInstaller 3.12 Windows verification complete

### v1.0.9 changes
- pyproject.toml: `Programming Language :: Python :: 3.11` added to classifiers
- TEMPLATE_GUIDE.md: stream-specific classifier note added (superseded by v1.0.10)

### v1.0.8 changes
- src layout: PACKAGENAME/ moved to src/PACKAGENAME/
- pyproject.toml: [tool.hatch.build.targets.wheel] added

### v1.0.7 changes
- pyproject.toml: copyright + motto comment added to top of file

### v1.0.6 changes (was v1.0.4 — versioning corrected)
- Build backend: hatchling; Licence: Proprietary; publish.yml added; Python 3.11 floor
