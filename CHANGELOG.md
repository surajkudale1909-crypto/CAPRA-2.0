# Changelog

All notable changes to CAPRA (Context-Aware Mobile App Privacy Risk Analyzer) are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/).

## [2.1.0] — 2026-10-27 — GUI Polish & Usability

### Changed — Threat Classification (no more "UNKNOWN")
- **Every scan now ends in a definitive classification.** When external intel (hash DB / VirusTotal) has no verdict, the fused risk decides: Medium risk (46/100) or above → `SUSPECTED_THREAT`, lower → `NO_THREAT_DETECTED`. Known intel verdicts (`MALICIOUS`, `VERIFIED_BENIGN`, `SUSPICIOUS`) are unchanged and keep their fusion-override semantics.
- GUI history table and metric chip show the definitive label (old rows with stored `UNKNOWN` are re-derived from their score at display time) and are color-coded green/red.
- Overview tab gains an explicit `Threat Status` line; heuristic verdicts carry an explanatory reputation/recommendation (`source: LOCAL_ANALYSIS`).

### Added — VirusTotal API Key
- **GUI settings dialog** (header **⚙ API Key**): paste/save/remove a VirusTotal v3 key with masked display; persisted in `~/.capra/gui_settings.json` and applied live to the running scan engine.
- The same stored key is picked up by the CLI and web dashboard (environment variable `VIRUSTOTAL_API_KEY` / `.env` still takes precedence); `--vt-key` and `--no-vt` unchanged.

### Added — Desktop GUI
- **Light/dark theme toggle** with persisted preference (`~/.capra/gui_settings.json`)
- **Banded risk gauge** (5 verdict-colored arcs) with animated needle sweep and band legend
- Color-coded metric chips; **Permissions breakdown** and **Exfiltration Combinations** Treeview tables with green/amber/red/gray/blue row tags
- **Progress bar + Cancel + elapsed timer** with a busy-state guard against concurrent scans
- Selected-filename feedback (name + size), **recent-files dropdown**, and last-directory memory
- **Export Markdown / Export JSON / Open Reports Folder** actions plus ML feature-importance plot viewer
- **Scan History window**: refresh, multi-delete, and two-scan comparison (score/ML drift, tracker delta, verdict trajectory)
- Optional **drag & drop** via `tkinterdnd2` (graceful fallback to Browse when unavailable)
- Friendlier error dialogs with actionable remediation hints

### Engineering
- Presentation logic extracted into **`src/gui_formatters.py`** (Tk-free: risk bands, gauge geometry, permission/combination rows, theme palettes, settings persistence, text builders) — fully unit-tested headless
- **`tests/test_gui_formatters.py`** (26 tests) and **`tests/test_gui_headless_logic.py`** (mock-Tk harness reproducing CI's pinned GUI flow without a display) — suite now 209 passing
- CI `tests/test_gui.py` pins unchanged (exact status string, synchronous `_execute_analysis`, busy-flag semantics)

## [2.0.0] — 2026-10-26

Complete v2 rebuild of the CAPRA privacy-risk analyzer (VIT Pune, CS-AI, EDAI Group 8).

### Added — Core Analysis
- **8-stage analysis pipeline**: threat intel → manifest parsing → category auto-detection → context heuristics → ML inference → bytecode static analysis → score fusion → audit logging/reporting
- **13-category context engine** with data-driven baselines (`data/context_rules.json`) and category aliases
- **Collusion/exfiltration matrix**: 9 dangerous permission-combination detectors (storage exfiltration, contact harvesting, audio wiretapping, SMS/2FA interception, visual surveillance, call-log exfiltration, location tracking, media-library exfiltration, toll fraud)
- **Auto category detector** with confidence scores and manual override
- **Bytecode static analysis**: 17 Exodus-style tracker signatures, cleartext-HTTP/hardcoded-IP extraction, dynamic-code-loading and obfuscation signals, source-to-sink call-graph reachability
- **VirusTotal v3 threat intel** with offline hash database, persistent cache, and exponential backoff
- **Fusion scoring**: 50% contextual heuristics / 35% ML / 15% attack surface, with critical threat-intel override (98–100) and 5-level verdicts (Safe/Low/Medium/High/Critical)
- **SQLite audit history** with scan-to-scan differential comparisons
- **Reporting**: rich terminal output, Markdown audit reports, JSON export, Tkinter GUI with risk-gauge canvas

### Added — Machine Learning
- Schema-aware training loader for real Kaggle/Drebin/CIC datasets (short/full permission names, metadata and aggregate-column exclusion, label auto-detection, multi-CSV concat, duplicate-column OR-merging)
- **Trained on 4,464 real apps** (`Android_Malware_Benign.csv`, 2,533 malware / 1,931 benign, 213 permission features): Gradient Boosting selected via 5-fold stratified CV — accuracy 0.875, F1 0.891, ROC-AUC 0.954
- Per-prediction explainability (top contributing permissions), model comparison (Random Forest vs Gradient Boosting), exported evaluation charts
- `scripts/train_from_kaggle.py` one-command training with `--scan-only` schema reports

### Added — Packaging & Final Release (Phase 6)
- `scripts/release_check.py`: automated fresh-machine verification — clean venv → `pip install -r requirements.txt` + `pip install .[dev]` → console script, demo from an unrelated cwd (proves the wheel ships models/rules/data), web boot, GUI-toolkit caveat check, full test suite, demo-day smoke — 8/9 PASS (GUI skips without `python3-tk`, documented)
- Runtime data packaged with the wheel (`data` package + `package-data`): context rules, tracker signatures, empirical baselines, pretrained model all ship with `pip install .`
- `scripts/build_binary.sh`: one-file PyInstaller demo binary recipe with known gotchas encoded (androguard `pentest` package exclusion, sklearn pickles) and artifact smoke tests
- README Release & Packaging section: fresh-install steps (incl. the `python3-tk` system-package caveat), binary recipe, demo-day checklist

### Added — Web Dashboard (Phase 5)
- **FastAPI web dashboard** (`src/webapp.py`, `python main.py --web`): APK upload with category override, one-click demo scenarios, and a styled HTML report rendering the same sections as `report_generator` (score gauge, threat intel, context + empirical baselines, ML + provenance, static analysis, secrets, reachability, deep links, findings)
- Machine-readable `POST /api/analyze` + `GET /api/demo/{scenario}` JSON endpoints and OpenAPI explorer at `/api/docs`
- Upload hardening: same env-tunable size caps as the CLI, random temp filenames, automatic cleanup, friendly typed-error messages, HTML-escaping of all APK-derived strings (XSS-tested)
- `tests/test_webapp.py` (11 headless TestClient tests) + demo_check web boot check
- Web dependencies (`fastapi`, `uvicorn[standard]`, `python-multipart`) in `requirements.txt` and the optional `web` extra; `httpx` in dev extras

### Added — Analysis Depth (Phase 4)
- **Call-graph reachability fixed and deepened**: the xref lookup read `get_xref_to()` (callees — always empty for framework APIs) instead of `get_xref_from()` (callers), silently disabling reachability on every real APK; fixed, and analysis now also finds **inter-method paths** — source in one method, sink in another, linked by a real call edge (1-hop), ranked with intra-method (High) and intra-class (Medium) paths, capped at 25
- **Hardcoded secret detection**: AWS access keys, Google API keys, JWTs, embedded private-key blocks, and generic credential assignments in the DEX string pool — samples are **redacted in all outputs**, full values never leave the detector
- **Deep-link attack-surface parsing**: exported components now carry intent-filter actions/categories/data, registered deep links (`scheme://host`), BROWSABLE flags, and an unprotected-BROWSABLE count surfaced in reports and CLI
- **Tracker catalog expanded 17 → 31** real Exodus-style signatures (Amplitude, Countly, MoEngage, CleverTap, Kochava, Singular, Tenjin, Tapjoy, StartApp, Pangle, Yandex AppMetrica, OneSignal, Airship, Matomo)
- **Model provenance** (HANDOFF #7): model payload records dataset filenames + SHA-256, sample/class counts, feature count, scikit-learn version, and training timestamp — rendered in reports (Model Provenance) and CLI
- Report/CLI sections for secrets, reachability path types (with caller chains), deep-link surface, and provenance
- `tests/test_analysis_depth.py` (22 tests) incl. a real-APK regression test that the xref direction finds callers

### Added — Context Intelligence (Phase 3)
- **Empirical category baselines** (`data/empirical_baselines.json`, derived by `scripts/derive_empirical_baselines.py` from 200 real-world apps × 28 store categories): per-category permission request frequencies injected into every context result as `empirical_context` — rare permissions get notes like *"READ_SMS is requested by only 12% of real-world Flashlight apps (2/16)"*. Informational enrichment only: golden tests prove byte-identical scores with/without the data
- **Data-driven context exemptions** (`exempt_categories` in `data/context_rules.json`): combinations that are expected functionality for a category (camera+internet in Camera/Photo, location+internet in Navigation, SMS+internet in Messaging, media access in Music/Video) are reported under *"Expected Functionality Combinations"* but not penalized — same permissions, different verdicts by category, verified in `reports/calibration.md`
- **ML decision-threshold calibration**: out-of-fold max-F1 threshold (0.45 on the real corpus, F1 0.892 / recall 0.921) computed during training, baked into the model payload, and consumed by `predict_risk` for `predicted_class`/`ml_verdict`
- **Known-app catalog** for the category detector (brand names like WhatsApp/Spotify/AliExpress carry no descriptive keywords; longest-token-match wins, e.g. "Amazon Alexa" ≠ "Amazon") plus expanded sports/browser/radio keyword sets — detector accuracy on real app listings **36.7% → 94.6%** (139/147, `reports/calibration.md`)
- `scripts/calibrate.py` → `reports/calibration.md`: threshold calibration tables, risk-archetype ladder (benign → moderate → exfiltration-heavy → malware-like, strictly separated), context-awareness proofs, detector accuracy
- Report/CLI enrichment: real-world baseline column in the suspicious-permissions table, empirical notes in terminal output, exemptions section in Markdown reports
- `tests/test_context_intelligence.py` (27 tests) covering baseline invariance, exemptions, threshold plumbing, brand catalog, and report rendering

### Security & Robustness
- **Untrusted-input hardening**: zip-bomb guards (size/entry-count/uncompressed-total/compression-ratio caps validated on the zip central directory with zero extraction), hard parse time budgets via daemon threads, typed errors (`APKTooLargeError`, `APKSecurityError`, `APKParseTimeoutError`)
- All limits env-tunable (`CAPRA_*` variables, documented in `.env.example`)
- GUI thread-safety: worker threads never touch Tk widgets (queue + main-thread poller), busy-state guards, friendly error dialogs
- Clean machine-readable CLI: `--json` emits pure JSON (logs to stderr)

### Quality
- 117-test regression suite: per-module test files, golden behavior tests (`tests/test_golden.py`), malformed-archive edge-case corpus (`tests/test_edge_cases.py`)
- `scripts/demo_check.py` demo-day smoke checklist (12 end-to-end checks)
- Coverage gate in CI (≥75%, currently 81% excluding GUI), GitHub Actions on Python 3.9–3.12 under xvfb
- Ruff lint + format configuration, pre-commit hooks

### Changed (vs v1)
- Categories expanded from 3 → 13; scoring moved from single heuristic to multi-signal fusion
- ML moved from synthetic-only toy to real-dataset training with honest reporting (small samples are explicitly labelled `ILLUSTRATIVE ONLY`)
- Model artifact renamed `rf_permission_model.joblib` → `permission_model.joblib` (stores the CV-selected winner)

### Removed
- Unused web dependencies (`fastapi`, `uvicorn`, `python-multipart`, `reportlab`) — no web dashboard in scope
- Owner-name strings from user-facing output and generated reports (attribution lives in the README)

## [1.0.0]
- Initial prototype: 3-category permission heuristics, single-split ML, console-only reporting.
