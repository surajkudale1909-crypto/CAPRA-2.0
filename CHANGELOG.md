# Changelog

All notable changes to CAPRA (Context-Aware Mobile App Privacy Risk Analyzer) are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/).

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
