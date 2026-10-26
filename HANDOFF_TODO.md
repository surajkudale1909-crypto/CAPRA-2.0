# CAPRA 2.0 — Handoff Backlog (Remaining Work)

Items below were **not** fixed in the 2026-10-26 review pass (quick wins are already done).
Each item is scoped so it can be picked up independently. Priority: P1 = before final submission, P2 = nice-to-have, P3 = future scope.

---

## P1 — Must do before submission/evaluation

### 1. Replace the toy ML dataset with a real one
**Status (2026-10-26): ✅ DONE.** Trained on `data/datasets/Android_Malware_Benign.csv` (Kaggle): 4,464 apps (2,533 malware / 1,931 benign), 213 permission features after short/full-name deduplication. Gradient Boosting selected by 5-fold CV: accuracy 0.875, F1 0.891, ROC-AUC 0.954. The bundled 60-row toy CSV is auto-ignored when real labelled data is present. `scripts/train_from_kaggle.py` retrains/regenerates all reports in one command.
**Remaining optional stretch:**
- Merge additional labelled sources (Drebin-215, CIC-AndMal2017) via `python scripts/train_from_kaggle.py` (multi-CSV concat is supported) to broaden coverage.
- Use `Extracted_permssion_updated.csv` (200 apps with Play Store categories × 138 permissions) to derive empirical per-category permission baselines for `data/context_rules.json`.

### 2. Harden APK parsing against malicious input
**Status (2026-10-26): ✅ DONE.** `src/extractor.py` now validates every archive against size/entry-count/uncompressed-total/compression-ratio caps (zip-bomb guards on the central directory, zero extraction) and runs manifest parsing + the DEX static stage under daemon-thread time budgets. Typed errors (`APKTooLargeError`, `APKSecurityError`, `APKParseTimeoutError`) with clean CLI messages. All limits are env-tunable (`CAPRA_*` vars documented in `.env.example`). 11 new tests cover bombs, caps, and timeouts.
**Remaining optional stretch:**
- Deep header-vs-payload verification (detect forged zip central directories) — Androguard already fails these; the current declared-size caps cover standard bombs.

### 3. Decide the fate of the web dashboard
**Why:** `fastapi`, `uvicorn`, `python-multipart`, `reportlab` were removed from `requirements.txt` (Dec 2026 review) because no code used them. Either earn them back or leave them out.
**Option A (recommended):** skip the web dashboard entirely — the Tkinter GUI + Markdown/JSON reports already satisfy the synopsis.
**Option B:** build it — minimal FastAPI app with an upload form calling `src.pipeline.analyze_apk`, render the same sections as `report_generator`. Re-add the four deps when the code exists.

---

## P2 — Quality improvements

### 4. Split `tests/test_pipeline.py` and gate on coverage
- One file per module: `tests/test_extractor.py`, `tests/test_context_engine.py`, `tests/test_ml_pipeline.py`, etc.
- Add `[tool.coverage.run]` to `pyproject.toml` and a CI step `pytest --cov=src --cov-fail-under=70`.
- Reduce reliance on `if os.path.exists(...)` conditional skips (they silently shrink coverage) — commit 2–3 small real APKs to `data/apks/` as a regression corpus and make those tests unconditional.

### 5. Lint & format the codebase
- Add Ruff (replaces flake8/isort/black): `pip install ruff`, add to `pyproject.toml`:
  ```toml
  [tool.ruff]
  line-length = 100
  target-version = "py39"
  ```
- Run `ruff check . --fix` and `ruff format .`, fix remaining violations, add a `.github/workflows/ci.yml` lint job.
- Optional: pre-commit hooks (`.pre-commit-config.yaml`) so the 4-person team stays consistent.

### 6. GUI thread-safety
**Status (2026-10-26): ✅ DONE (Phase 1).** Worker threads never touch Tk widgets — results/errors flow through a `queue.Queue` drained by a main-thread poller. Busy-state guards prevent concurrent scans; errors surface via friendly dialogs (`friendly_error_message` in `src/extractor.py`, unit-tested headless); the analyze button shows progress state; UI render failures can't kill the poller.

### 7. Model provenance
- When saving `permission_model.joblib`, record in the payload: dataset filename + SHA-256, n_samples, class balance, scikit-learn version, training date.
- Lets a reviewer verify which data produced which model, and invalidates stale models when data changes.

### 8. Golden regression tests for risk scores
**Status (2026-10-26): ✅ DONE (Phase 1).** `tests/test_golden.py` pins verified behavior with invariants/ranges (sample APK → Safe, spyware demo → Critical ≥ 90, navigation location exemption, fusion verdict boundaries, threat override ≥ 98, determinism). `tests/test_edge_cases.py` covers the malformed-archive corpus (empty/garbage/truncated/no-manifest/text-manifest). `scripts/demo_check.py` is the demo-day PASS/FAIL smoke checklist (caught a real `--json` stdout-pollution bug on first run, now fixed via stderr logging).

---

## P3 — Future scope / final-semester stretch goals

### 9. Dynamic-analysis comparison (future work section)
- The synopsis references FlowDroid/SweetDroid papers in `DOCX/`. A small experiment comparing CAPRA's static reachability verdicts against FlowDroid on 3–5 APKs would make a strong evaluation chapter — even if CAPRA loses on some cases, the honest comparison scores points.

### 10. Packaging for demo day
- PyInstaller one-file build: `pyinstaller --onefile --name capra main.py` (GUI: `--windowed`). Avoids "install Python + deps" friction during live demos. Test on the exact lab machine first.

### 11. Documentation polish
- Screenshots of the GUI (risk gauge, tabs) in the README.
- `CHANGELOG.md` with v1 → v2 deltas.
- Align final project report/presentation claims with the honest ML wording now used in the README.

---

## Done in the 2026-10-26 review pass (for reference)

- Real-dataset training tooling: schema-aware `load_dataset` (Kaggle/Drebin/CIC CSVs, label auto-detection, dynamic permission vocabulary, multi-CSV concat, toy-dataset auto-replacement) + `scripts/train_from_kaggle.py` with `--scan-only` schema reports. Model payload now records feature vocabulary, n_samples, and class balance; `perm_to_idx` rebuilt correctly on model load.

- Removed unused deps (`fastapi`, `uvicorn`, `python-multipart`, `reportlab`).
- README drift fixed: academic year (2026–27, Sem 3), category list (actual 13), clone URL, honest ML benchmark wording + validity note.
- `capra.egg-info/` untracked and gitignored.
- Positional APK arg (`python main.py app.apk`), `--vt-key` usage warning.
- Model renamed `rf_permission_model.joblib` → `permission_model.joblib` (it stores the GB winner).
- `FusionEngine.fuse()` no longer mutates shared `raw_ceiling` state.
- ML positive-class lookup hardened against label reordering (`classes_` index).
- Small-sample datasets (< 200 rows) labelled `ILLUSTRATIVE ONLY` with a training-time warning.
- Owner-name strings removed from terminal output and generated reports (attribution stays in README).
- GUI test now skips gracefully when tkinter/display is unavailable (suite is green headless).
- GitHub Actions CI added (`.github/workflows/ci.yml`, Python 3.9–3.12).
- `.env.example` added; `pyproject.toml` classifier downgraded to `4 - Beta`.
