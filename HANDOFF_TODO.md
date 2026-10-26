# CAPRA 2.0 — Handoff Backlog (Remaining Work)

Items below were **not** fixed in the 2026-10-26 review pass (quick wins are already done).
Each item is scoped so it can be picked up independently. Priority: P1 = before final submission, P2 = nice-to-have, P3 = future scope.

---

## P1 — Must do before submission/evaluation

### 1. Replace the toy ML dataset with a real one
**Why:** `data/datasets/sample_android_malware_dataset.csv` has 60 hand-built rows. The loader now labels it `SMALL SAMPLE ... ILLUSTRATIVE ONLY`, and `reports/` metrics (AUC 1.0) are mechanically correct but scientifically meaningless. This is the #1 thing an examiner will challenge.
**What:**
- Obtain a real labelled dataset: **Drebin-215** (request access from TU Braunschweig), **CIC-AndMal2017** (UNB website), or a Kaggle Android malware permissions dataset.
- Convert to the loader's expected format: one row per app, columns = the 32 permissions in `FEATURE_PERMISSIONS` (short names like `INTERNET` or full `android.permission.*` both work), plus a label column named `class` with `1/malware` and `0/benign`.
- Drop the CSV into `data/datasets/` and retrain: `python -c "from src.ml_pipeline import PermissionMLPipeline; PermissionMLPipeline(force_retrain=True)"`.
- Verify the "SMALL SAMPLE" warning no longer appears, then regenerate `reports/` and update any README numbers with the real metrics.

### 2. Harden APK parsing against malicious input
**Why:** the tool's *purpose* is to open untrusted, possibly hostile APKs. `src/extractor.py` currently feeds any file to Androguard/zip parsing with no limits.
**What:**
- Enforce a max file size (e.g. 200 MB) before parsing.
- Guard against zip bombs: limit total uncompressed size and entry count when the zip is inspected.
- Wrap analysis in a timeout (Androguard can choke on pathological DEX); return `APKCorruptedError` on timeout.
- Add tests for: oversized file, zip bomb (high compression ratio), truncated DEX, zero-byte file.

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
- `src/gui.py` runs `_execute_analysis` in a thread against the global pipeline singleton (`get_default_pipeline`). `FusionEngine.fuse()` no longer mutates shared state (fixed), but `PrivacyAnalysisPipeline` instances should ideally be created per analysis, or guarded with a lock.
- Also: surface exceptions in the GUI status bar instead of swallowing them in the worker thread.

### 7. Model provenance
- When saving `permission_model.joblib`, record in the payload: dataset filename + SHA-256, n_samples, class balance, scikit-learn version, training date.
- Lets a reviewer verify which data produced which model, and invalidates stale models when data changes.

### 8. Golden regression tests for risk scores
- For each APK in `data/apks/`, assert expected package name, detected category, and a score *range* (not exact score — fusion weights may be tuned).
- Protects against silent scoring regressions when rules change.

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
