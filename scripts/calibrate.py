#!/usr/bin/env python
"""CAPRA Calibration Study.

Produces reports/calibration.md with four evidence sections:
  1. ML decision-threshold calibration on out-of-fold predictions (real corpus)
  2. Risk-archetype separation + context-awareness checks of the fusion pipeline
  3. Category auto-detector accuracy against real-world app metadata
  4. Verdict-band documentation

Usage:
    python scripts/calibrate.py
"""

from __future__ import annotations

import json
import logging
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import numpy as np

logging.disable(logging.INFO)

from sklearn.model_selection import StratifiedKFold, cross_val_predict  # noqa: E402

from src.category_detector import detect_app_category  # noqa: E402
from src.context_engine import ContextEngine  # noqa: E402
from src.fusion_engine import FusionEngine  # noqa: E402
from src.ml_pipeline import (  # noqa: E402
    PermissionMLPipeline,
    _calibrate_decision_threshold,
    load_dataset,
    normalize_permission_column,
)

REPORT_PATH = os.path.join(ROOT_DIR, "reports", "calibration.md")
BASELINES_PATH = os.path.join(ROOT_DIR, "data", "empirical_baselines.json")
DATASET_CSV = os.path.join(ROOT_DIR, "data", "datasets", "Extracted_permssion_updated.csv")
TRAIN_CSV = os.path.join(ROOT_DIR, "data", "datasets", "Android_Malware_Benign.csv")

ARCHETYPES = [
    ("benign_minimal", "Benign utility (minimal)", ["android.permission.VIBRATE"]),
    (
        "benign_standard",
        "Benign utility (common background perms)",
        [
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK",
            "android.permission.INTERNET",
        ],
    ),
    (
        "moderate_suspicious",
        "Moderate risk (location + device ID + net)",
        [
            "android.permission.INTERNET",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_PHONE_STATE",
        ],
    ),
    (
        "exfiltration_heavy",
        "Exfiltration-heavy (SMS + contacts + storage + location)",
        [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
    ),
    (
        "malware_profile",
        "Malware-like (SMS interception + call log + overlay)",
        [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.CALL_PHONE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_PHONE_STATE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
    ),
]

# Same permission set, different app categories — the context-awareness thesis.
CONTEXT_CASES = [
    (
        "Camera/share stack (CAMERA + READ_MEDIA_IMAGES + INTERNET)",
        [
            "android.permission.CAMERA",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.INTERNET",
        ],
        ["Camera/Photo", "Music/Video", "Calculator", "Flashlight"],
    ),
    (
        "Location + internet (ACCESS_FINE_LOCATION + INTERNET)",
        ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
        ["Navigation", "Calculator", "Flashlight"],
    ),
    (
        "SMS + internet (READ_SMS + INTERNET)",
        ["android.permission.READ_SMS", "android.permission.INTERNET"],
        ["Messaging", "Flashlight", "Calculator"],
    ),
]


def _composite_score(fe, ml, ce, perms, category):
    ctx = ce.evaluate_permissions(perms, category=category)
    ml_res = ml.predict_risk(perms)
    manifest = {
        "target_sdk_version": 34,
        "components": {"exported": {"unprotected_exported": 0}},
    }
    fusion = fe.fuse(context_result=ctx, manifest_data=manifest, ml_data=ml_res)
    return fusion["score"], fusion["verdict"]


def section_ml_calibration(lines, pipeline):
    """Out-of-fold threshold calibration and score separation on the real corpus."""
    X, y, source_type, source_desc, features = load_dataset(TRAIN_CSV)
    model = pipeline.model

    # Same split strategy as training (StratifiedKFold, shuffle, seed 42) so the
    # threshold reproduced here matches the one baked into the saved model.
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    oof_probs = cross_val_predict(model, X, y, cv=cv, method="predict_proba")[:, 1]
    cal = _calibrate_decision_threshold(y, oof_probs)
    threshold = cal["decision_threshold"]

    lines.append("## 1. ML Decision-Threshold Calibration (out-of-fold)")
    lines.append("")
    lines.append(
        f"**Dataset:** {source_desc} — {len(X)} apps ({int(sum(y == 1))} malware / {int(sum(y == 0))} benign)"
    )
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| Selected decision threshold (max-F1) | **{threshold}** |")
    lines.append(f"| Precision at threshold | {cal['precision_at_threshold']} |")
    lines.append(f"| Recall at threshold | {cal['recall_at_threshold']} |")
    lines.append(f"| F1 at threshold | {cal['f1_at_threshold']} |")
    lines.append(f"| Youden's-J threshold (reference) | {cal['youden_threshold']} |")
    lines.append(f"| Threshold in deployed model payload | {pipeline.decision_threshold} |")
    lines.append("")
    lines.append("### Out-of-fold score distribution by class")
    lines.append("")
    lines.append("| Probability band | Malware apps | Benign apps |")
    lines.append("| :--- | :---: | :---: |")
    bands = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)]
    for lo, hi in bands:
        in_band = (oof_probs >= lo) & (oof_probs <= hi if hi == 1.0 else oof_probs < hi)
        m = int(np.sum((y == 1) & in_band))
        b = int(np.sum((y == 0) & in_band))
        lines.append(f"| {lo:.1f} – {hi:.1f} | {m} | {b} |")
    lines.append("")
    sep = float(np.mean(oof_probs[y == 1])) - float(np.mean(oof_probs[y == 0]))
    lines.append(
        f"**Class separation:** mean malware probability {np.mean(oof_probs[y == 1]):.3f} "
        f"vs mean benign probability {np.mean(oof_probs[y == 0]):.3f} (gap {sep:.3f})."
    )
    lines.append("")
    return cal


def section_archetype_separation(lines, pipeline):
    """Composite fusion scores for risk archetypes + context-awareness checks."""
    ce = ContextEngine()
    fe = FusionEngine()
    ml = pipeline
    categories = ce.get_supported_categories()

    # --- Part A: risk ladder across all categories ---
    rows = []
    for _key, label, perms in ARCHETYPES:
        scores = []
        verdicts = []
        for cat in categories:
            score, verdict = _composite_score(fe, ml, ce, perms, cat)
            scores.append(score)
            verdicts.append(verdict)
        rows.append((label, scores, verdicts))

    lines.append("## 2. Risk-Archetype Separation (full fusion pipeline)")
    lines.append("")
    lines.append(
        "Composite scores for each archetype evaluated across all "
        f"{len(categories)} categories (min / mean / max):"
    )
    lines.append("")
    lines.append("| Archetype | Min | Mean | Max | Dominant verdict |")
    lines.append("| :--- | :---: | :---: | :---: | :--- |")
    means = []
    for label, scores, verdicts in rows:
        mean_score = float(np.mean(scores))
        means.append(mean_score)
        dominant = max(set(verdicts), key=verdicts.count)
        lines.append(f"| {label} | {min(scores)} | {mean_score:.1f} | {max(scores)} | {dominant} |")
    lines.append("")
    # Risk-relevant property: every risk tier must score strictly above the tier
    # before it. Both benign archetypes share the Safe band and may differ by
    # sub-point rounding noise (ML-discount granularity), so they are checked
    # jointly against the moderate tier rather than against each other.
    monotonic = max(means[0], means[1]) < means[2] < means[3] < means[4]
    lines.append(
        f"**Risk-ladder separation:** "
        f"{'✅ INCREASING (benign < moderate < exfiltration-heavy < malware-like)' if monotonic else '⚠ violation detected'} "
        "(benign archetypes share the Safe band and are compared jointly)."
    )
    lines.append("")

    # --- Part B: context-awareness, same permissions across categories ---
    lines.append("### Context-awareness: same permissions, different categories")
    lines.append("")
    lines.append(
        "The thesis of CAPRA — identical permission sets must be judged against the "
        "app's declared function. Combinations that are *expected functionality* for a "
        "category (declared in `exempt_categories` of `data/context_rules.json`) are "
        "reported but not penalized:"
    )
    lines.append("")
    context_ok = True
    for label, perms, cats in CONTEXT_CASES:
        lines.append(f"**{label}**")
        lines.append("")
        lines.append("| Category | Score | Verdict |")
        lines.append("| :--- | :---: | :--- |")
        scores_by_cat = {}
        for cat in cats:
            score, verdict = _composite_score(fe, ml, ce, perms, cat)
            scores_by_cat[cat] = score
            marker = " *(expected functionality)*" if cat == cats[0] else ""
            lines.append(f"| {cat}{marker} | {score} | {verdict} |")
        lines.append("")
        # The first category is the functionally-correct one: it must score strictly
        # lower than the mismatched categories listed after it.
        if any(scores_by_cat[cats[0]] >= scores_by_cat[c] for c in cats[1:]):
            context_ok = False

    lines.append(
        "**Context check:** "
        + (
            "✅ functionally-correct categories score strictly lower than mismatched ones"
            if context_ok
            else "⚠ mismatch detected"
        )
    )
    lines.append("")
    return monotonic, context_ok


def section_detector_accuracy(lines):
    """Category auto-detector accuracy against real-world app listings."""
    import pandas as pd

    baselines = json.load(open(BASELINES_PATH, encoding="utf-8"))
    reverse_map = {}
    for canonical, store_cats in baselines["category_map"].items():
        for store in store_cats:
            reverse_map.setdefault(store, set()).add(canonical)

    df = pd.read_csv(DATASET_CSV)
    cat_col = [c for c in df.columns if c.strip().lower() == "app categore"][0]
    df["_cat"] = df[cat_col].astype(str).str.strip()

    perm_cols = [c for c in df.columns if normalize_permission_column(c)]

    total = 0
    correct = 0
    conf_correct = []
    conf_wrong = []
    fallback_wrong = 0
    for _, row in df.iterrows():
        expected_set = reverse_map.get(row["_cat"])
        if not expected_set:
            continue
        total += 1
        perms = [
            normalize_permission_column(c) for c in perm_cols if str(row[c]) not in ("0", "0.0")
        ]
        res = detect_app_category(
            package_name="",
            app_name=str(row["pkgname"]),
            declared_permissions=[p for p in perms if p],
        )
        hit = res.category in expected_set
        if hit:
            correct += 1
            conf_correct.append(res.confidence)
        else:
            conf_wrong.append(res.confidence)
            if res.method == "fallback_heuristic":
                fallback_wrong += 1

    acc = correct / total if total else 0.0
    lines.append("## 3. Category Auto-Detector Accuracy (real-world app names)")
    lines.append("")
    lines.append(
        f"Evaluated on the **{total} apps** in `Extracted_permssion_updated.csv` whose store "
        "category maps to a CAPRA category (accepted if the detector's answer is any "
        "canonical category that maps to the same store category)."
    )
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| Accuracy | **{acc * 100:.1f}%** ({correct}/{total}) |")
    if conf_correct:
        lines.append(f"| Mean confidence when correct | {np.mean(conf_correct):.2f} |")
    if conf_wrong:
        lines.append(f"| Mean confidence when wrong | {np.mean(conf_wrong):.2f} |")
        lines.append(
            f"| Wrong predictions that were low-confidence fallbacks | {fallback_wrong}/{len(conf_wrong)} |"
        )
    lines.append("")
    return acc


def section_verdict_thresholds(lines):
    """Document the verdict bands and their calibration basis."""
    lines.append("## 4. Verdict Bands")
    lines.append("")
    lines.append("| Score range | Verdict | Rationale |")
    lines.append("| :--- | :--- | :--- |")
    lines.append("| 0 – 20 | Safe | Benign archetypes score below this band across categories |")
    lines.append("| 21 – 45 | Low | Mild context mismatches without exfiltration combos |")
    lines.append("| 46 – 70 | Medium | Suspicious mismatches and/or single exfil combos |")
    lines.append("| 71 – 89 | High | Multiple exfil combos or strong ML+static agreement |")
    lines.append("| 90 – 100 | Critical | Threat-intel match or extreme multi-signal evidence |")
    lines.append("")
    lines.append(
        "Bands are held constant by golden regression tests (`tests/test_golden.py`); "
        "any recalibration must re-verify the demo scenarios in the same commit."
    )
    lines.append("")


def main() -> None:
    lines = [
        "# CAPRA Calibration Report",
        "",
        "Generated by `scripts/calibrate.py`. Documents how ML thresholds, fusion scores,",
        "and category detection were calibrated against real-world data.",
        "",
    ]
    pipeline = PermissionMLPipeline()

    print("Running ML threshold calibration (5-fold out-of-fold predictions)...")
    cal = section_ml_calibration(lines, pipeline)
    print(f"  threshold={cal['decision_threshold']}  f1={cal['f1_at_threshold']}")

    print("Running risk-archetype separation...")
    mono, ctx_ok = section_archetype_separation(lines, pipeline)
    print(f"  monotonic={mono}  context_check={ctx_ok}")

    print("Running category detector evaluation...")
    acc = section_detector_accuracy(lines)
    print(f"  accuracy={acc * 100:.1f}%")

    section_verdict_thresholds(lines)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
