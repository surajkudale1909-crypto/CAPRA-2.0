#!/usr/bin/env python
"""Derive empirical per-category permission baselines from real-world app data.

Reads the real permission dump (data/datasets/Extracted_permssion_updated.csv:
200 Play Store apps x 138 permissions x 28 store categories) and produces
data/empirical_baselines.json, which the ContextEngine uses to answer:
  "how common is this permission for apps of this category in the real world?"

Usage:
    python scripts/derive_empirical_baselines.py
"""

from __future__ import annotations

import json
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd

from src.ml_pipeline import normalize_permission_column

SOURCE_CSV = os.path.join(ROOT_DIR, "data", "datasets", "Extracted_permssion_updated.csv")
OUTPUT_JSON = os.path.join(ROOT_DIR, "data", "empirical_baselines.json")

#: Canonical CAPRA category -> Play Store categories used as its empirical proxy.
#: Categories without a sensible store counterpart simply have no empirical data.
CATEGORY_MAP = {
    "Calculator": ["Tools"],
    "Flashlight": ["Tools"],
    "Navigation": ["Maps & Navigation"],
    "Social Media": ["Social Media", "Dating"],
    "Messaging": ["Communications"],
    "Banking/Finance": ["Finance"],
    "Health/Fitness": ["Sports", "Medical/Healthcare"],
    "Games": ["Games"],
    "Camera/Photo": ["Photography Apps"],
    "Music/Video": ["Music & Audio", "Video Players & Editors"],
    "Shopping": ["Shopping"],
    "Productivity": ["Productivity", "Business", "Tools"],
    "Education": ["Education", "Books & Reference", "Comics"],
}


def derive(source_csv: str = SOURCE_CSV) -> dict:
    """Compute per-store-category permission frequencies from the raw dump."""
    df = pd.read_csv(source_csv)

    # The category column has trailing spaces in the source data ("Communications ")
    cat_col = [c for c in df.columns if c.strip().lower() == "app categore"][0]
    df["_cat"] = df[cat_col].astype(str).str.strip()

    perm_cols = {}
    for col in df.columns:
        norm = normalize_permission_column(col)
        if norm is not None:
            perm_cols.setdefault(norm, []).append(col)

    frequencies: dict = {}
    sample_sizes: dict = {}
    for cat, group in df.groupby("_cat"):
        sample_sizes[cat] = int(len(group))
        freqs = {}
        for norm, cols in perm_cols.items():
            combined = (group[cols].apply(pd.to_numeric, errors="coerce").fillna(0) > 0).any(axis=1)
            count = int(combined.sum())
            if count > 0:
                freqs[norm] = {
                    "count": count,
                    "n": int(len(group)),
                    "frequency": round(count / len(group), 4),
                }
        frequencies[cat] = freqs

    return {
        "metadata": {
            "source_file": os.path.relpath(source_csv, ROOT_DIR),
            "n_apps": int(len(df)),
            "n_store_categories": int(df["_cat"].nunique()),
            "n_permission_features": len(perm_cols),
            "description": (
                "Empirical permission request frequencies per Play Store category, "
                "derived from real-world app listings. Used by the ContextEngine to "
                "contextualize rule-based findings against real category norms."
            ),
        },
        "category_map": CATEGORY_MAP,
        "sample_sizes": sample_sizes,
        "frequencies": frequencies,
    }


def main() -> None:
    if not os.path.exists(SOURCE_CSV):
        print(f"Source CSV not found: {SOURCE_CSV}")
        sys.exit(1)

    payload = derive()
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1, sort_keys=False)

    meta = payload["metadata"]
    print(f"Wrote {OUTPUT_JSON}")
    print(
        f"  Apps: {meta['n_apps']}  Store categories: {meta['n_store_categories']}  "
        f"Permission features: {meta['n_permission_features']}"
    )
    for canonical, store_cats in CATEGORY_MAP.items():
        n = sum(payload["sample_sizes"].get(c, 0) for c in store_cats)
        print(f"  {canonical:<16} <- {', '.join(store_cats)}  (n={n})")


if __name__ == "__main__":
    main()
