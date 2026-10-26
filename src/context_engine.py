"""Context Engine Module.

Evaluates an application's declared permissions against category-specific
baselines and detects dangerous permission combinations (exfiltration vectors).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_RULES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "context_rules.json")
)
DEFAULT_EMPIRICAL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "empirical_baselines.json")
)


class ContextRuleError(Exception):
    """Raised when rules cannot be loaded or an invalid category is provided."""


CATEGORY_ALIASES: Dict[str, str] = {
    "calc": "Calculator",
    "math": "Calculator",
    "torch": "Flashlight",
    "nav": "Navigation",
    "maps": "Navigation",
    "map": "Navigation",
    "gps": "Navigation",
    "social": "Social Media",
    "social_media": "Social Media",
    "chat": "Messaging",
    "messenger": "Messaging",
    "im": "Messaging",
    "finance": "Banking/Finance",
    "banking": "Banking/Finance",
    "bank": "Banking/Finance",
    "fintech": "Banking/Finance",
    "health": "Health/Fitness",
    "fitness": "Health/Fitness",
    "workout": "Health/Fitness",
    "game": "Games",
    "gaming": "Games",
    "photo": "Camera/Photo",
    "camera": "Camera/Photo",
    "photography": "Camera/Photo",
    "music": "Music/Video",
    "video": "Music/Video",
    "audio": "Music/Video",
    "ecommerce": "Shopping",
    "e-commerce": "Shopping",
    "retail": "Shopping",
    "office": "Productivity",
    "notes": "Productivity",
    "learning": "Education",
    "study": "Education",
}


class ContextEngine:
    """Evaluator that applies contextual permission baselines and combination heuristics."""

    def __init__(
        self,
        rules_path: Optional[str] = None,
        empirical_path: Optional[str] = None,
    ):
        """Initialize the context engine with a rule configuration file.

        Args:
            rules_path: Path to context_rules.json. If None, defaults to data/context_rules.json.
            empirical_path: Path to empirical_baselines.json (real-world per-category
                permission frequencies). If None, defaults to data/empirical_baselines.json
                when present; empirical enrichment is optional and degrades gracefully.
        """
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self.rules = self._load_rules()
        self.categories: Dict[str, Any] = self.rules.get("categories", {})
        self.dangerous_combinations: List[Dict[str, Any]] = self.rules.get(
            "dangerous_combinations", []
        )
        self.aosp_dangerous: Set[str] = set(self.rules.get("aosp_dangerous_permissions", []))
        self.weights: Dict[str, Any] = self.rules.get(
            "scoring_weights",
            {
                "default_suspicious_penalty": 20,
                "unlisted_dangerous_penalty": 15,
                "exported_component_penalty": 3,
                "max_raw_score_ceiling": 160,
            },
        )
        self.empirical: Optional[Dict[str, Any]] = self._load_empirical(
            empirical_path or DEFAULT_EMPIRICAL_PATH
        )
        self._empirical_index = self._build_empirical_index()

    def _load_empirical(self, path: str) -> Optional[Dict[str, Any]]:
        """Load empirical baselines if available; enrichment is optional."""
        if not os.path.exists(path):
            logger.info("No empirical baselines found at %s (enrichment disabled).", path)
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if "frequencies" in data and "category_map" in data:
                return data
            logger.warning("Empirical baselines at %s have an unknown schema; ignoring.", path)
            return None
        except Exception as e:
            logger.warning("Could not load empirical baselines from %s (%s).", path, e)
            return None

    def _build_empirical_index(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Aggregate store-category frequencies onto canonical CAPRA categories.

        Frequencies from multiple store categories (e.g. 'Music & Audio' +
        'Video Players & Editors' -> Music/Video) are merged by summed counts.
        """
        if not self.empirical:
            return {}
        index: Dict[str, Dict[str, Dict[str, Any]]] = {}
        freq_by_store = self.empirical.get("frequencies", {})
        for canonical, store_cats in self.empirical.get("category_map", {}).items():
            merged: Dict[str, Dict[str, Any]] = {}
            used_stores = []
            total_n = 0
            for store in store_cats:
                store_freqs = freq_by_store.get(store)
                if not store_freqs:
                    continue
                used_stores.append(store)
                n_store = int(self.empirical.get("sample_sizes", {}).get(store, 0))
                total_n += n_store
                for perm, stats in store_freqs.items():
                    entry = merged.setdefault(perm, {"count": 0, "n": 0})
                    entry["count"] += int(stats.get("count", 0))
                    entry["n"] += int(stats.get("n", 0))
            for _perm, entry in merged.items():
                entry["frequency"] = round(entry["count"] / entry["n"], 4) if entry["n"] else 0.0
                entry["store_categories"] = used_stores
            index[canonical] = merged
            index.setdefault("__meta__", {})
            index["__meta__"][canonical] = {
                "sample_size": total_n,
                "store_categories": used_stores,
            }
        return index

    def get_empirical_stats(self, category: str, permission: str) -> Optional[Dict[str, Any]]:
        """Return real-world request statistics for a permission in a category.

        Returns:
            {'frequency', 'count', 'n', 'store_categories'} or None when no
            empirical data covers this category/permission.
        """
        if not self._empirical_index:
            return None
        try:
            canonical = self.resolve_category(category)
        except ContextRuleError:
            return None
        stats = self._empirical_index.get(canonical, {}).get(permission)
        if not stats:
            short = permission.replace("android.permission.", "")
            stats = self._empirical_index.get(canonical, {}).get(f"android.permission.{short}")
        return dict(stats) if stats else None

    def _empirical_note(self, category: str, permission: str) -> Optional[str]:
        """Build a human-readable real-world-norm note for a permission."""
        stats = self.get_empirical_stats(category, permission)
        if not stats or stats.get("n", 0) <= 0:
            return None
        pct = stats["frequency"] * 100
        short = permission.replace("android.permission.", "")
        ratio = f"{stats['count']}/{stats['n']}"
        if stats["frequency"] < 0.10:
            return (
                f"Empirical norm: only {pct:.0f}% of real-world {category} apps "
                f"request {short} ({ratio}) - rare for this category."
            )
        if stats["frequency"] >= 0.50:
            return (
                f"Empirical norm: common for {category} apps - {pct:.0f}% request "
                f"{short} ({ratio})."
            )
        return f"Empirical norm: requested by {pct:.0f}% of real-world {category} apps ({ratio})."

    def _load_rules(self) -> Dict[str, Any]:
        """Load and parse JSON rules configuration."""
        if not os.path.exists(self.rules_path):
            raise ContextRuleError(f"Context rules file not found at: {self.rules_path}")

        try:
            with open(self.rules_path, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ContextRuleError(f"Malformed JSON in context rules file: {e}") from e
        except Exception as e:
            raise ContextRuleError(f"Failed to load context rules: {e}") from e

    def get_supported_categories(self) -> List[str]:
        """Return list of canonical supported app categories."""
        return list(self.categories.keys())

    def resolve_category(self, user_category: str) -> str:
        """Resolve case-insensitive category string or alias to its canonical key."""
        cleaned = user_category.strip().lower()
        # Direct canonical match
        for cat in self.categories:
            if cat.lower() == cleaned:
                return cat

        # Known alias match
        if cleaned in CATEGORY_ALIASES:
            aliased = CATEGORY_ALIASES[cleaned]
            if aliased in self.categories:
                return aliased

        supported = ", ".join(self.categories.keys())
        raise ContextRuleError(
            f"Unsupported category '{user_category}'. Supported categories are: {supported}"
        )

    def evaluate_permissions(
        self,
        requested_permissions: List[str],
        category: str,
        exported_components_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze permissions in context of the app category and detect risky combinations.

        Args:
            requested_permissions: List of permissions declared by the APK.
            category: Target application category (e.g. 'Calculator').
            exported_components_info: Optional component export metrics from extractor.

        Returns:
            Dictionary containing categorized permissions, triggered combinations,
            and calculated heuristic penalties.
        """
        canonical_category = self.resolve_category(category)
        cat_rule = self.categories[canonical_category]

        acceptable_set = set(cat_rule.get("acceptable_permissions", []))
        suspicious_rules = cat_rule.get("suspicious_permissions", {})
        requested_set = set(requested_permissions)

        acceptable: List[Dict[str, str]] = []
        suspicious: List[Dict[str, Any]] = []
        unexpected_dangerous: List[Dict[str, Any]] = []
        neutral: List[str] = []

        mismatch_penalty = 0

        # Classify each requested permission
        for perm in requested_permissions:
            if perm in acceptable_set:
                acceptable.append(
                    {
                        "permission": perm,
                        "status": "Acceptable",
                        "description": "Standard baseline permission for this category.",
                    }
                )
            elif perm in suspicious_rules:
                detail = suspicious_rules[perm]
                penalty = detail.get("penalty", self.weights.get("default_suspicious_penalty", 20))
                reason = detail.get("reason", "Suspicious for this category.")
                entry = {
                    "permission": perm,
                    "penalty": penalty,
                    "reason": reason,
                }
                emp_stats = self.get_empirical_stats(canonical_category, perm)
                if emp_stats:
                    entry["empirical"] = emp_stats
                    entry["empirical_note"] = self._empirical_note(canonical_category, perm)
                suspicious.append(entry)
                mismatch_penalty += penalty
            elif perm in self.aosp_dangerous:
                # Unlisted runtime dangerous permission
                penalty = self.weights.get("unlisted_dangerous_penalty", 15)
                entry = {
                    "permission": perm,
                    "penalty": penalty,
                    "reason": "Dangerous AOSP runtime permission not standard for this category.",
                }
                emp_stats = self.get_empirical_stats(canonical_category, perm)
                if emp_stats:
                    entry["empirical"] = emp_stats
                    entry["empirical_note"] = self._empirical_note(canonical_category, perm)
                unexpected_dangerous.append(entry)
                mismatch_penalty += penalty
            else:
                neutral.append(perm)

        # Detect dangerous combinations (Collusion / Exfiltration)
        combination_penalty = 0
        triggered_combinations: List[Dict[str, Any]] = []
        contextual_exemptions: List[Dict[str, Any]] = []

        for comb in self.dangerous_combinations:
            comb_perms = set(comb.get("permissions", []))
            if comb_perms.issubset(requested_set):
                # Context-aware suppression (issue #11): combos may declare categories where
                # the combination is expected functionality (Navigation + location, Camera
                # apps + camera/sharing). Reported, but NOT penalized there.
                is_contextually_exempt = canonical_category in (comb.get("exempt_categories") or [])

                if is_contextually_exempt:
                    contextual_exemptions.append(
                        {
                            "id": comb.get("id"),
                            "name": comb.get("name"),
                            "risk_type": comb.get("risk_type"),
                            "penalty": 0,
                            "description": comb.get("description"),
                            "matched_permissions": list(comb_perms),
                            "exempt_reason": (
                                f"Expected functionality for category '{canonical_category}' "
                                f"(declared in exempt_categories); reported without penalty."
                            ),
                        }
                    )
                else:
                    penalty = comb.get("penalty", 30)
                    combination_penalty += penalty
                    triggered_combinations.append(
                        {
                            "id": comb.get("id"),
                            "name": comb.get("name"),
                            "risk_type": comb.get("risk_type"),
                            "penalty": penalty,
                            "description": comb.get("description"),
                            "matched_permissions": list(comb_perms),
                        }
                    )

        # Calculate exported component exposure penalty
        exported_penalty = 0
        unprotected_count = 0
        if exported_components_info:
            unprotected_count = exported_components_info.get("unprotected_exported", 0)
            comp_weight = self.weights.get("exported_component_penalty", 3)
            # Cap component exposure penalty at 30 points
            exported_penalty = min(unprotected_count * comp_weight, 30)

        total_raw_penalty = mismatch_penalty + combination_penalty + exported_penalty

        # Empirical category norms (informational enrichment, no scoring impact)
        meta = (self._empirical_index or {}).get("__meta__", {}).get(canonical_category, {})
        category_norm_notes: List[str] = []
        if meta:
            rarity_candidates = []
            for perm in requested_set:
                emp_stats = self.get_empirical_stats(canonical_category, perm)
                if emp_stats and emp_stats.get("n", 0) > 0:
                    rarity_candidates.append((emp_stats["frequency"], perm, emp_stats))
            rarity_candidates.sort(key=lambda x: x[0])
            for freq, perm, emp_stats in rarity_candidates[:5]:
                if freq < 0.25:
                    short = perm.replace("android.permission.", "")
                    category_norm_notes.append(
                        f"{short} is requested by only {freq * 100:.0f}% of real-world "
                        f"{canonical_category} apps ({emp_stats['count']}/{emp_stats['n']})."
                    )

        empirical_context = {
            "available": bool(meta),
            "sample_size": meta.get("sample_size", 0),
            "store_categories": meta.get("store_categories", []),
            "category_norm_notes": category_norm_notes,
        }

        return {
            "category": canonical_category,
            "category_description": cat_rule.get("description", ""),
            "total_requested": len(requested_permissions),
            "empirical_context": empirical_context,
            "breakdown": {
                "acceptable_count": len(acceptable),
                "suspicious_count": len(suspicious),
                "unexpected_dangerous_count": len(unexpected_dangerous),
                "neutral_count": len(neutral),
                "combinations_triggered_count": len(triggered_combinations),
            },
            "acceptable_permissions": acceptable,
            "suspicious_permissions": suspicious,
            "unexpected_dangerous_permissions": unexpected_dangerous,
            "neutral_permissions": neutral,
            "triggered_combinations": triggered_combinations,
            "contextual_exemptions": contextual_exemptions,
            "penalties": {
                "mismatch_penalty": mismatch_penalty,
                "combination_penalty": combination_penalty,
                "exported_component_penalty": exported_penalty,
                "total_raw_penalty": total_raw_penalty,
            },
            "scoring_weights": self.weights,
        }
