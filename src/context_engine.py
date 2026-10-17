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

    def __init__(self, rules_path: Optional[str] = None):
        """Initialize the context engine with a rule configuration file.

        Args:
            rules_path: Path to context_rules.json. If None, defaults to data/context_rules.json.
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

    def _load_rules(self) -> Dict[str, Any]:
        """Load and parse JSON rules configuration."""
        if not os.path.exists(self.rules_path):
            raise ContextRuleError(f"Context rules file not found at: {self.rules_path}")

        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
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
                acceptable.append({
                    "permission": perm,
                    "status": "Acceptable",
                    "description": "Standard baseline permission for this category.",
                })
            elif perm in suspicious_rules:
                detail = suspicious_rules[perm]
                penalty = detail.get("penalty", self.weights.get("default_suspicious_penalty", 20))
                reason = detail.get("reason", "Suspicious for this category.")
                suspicious.append({
                    "permission": perm,
                    "penalty": penalty,
                    "reason": reason,
                })
                mismatch_penalty += penalty
            elif perm in self.aosp_dangerous:
                # Unlisted runtime dangerous permission
                penalty = self.weights.get("unlisted_dangerous_penalty", 15)
                unexpected_dangerous.append({
                    "permission": perm,
                    "penalty": penalty,
                    "reason": "Dangerous AOSP runtime permission not standard for this category.",
                })
                mismatch_penalty += penalty
            else:
                neutral.append(perm)

        # Detect dangerous combinations (Collusion / Exfiltration)
        combination_penalty = 0
        triggered_combinations: List[Dict[str, Any]] = []

        for comb in self.dangerous_combinations:
            comb_perms = set(comb.get("permissions", []))
            if comb_perms.issubset(requested_set):
                # Context-aware suppression:
                # If Navigation app has Location + Internet, this is expected behavior.
                is_contextually_exempt = (
                    comb.get("id") == "COMB_LOCATION_TRACKING"
                    and canonical_category == "Navigation"
                )

                if not is_contextually_exempt:
                    penalty = comb.get("penalty", 30)
                    combination_penalty += penalty
                    triggered_combinations.append({
                        "id": comb.get("id"),
                        "name": comb.get("name"),
                        "risk_type": comb.get("risk_type"),
                        "penalty": penalty,
                        "description": comb.get("description"),
                        "matched_permissions": list(comb_perms),
                    })

        # Calculate exported component exposure penalty
        exported_penalty = 0
        unprotected_count = 0
        if exported_components_info:
            unprotected_count = exported_components_info.get("unprotected_exported", 0)
            comp_weight = self.weights.get("exported_component_penalty", 3)
            # Cap component exposure penalty at 30 points
            exported_penalty = min(unprotected_count * comp_weight, 30)

        total_raw_penalty = mismatch_penalty + combination_penalty + exported_penalty

        return {
            "category": canonical_category,
            "category_description": cat_rule.get("description", ""),
            "total_requested": len(requested_permissions),
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
            "penalties": {
                "mismatch_penalty": mismatch_penalty,
                "combination_penalty": combination_penalty,
                "exported_component_penalty": exported_penalty,
                "total_raw_penalty": total_raw_penalty,
            },
            "scoring_weights": self.weights,
        }
