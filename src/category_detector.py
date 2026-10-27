"""Automatic Application Category Detection Module.

Part of Context Intelligence (CAPRA v2 - Omraj's Module).
Analyzes package name tokens, application label strings, and manifest permission/component
profiles to automatically infer the app's functional category.
Provides confidence scoring and allows manual override.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CategoryDetectionResult:
    """Outcome of category detection analysis."""

    category: str
    confidence: float
    method: str
    matched_signals: List[str] = field(default_factory=list)
    is_overridden: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection result to serializable dictionary."""
        return {
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "confidence_percentage": round(self.confidence * 100, 1),
            "method": self.method,
            "matched_signals": self.matched_signals,
            "is_overridden": self.is_overridden,
        }


# Canonical category keyword dictionaries
CATEGORY_KEYWORDS: Dict[str, Dict[str, List[str]]] = {
    "Calculator": {
        "primary": ["calculator", "calc", "math", "arithmetic"],
        "secondary": ["algebra", "scientific_calc", "equations", "numbers", "matrix"],
    },
    "Flashlight": {
        "primary": ["flashlight", "torch", "led_light"],
        "secondary": ["illumination", "strobe", "lamp", "lantern", "bright_light"],
    },
    "Navigation": {
        "primary": ["navigation", "navigator", "maps", "gps", "route"],
        "secondary": [
            "transit",
            "osm",
            "waze",
            "commute",
            "turnbyturn",
            "directions",
            "location_tracker",
        ],
    },
    "Social Media": {
        "primary": ["social", "network", "community", "feed", "profile"],
        "secondary": ["tweet", "insta", "forum", "clubhouse", "friends", "posts", "connect"],
    },
    "Messaging": {
        "primary": [
            "message",
            "messaging",
            "chat",
            "messenger",
            "sms",
            "browser",
            "email",
            "mail",
            "voip",
            "dialer",
        ],
        "secondary": [
            "talk",
            "texting",
            "wechat",
            "whatsapp",
            "signal",
            "telegram",
            "inbox",
            "voip",
        ],
    },
    "Banking/Finance": {
        "primary": ["bank", "banking", "finance", "fintech", "wallet"],
        "secondary": [
            "pay",
            "payment",
            "money",
            "loan",
            "crypto",
            "credit",
            "invest",
            "stock",
            "wealth",
            "upi",
        ],
    },
    "Health/Fitness": {
        "primary": [
            "fitness",
            "workout",
            "health",
            "exercise",
            "running",
            "sport",
            "sports",
            "football",
            "soccer",
            "cricket",
            "basketball",
            "baseball",
            "hockey",
            "tennis",
            "golf",
        ],
        "secondary": [
            "pedometer",
            "diet",
            "gym",
            "cardio",
            "sleep",
            "heartrate",
            "steps",
            "calorie",
            "league",
            "score",
            "scores",
            "olympic",
            "marathon",
            "yoga",
            "meditation",
            "pain",
            "symptom",
            "wellness",
        ],
    },
    "Games": {
        "primary": ["game", "games", "gaming", "play", "arcade"],
        "secondary": [
            "puzzle",
            "rpg",
            "quest",
            "racing",
            "clash",
            "simulator",
            "unity",
            "craft",
            "battle",
            "hero",
            "gacha",
            "tycoon",
            "survival",
            "sudoku",
            "chess",
            "ludo",
            "royale",
        ],
    },
    "Camera/Photo": {
        "primary": ["camera", "photo", "photography", "selfie", "editor"],
        "secondary": ["filter", "pic", "image", "lens", "capture", "retouch", "gallery", "collage"],
    },
    "Music/Video": {
        "primary": ["music", "video", "media", "player", "audio"],
        "secondary": [
            "stream",
            "mp3",
            "podcast",
            "radio",
            "track",
            "tune",
            "sound",
            "mp4",
            "playback",
            "fm",
            "movies",
            "clips",
            "karaoke",
            "lyrics",
        ],
    },
    "Shopping": {
        "primary": ["shop", "shopping", "store", "ecommerce", "cart"],
        "secondary": [
            "deals",
            "buy",
            "marketplace",
            "mall",
            "fashion",
            "retail",
            "discounts",
            "orders",
        ],
    },
    "Productivity": {
        "primary": ["productivity", "office", "notes", "notepad", "task"],
        "secondary": [
            "todo",
            "calendar",
            "document",
            "pdf",
            "scanner",
            "organizer",
            "workflow",
            "sheets",
        ],
    },
    "Education": {
        "primary": ["education", "learning", "study", "course", "quiz"],
        "secondary": [
            "tutor",
            "school",
            "dictionary",
            "language",
            "academy",
            "vocab",
            "flashcards",
            "learn",
            "quran",
            "bible",
            "exam",
            "lectures",
        ],
    },
}

# Permission profile fingerprint hints
PERMISSION_PROFILE_HINTS: Dict[str, Tuple[List[str], str]] = {
    "Health/Fitness": (
        ["android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION"],
        "Includes biometric body sensor / physical activity telemetry",
    ),
    "Navigation": (
        [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ],
        "Includes continuous background geolocation tracking",
    ),
    "Camera/Photo": (
        ["android.permission.CAMERA", "android.permission.READ_MEDIA_IMAGES"],
        "Includes camera sensor combined with photo library access",
    ),
    "Music/Video": (
        ["android.permission.READ_MEDIA_AUDIO", "android.permission.FOREGROUND_SERVICE"],
        "Includes foreground audio playback permissions",
    ),
    "Banking/Finance": (
        ["android.permission.USE_BIOMETRIC", "android.permission.INTERNET"],
        "Includes biometric authentication with internet connectivity",
    ),
}

# Catalog of well-known apps (brand tokens -> canonical category).
# Real-world app listings are frequently brand names ("Spotify", "Turbo VPN") that
# carry no descriptive keywords; a curated catalog is the only reliable signal for
# them. Matching prefers the most specific (most-token) entry. This mirrors how
# commercial app-classification products combine heuristics with app catalogs.
KNOWN_APPS: Dict[str, str] = {
    # Navigation & travel
    "waze": "Navigation",
    "sygic": "Navigation",
    "osmand": "Navigation",
    "komoot": "Navigation",
    "alltrails": "Navigation",
    "google maps": "Navigation",
    "google map": "Navigation",
    "uber": "Navigation",
    "lyft": "Navigation",
    # Social & dating
    "facebook": "Social Media",
    "instagram": "Social Media",
    "tiktok": "Social Media",
    "snapchat": "Social Media",
    "reddit": "Social Media",
    "pinterest": "Social Media",
    "linkedin": "Social Media",
    "threads": "Social Media",
    "twitter": "Social Media",
    "tumblr": "Social Media",
    "quora": "Social Media",
    "sharechat": "Social Media",
    "likee": "Social Media",
    "bigo": "Social Media",
    "tango": "Social Media",
    "whisper": "Social Media",
    "textplus": "Social Media",
    "meetme": "Social Media",
    "coffee meets bagel": "Social Media",
    "hinge": "Social Media",
    "tinder": "Social Media",
    "bumble": "Social Media",
    "badoo": "Social Media",
    "okcupid": "Social Media",
    # Messaging & communication (incl. browsers/mail — the comms bucket)
    "whatsapp": "Messaging",
    "telegram": "Messaging",
    "signal": "Messaging",
    "viber": "Messaging",
    "wechat": "Messaging",
    "kik": "Messaging",
    "hangouts": "Messaging",
    "skype": "Messaging",
    "zoom": "Messaging",
    "jitsi meet": "Messaging",
    "groupme": "Messaging",
    "truecaller": "Messaging",
    "nextplus": "Messaging",
    "messenger": "Messaging",
    "discord": "Messaging",
    "google meet": "Messaging",
    "google chat": "Messaging",
    "gmail": "Messaging",
    "yahoo mail": "Messaging",
    "protonmail": "Messaging",
    "firefox": "Messaging",
    "google chrome": "Messaging",
    "chrome": "Messaging",
    "microsoft edge": "Messaging",
    "opera": "Messaging",
    "brave": "Messaging",
    "puffin": "Messaging",
    # Banking & finance
    "paypal": "Banking/Finance",
    "venmo": "Banking/Finance",
    "webull": "Banking/Finance",
    "revolut": "Banking/Finance",
    "robinhood": "Banking/Finance",
    "coinbase": "Banking/Finance",
    "binance": "Banking/Finance",
    "cash app": "Banking/Finance",
    "monzo": "Banking/Finance",
    "nubank": "Banking/Finance",
    "chime": "Banking/Finance",
    "klarna": "Banking/Finance",
    "afterpay": "Banking/Finance",
    "wise": "Banking/Finance",
    "google pay": "Banking/Finance",
    "paytm": "Banking/Finance",
    "phonepe": "Banking/Finance",
    # Health & fitness (incl. sports — the health bucket)
    "fitbit": "Health/Fitness",
    "fitnotes": "Health/Fitness",
    "strava": "Health/Fitness",
    "peloton": "Health/Fitness",
    "myfitnesspal": "Health/Fitness",
    "google fit": "Health/Fitness",
    "garmin": "Health/Fitness",
    "headspace": "Health/Fitness",
    "espn": "Health/Fitness",
    "nba": "Health/Fitness",
    "nfl": "Health/Fitness",
    "premier league": "Health/Fitness",
    "onefootball": "Health/Fitness",
    "flashscore": "Health/Fitness",
    "cricbuzz": "Health/Fitness",
    # Games
    "roblox": "Games",
    "pubg": "Games",
    "among us": "Games",
    "angry birds": "Games",
    "candy crush": "Games",
    "subway surfers": "Games",
    "clash of clans": "Games",
    "clash royale": "Games",
    "brawl stars": "Games",
    "minecraft": "Games",
    "fortnite": "Games",
    "temple run": "Games",
    "shadow fight": "Games",
    "mobile legends": "Games",
    "free fire": "Games",
    "lego": "Games",
    # Camera & photo
    "picsart": "Camera/Photo",
    "vsco": "Camera/Photo",
    "snapseed": "Camera/Photo",
    "lightroom": "Camera/Photo",
    "beautyplus": "Camera/Photo",
    "retrica": "Camera/Photo",
    "google photos": "Camera/Photo",
    "imaging edge": "Camera/Photo",
    # Music & video
    "spotify": "Music/Video",
    "youtube music": "Music/Video",
    "youtube": "Music/Video",
    "deezer": "Music/Video",
    "soundcloud": "Music/Video",
    "tidal": "Music/Video",
    "netflix": "Music/Video",
    "prime video": "Music/Video",
    "amazon music": "Music/Video",
    "hotstar": "Music/Video",
    "vlc": "Music/Video",
    "mx player": "Music/Video",
    "jiosaavn": "Music/Video",
    "gaana": "Music/Video",
    "shazam": "Music/Video",
    "siriusxm": "Music/Video",
    "bilibili": "Music/Video",
    "dailymotion": "Music/Video",
    "vimeo": "Music/Video",
    "twitch": "Music/Video",
    "capcut": "Music/Video",
    "powerdirector": "Music/Video",
    "youcut": "Music/Video",
    "inshot": "Music/Video",
    "kinemaster": "Music/Video",
    "plex": "Music/Video",
    # Shopping
    "amazon": "Shopping",
    "aliexpress": "Shopping",
    "shein": "Shopping",
    "ebay": "Shopping",
    "etsy": "Shopping",
    "zara": "Shopping",
    "walmart": "Shopping",
    "kroger": "Shopping",
    "walgreens": "Shopping",
    "nike": "Shopping",
    "adidas": "Shopping",
    "family dollar": "Shopping",
    "asos": "Shopping",
    "flipkart": "Shopping",
    "myntra": "Shopping",
    "ajio": "Shopping",
    "noon": "Shopping",
    "jumia": "Shopping",
    "lazada": "Shopping",
    "shopee": "Shopping",
    "temu": "Shopping",
    "zalando": "Shopping",
    "dolap": "Shopping",
    "wayfair": "Shopping",
    # Productivity & utilities
    "shopify": "Productivity",
    "amazon alexa": "Productivity",
    "google go": "Productivity",
    "google translate": "Productivity",
    "family link": "Productivity",
    "authenticator": "Productivity",
    "termux": "Productivity",
    "bing": "Productivity",
    "shareme": "Productivity",
    "govee": "Productivity",
    "soundcore": "Productivity",
    "sennheiser": "Productivity",
    "duckduckgo": "Productivity",
    "turbo vpn": "Productivity",
    "canva": "Productivity",
    "evernote": "Productivity",
    "trello": "Productivity",
    "notion": "Productivity",
    "dropbox": "Productivity",
    "onedrive": "Productivity",
    "google drive": "Productivity",
    "google keep": "Productivity",
    "camscanner": "Productivity",
    "wps": "Productivity",
    # Education & books
    "duolingo": "Education",
    "khan academy": "Education",
    "coursera": "Education",
    "udemy": "Education",
    "quizlet": "Education",
    "brainly": "Education",
    "byjus": "Education",
    "goodreads": "Education",
    "tapas": "Education",
    "wattpad": "Education",
    "kindle": "Education",
    "google play books": "Education",
    "audiobooks": "Education",
    "audible": "Education",
    "dreame": "Education",
    "photomath": "Education",
    "memrise": "Education",
}


class CategoryDetector:
    """Context-aware application category classifier."""

    def __init__(self) -> None:
        self.categories = list(CATEGORY_KEYWORDS.keys())

    def _tokenize(self, text: str) -> Set[str]:
        """Split package name or app label into lowercase normalized tokens."""
        if not text:
            return set()
        # Split by dots, underscores, dashes, camelCase and non-alphanumeric
        s = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
        tokens = re.split(r"[^a-zA-Z0-9]+", s.lower())
        return {t for t in tokens if len(t) >= 2}

    def _match_known_app(self, *names: str) -> Optional[Tuple[str, str]]:
        """Return (brand_key, category) for the most specific known-app match.

        A brand key matches when ALL of its tokens appear in the name's tokens;
        the entry with the most tokens wins ("google chrome" beats "chrome").
        Brand matching deliberately avoids camelCase splitting so glued brands
        ("AliExpress", "WhatsApp", "YouTube") stay intact.
        """
        best_key = None
        best_cat = ""
        for name in names:
            tokens = {t for t in re.split(r"[^a-zA-Z0-9]+", (name or "").lower()) if len(t) >= 2}
            if not tokens:
                continue
            for key, cat in KNOWN_APPS.items():
                key_tokens = key.split()
                if set(key_tokens).issubset(tokens):
                    if best_key is None or len(key_tokens) > len(best_key.split()):
                        best_key, best_cat = key, cat
        return (best_key, best_cat) if best_key else None

    def detect(
        self,
        package_name: str,
        app_name: str = "",
        declared_permissions: Optional[List[str]] = None,
        components: Optional[Dict[str, Any]] = None,
        override_category: Optional[str] = None,
    ) -> CategoryDetectionResult:
        """Infer app category with confidence scoring and manual override support.

        Args:
            package_name: Android package name (e.g. 'org.fossify.math').
            app_name: Optional human-readable app label (e.g. 'Calculator').
            declared_permissions: Optional list of requested permissions.
            components: Optional parsed component summaries.
            override_category: Optional explicit user category override.

        Returns:
            CategoryDetectionResult with canonical category, confidence, and explanation.
        """
        # 1. Check for explicit manual override
        if override_category:
            from src.context_engine import ContextEngine

            try:
                ce = ContextEngine()
                resolved = ce.resolve_category(override_category)
                return CategoryDetectionResult(
                    category=resolved,
                    confidence=1.0,
                    method="manual_override",
                    matched_signals=[f"Manual user override applied: '{override_category}'"],
                    is_overridden=True,
                )
            except Exception:
                # If invalid override, proceed with auto-detection
                pass

        pkg_tokens = self._tokenize(package_name)
        app_tokens = self._tokenize(app_name)
        perms_set = set(declared_permissions or [])

        # 2. Known-app catalog (brand names carry no descriptive keywords)
        known = self._match_known_app(app_name, package_name)
        if known:
            brand_key, brand_cat = known
            return CategoryDetectionResult(
                category=brand_cat,
                confidence=0.95,
                method="known_app_catalog",
                matched_signals=[f"Recognized popular app brand '{brand_key}'"],
                is_overridden=False,
            )

        category_scores: Dict[str, float] = {cat: 0.0 for cat in self.categories}
        category_signals: Dict[str, List[str]] = {cat: [] for cat in self.categories}

        # 3. Keyword scoring across package name and app label
        for cat, kw_dict in CATEGORY_KEYWORDS.items():
            # App Label matches (strongest weight: 4.0 primary, 2.0 secondary)
            for kw in kw_dict["primary"]:
                if kw in app_tokens:
                    category_scores[cat] += 4.0
                    category_signals[cat].append(f"App label matches primary keyword '{kw}'")
                elif any(kw in t for t in app_tokens):
                    category_scores[cat] += 2.5
                    category_signals[cat].append(f"App label contains keyword substring '{kw}'")

            for kw in kw_dict["secondary"]:
                if kw in app_tokens:
                    category_scores[cat] += 2.0
                    category_signals[cat].append(f"App label matches secondary keyword '{kw}'")

            # Package Name matches (weight: 3.0 primary, 1.5 secondary)
            for kw in kw_dict["primary"]:
                if kw in pkg_tokens:
                    category_scores[cat] += 3.0
                    category_signals[cat].append(f"Package name matches primary keyword '{kw}'")
                elif any(kw in t for t in pkg_tokens):
                    category_scores[cat] += 2.0
                    category_signals[cat].append(f"Package name contains keyword substring '{kw}'")

            for kw in kw_dict["secondary"]:
                if kw in pkg_tokens:
                    category_scores[cat] += 1.5
                    category_signals[cat].append(f"Package name matches secondary keyword '{kw}'")

        # 4. Manifest Permission Profile scoring
        for cat, (target_perms, desc) in PERMISSION_PROFILE_HINTS.items():
            if set(target_perms).issubset(perms_set):
                category_scores[cat] += 2.5
                category_signals[cat].append(f"Permission signature: {desc}")

        # 5. Determine winning category
        best_cat = max(category_scores.keys(), key=lambda c: category_scores[c])
        max_score = category_scores[best_cat]

        # Calculate confidence score
        if max_score >= 6.0:
            confidence = min(0.96, 0.75 + (max_score * 0.03))
            method = "keyword_exact"
        elif max_score >= 3.0:
            confidence = min(0.85, 0.60 + (max_score * 0.04))
            method = "keyword_heuristic"
        elif max_score > 0.0:
            confidence = min(0.65, 0.40 + (max_score * 0.05))
            method = "manifest_feature"
        else:
            # Fallback to general utility (Productivity) or Calculator
            best_cat = "Calculator" if "calc" in package_name.lower() else "Productivity"
            confidence = 0.30
            method = "fallback_heuristic"
            category_signals[best_cat].append(
                "No explicit keywords matched; default baseline applied."
            )

        return CategoryDetectionResult(
            category=best_cat,
            confidence=round(confidence, 3),
            method=method,
            matched_signals=category_signals[best_cat],
            is_overridden=False,
        )


# Singleton instance
_detector_instance: Optional[CategoryDetector] = None


def get_category_detector() -> CategoryDetector:
    """Retrieve or initialize the global CategoryDetector."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = CategoryDetector()
    return _detector_instance


def detect_app_category(
    package_name: str,
    app_name: str = "",
    declared_permissions: Optional[List[str]] = None,
    components: Optional[Dict[str, Any]] = None,
    override_category: Optional[str] = None,
) -> CategoryDetectionResult:
    """Functional convenience wrapper for category detection."""
    detector = get_category_detector()
    return detector.detect(
        package_name=package_name,
        app_name=app_name,
        declared_permissions=declared_permissions,
        components=components,
        override_category=override_category,
    )
