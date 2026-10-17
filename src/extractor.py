"""APK Manifest Extraction Module.

Uses Androguard to statically parse AndroidManifest.xml and extract
package metadata, declared/requested permissions, SDK versioning,
and exported application components.
"""

from __future__ import annotations

import logging
import os
import zipfile
from typing import Any, Dict, List, Optional

# Suppress noisy androguard debug logging if loguru is installed
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except ImportError:
    pass

# Support both Androguard 4.x and legacy 3.x module namespaces
try:
    from androguard.core.apk import APK
except ImportError:
    try:
        # pyrefly: ignore [missing-import]
        from androguard.core.bytecodes.apk import APK
    except ImportError as e:
        raise ImportError(
            "Could not import APK from Androguard. Ensure 'androguard' is installed."
        ) from e

logger = logging.getLogger(__name__)

ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"


class APKExtractionError(Exception):
    """Base exception for APK extraction failures."""


class APKNotFoundError(APKExtractionError):
    """Raised when the target APK file does not exist."""


class APKCorruptedError(APKExtractionError):
    """Raised when the target APK is not a valid zip or has corrupted headers."""


def _get_attr(element: Any, attr_name: str) -> Optional[str]:
    """Helper to extract an attribute from an XML element respecting Android namespaces."""
    if element is None or not hasattr(element, "attrib"):
        return None
    # Check namespaced attribute first
    namespaced = f"{ANDROID_NAMESPACE}{attr_name}"
    if namespaced in element.attrib:
        return element.attrib[namespaced]
    # Check non-namespaced fallback
    if attr_name in element.attrib:
        return element.attrib[attr_name]
    return None


def _is_component_exported(
    element: Any,
    tag_name: str,
    target_sdk: Optional[int] = None,
) -> bool:
    """Determine if a component is exported based on android:exported or presence of intent-filters.

    Android documentation rules:
    - If android:exported is explicitly defined ("true"/"false"), obey it.
    - If android:exported is not defined:
        - For targetSdk < 31: If intent-filter exists, defaults to true; else false.
        - For content providers on SDK < 17, defaults to true; on >=17 defaults to false.
    """
    exported_val = _get_attr(element, "exported")
    if exported_val is not None:
        return str(exported_val).strip().lower() == "true"

    # Default logic when android:exported is omitted
    has_intent_filter = False
    if hasattr(element, "findall"):
        has_intent_filter = len(element.findall("intent-filter")) > 0

    if tag_name == "provider":
        if target_sdk and target_sdk < 17:
            return True
        return has_intent_filter

    return has_intent_filter


def _parse_exported_components(
    apk: APK,
    target_sdk: Optional[int] = None,
) -> Dict[str, Any]:
    """Inspect activities, services, receivers, and providers to identify exported components."""
    exported_summary: Dict[str, Any] = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "total_exported": 0,
        "unprotected_exported": 0,
    }

    try:
        manifest = apk.get_android_manifest_xml()
        if manifest is None:
            return exported_summary

        app_element = manifest.find("application")
        if app_element is None:
            return exported_summary

        component_tags = {
            "activity": "activities",
            "service": "services",
            "receiver": "receivers",
            "provider": "providers",
        }

        for tag, key in component_tags.items():
            for elem in app_element.findall(tag):
                name = _get_attr(elem, "name") or "Unknown"
                permission = _get_attr(elem, "permission")
                is_exported = _is_component_exported(elem, tag, target_sdk)

                if is_exported:
                    comp_info = {
                        "name": name,
                        "type": tag,
                        "permission_required": permission,
                        "is_protected": bool(permission),
                    }
                    exported_summary[key].append(comp_info)
                    exported_summary["total_exported"] += 1
                    if not permission:
                        exported_summary["unprotected_exported"] += 1

    except Exception as e:
        logger.warning(f"Could not fully parse exported components: {e}")

    return exported_summary


def extract_manifest_info(apk_path: str) -> Dict[str, Any]:
    """Statically parse AndroidManifest.xml from an APK file.

    Args:
        apk_path: Absolute or relative file path to the target .apk.

    Returns:
        Structured dictionary containing package metadata, permissions, SDK levels,
        and exported component summaries.

    Raises:
        APKNotFoundError: If the file does not exist.
        APKCorruptedError: If the file is not a valid APK/ZIP archive.
        APKExtractionError: If manifest parsing fails.
    """
    if not os.path.isfile(apk_path):
        raise APKNotFoundError(f"Target APK file does not exist: {apk_path}")

    # Check basic zip validity before invoking heavy parsing
    try:
        if not zipfile.is_zipfile(apk_path):
            raise APKCorruptedError(f"File is not a valid ZIP/APK archive: {apk_path}")
    except Exception as e:
        raise APKCorruptedError(f"Error checking archive validity for {apk_path}: {e}") from e

    try:
        apk = APK(apk_path)
    except Exception as e:
        raise APKCorruptedError(f"Androguard failed to initialize APK archive '{apk_path}': {e}") from e

    try:
        package_name = apk.get_package() or "unknown.package"
        app_name = apk.get_app_name() or ""

        # Normalize target and min SDK versions
        raw_target_sdk = apk.get_target_sdk_version()
        raw_min_sdk = apk.get_min_sdk_version()

        try:
            target_sdk = int(raw_target_sdk) if raw_target_sdk is not None else None
        except (ValueError, TypeError):
            target_sdk = None

        try:
            min_sdk = int(raw_min_sdk) if raw_min_sdk is not None else None
        except (ValueError, TypeError):
            min_sdk = None

        version_name = apk.get_androidversion_name() or ""
        version_code = apk.get_androidversion_code() or ""

        # Requested permissions (<uses-permission>)
        raw_permissions = apk.get_permissions() or []
        declared_permissions = sorted(list(set(raw_permissions)))

        # Custom defined permissions (<permission>)
        raw_custom = apk.get_declared_permissions() or []
        custom_permissions = sorted(list(set(raw_custom)))

        # Component counts
        activities = apk.get_activities() or []
        services = apk.get_services() or []
        receivers = apk.get_receivers() or []
        providers = apk.get_providers() or []

        exported_details = _parse_exported_components(apk, target_sdk)

        file_size = os.path.getsize(apk_path)

        return {
            "file_path": os.path.abspath(apk_path),
            "file_size_bytes": file_size,
            "package_name": package_name,
            "app_name": app_name,
            "target_sdk_version": target_sdk,
            "min_sdk_version": min_sdk,
            "version_name": version_name,
            "version_code": version_code,
            "declared_permissions": declared_permissions,
            "custom_permissions": custom_permissions,
            "total_permissions_count": len(declared_permissions),
            "components": {
                "activities_count": len(activities),
                "services_count": len(services),
                "receivers_count": len(receivers),
                "providers_count": len(providers),
                "exported": exported_details,
            },
        }

    except Exception as e:
        raise APKExtractionError(f"Failed to parse manifest data from '{apk_path}': {e}") from e


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.extractor <path_to_apk>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        res = extract_manifest_info(target)
        print(json.dumps(res, indent=2))
    except APKExtractionError as err:
        print(f"Extraction Error: {err}", file=sys.stderr)
        sys.exit(1)
