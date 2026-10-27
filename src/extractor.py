"""APK Manifest Extraction Module.

Uses Androguard to statically parse AndroidManifest.xml and extract
package metadata, declared/requested permissions, SDK versioning,
and exported application components.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import zipfile
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

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


class APKTooLargeError(APKExtractionError):
    """Raised when the APK exceeds the configured maximum file size."""


class APKSecurityError(APKExtractionError):
    """Raised when an APK fails untrusted-input safety checks (zip bombs etc.)."""


class APKParseTimeoutError(APKExtractionError):
    """Raised when APK parsing exceeds the configured time budget."""


def friendly_error_message(err: Exception) -> str:
    """Map APK extraction exceptions to friendly, actionable user-facing messages.

    Shared by the CLI and the desktop GUI; defined here so it is unit-testable
    without a Tk display.
    """
    if isinstance(err, APKParseTimeoutError):
        return (
            f"Analysis timed out: {err}\n\n"
            "The APK may be malicious or pathological. The scan was safely abandoned."
        )
    if isinstance(err, APKTooLargeError):
        return f"APK rejected by safety limit:\n{err}"
    if isinstance(err, APKSecurityError):
        return f"APK rejected as unsafe (possible zip bomb):\n{err}"
    if isinstance(err, APKNotFoundError):
        return f"File not found:\n{err}"
    if isinstance(err, APKCorruptedError):
        return f"The file is not a valid APK archive:\n{err}"
    return str(err)


@dataclass(frozen=True)
class APKSecurityLimits:
    """Safety limits applied to untrusted APK input before heavy parsing."""

    max_apk_size_mb: float = 500
    max_zip_entries: int = 100_000
    max_uncompressed_mb: float = 4000
    max_compression_ratio: float = 200.0
    parse_timeout_seconds: float = 120

    @classmethod
    def from_settings(cls) -> APKSecurityLimits:
        """Build limits from the global application settings."""
        from src.config import settings

        return cls(
            max_apk_size_mb=settings.max_apk_size_mb,
            max_zip_entries=settings.max_zip_entries,
            max_uncompressed_mb=settings.max_uncompressed_mb,
            max_compression_ratio=settings.max_compression_ratio,
            parse_timeout_seconds=settings.apk_parse_timeout_seconds,
        )


def validate_apk_archive(
    apk_path: str,
    limits: Optional[APKSecurityLimits] = None,
) -> Dict[str, Any]:
    """Validate that an APK is safe to hand to heavy parsers.

    Performs cheap checks on the zip central directory only (no extraction):
      * file size cap
      * zip entry-count cap (zip directory bombs)
      * total declared uncompressed size cap (decompression bombs)
      * overall compression-ratio cap (classic zip bombs)

    Args:
        apk_path: Path to the target .apk file.
        limits: Optional override of security limits (defaults to app settings).

    Returns:
        Archive statistics dict (entry count, compressed/uncompressed totals).

    Raises:
        APKNotFoundError: If the file does not exist.
        APKTooLargeError: If the file exceeds the size cap.
        APKCorruptedError: If the file is not a valid zip archive.
        APKSecurityError: If the archive looks like a decompression/zip bomb.
    """
    lim = limits or APKSecurityLimits.from_settings()

    if not os.path.isfile(apk_path):
        raise APKNotFoundError(f"Target APK file does not exist: {apk_path}")

    file_size = os.path.getsize(apk_path)
    max_size_bytes = lim.max_apk_size_mb * 1024 * 1024
    if file_size > max_size_bytes:
        raise APKTooLargeError(
            f"APK file size ({file_size / 1024 / 1024:.1f} MB) exceeds the safety limit "
            f"of {lim.max_apk_size_mb} MB: {apk_path}"
        )

    try:
        if not zipfile.is_zipfile(apk_path):
            raise APKCorruptedError(f"File is not a valid ZIP/APK archive: {apk_path}")
        with zipfile.ZipFile(apk_path, "r") as zf:
            entries = zf.infolist()
    except APKCorruptedError:
        raise
    except Exception as e:
        raise APKCorruptedError(f"Error checking archive validity for {apk_path}: {e}") from e

    if len(entries) > lim.max_zip_entries:
        raise APKSecurityError(
            f"Archive declares {len(entries)} entries, exceeding the safety limit of "
            f"{lim.max_zip_entries} (zip directory bomb pattern): {apk_path}"
        )

    total_uncompressed = sum(e.file_size for e in entries)
    total_compressed = sum(e.compress_size for e in entries)
    max_uncompressed_bytes = lim.max_uncompressed_mb * 1024 * 1024
    if total_uncompressed > max_uncompressed_bytes:
        raise APKSecurityError(
            f"Archive declares {total_uncompressed / 1024 / 1024:.1f} MB uncompressed content, "
            f"exceeding the safety limit of {lim.max_uncompressed_mb} MB "
            f"(decompression bomb pattern): {apk_path}"
        )

    if total_compressed > 0:
        ratio = total_uncompressed / total_compressed
        if ratio > lim.max_compression_ratio:
            raise APKSecurityError(
                f"Archive compression ratio {ratio:.0f}:1 exceeds the safety limit of "
                f"{lim.max_compression_ratio:.0f}:1 (classic zip bomb pattern): {apk_path}"
            )

    return {
        "file_size_bytes": file_size,
        "entry_count": len(entries),
        "total_uncompressed_bytes": total_uncompressed,
        "total_compressed_bytes": total_compressed,
        "compression_ratio": round(total_uncompressed / total_compressed, 2)
        if total_compressed
        else 0.0,
    }


def run_with_timeout(
    func: Callable[..., Any],
    *args: Any,
    timeout_seconds: float,
    **kwargs: Any,
) -> Any:
    """Run a callable with a hard time budget.

    Uses a daemon worker thread so a hung parser cannot block process exit.
    If the budget is exhausted, raises APKParseTimeoutError and abandons the
    worker (it is killed with the process).

    Raises:
        APKParseTimeoutError: If func does not finish within timeout_seconds.
    """
    result_box: queue.Queue = queue.Queue(maxsize=1)

    def _worker() -> None:
        try:
            result_box.put((True, func(*args, **kwargs)))
        except Exception as exc:  # noqa: BLE001 - forwarded to caller
            result_box.put((False, exc))

    worker = threading.Thread(
        target=_worker,
        daemon=True,
        name="capra-apk-parse",
    )
    worker.start()
    worker.join(timeout_seconds)

    if worker.is_alive():
        raise APKParseTimeoutError(
            f"{getattr(func, '__name__', 'operation')} exceeded the time budget of "
            f"{timeout_seconds}s and was abandoned (possible malicious or pathological APK)."
        )

    try:
        ok, payload = result_box.get_nowait()
    except queue.Empty as exc:
        raise APKParseTimeoutError(
            f"{getattr(func, '__name__', 'operation')} terminated without a result."
        ) from exc

    if ok:
        return payload
    raise payload


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
        "deeplinks": [],
        "browsable_unprotected": 0,
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
                    # Intent-filter / deep-link attack-surface detail
                    intent_filters = []
                    deeplinks: List[str] = []
                    is_browsable = False
                    for f in elem.findall("intent-filter"):
                        actions = [
                            a for a in (_get_attr(x, "name") for x in f.findall("action")) if a
                        ]
                        categories = [
                            c for c in (_get_attr(x, "name") for x in f.findall("category")) if c
                        ]
                        data_entries = []
                        for d in f.findall("data"):
                            entry = {
                                k: v
                                for k, v in {
                                    "scheme": _get_attr(d, "scheme"),
                                    "host": _get_attr(d, "host"),
                                    "port": _get_attr(d, "port"),
                                    "pathPrefix": _get_attr(d, "pathPrefix"),
                                    "mimeType": _get_attr(d, "mimeType"),
                                }.items()
                                if v
                            }
                            if entry:
                                data_entries.append(entry)
                            scheme = entry.get("scheme")
                            host = entry.get("host")
                            if scheme and host:
                                port = entry.get("port")
                                deeplinks.append(
                                    f"{scheme}://{host}" + (f":{port}" if port else "")
                                )
                            elif scheme:
                                deeplinks.append(f"{scheme}://")
                        if any("BROWSABLE" in (c or "") for c in categories):
                            is_browsable = True
                        intent_filters.append(
                            {"actions": actions, "categories": categories, "data": data_entries}
                        )

                    comp_info = {
                        "name": name,
                        "type": tag,
                        "permission_required": permission,
                        "is_protected": bool(permission),
                        "intent_filters": intent_filters,
                        "deeplinks": sorted(set(deeplinks)),
                        "is_browsable": is_browsable,
                    }
                    exported_summary[key].append(comp_info)
                    exported_summary["total_exported"] += 1
                    if not permission:
                        exported_summary["unprotected_exported"] += 1
                    if deeplinks:
                        exported_summary["deeplinks"].extend(sorted(set(deeplinks)))
                    if is_browsable and not permission:
                        exported_summary["browsable_unprotected"] += 1

    except Exception as e:
        logger.warning(f"Could not fully parse exported components: {e}")

    return exported_summary


def _parse_manifest_fields(apk_path: str) -> Dict[str, Any]:
    """Inner parse: open with Androguard and extract manifest metadata."""
    try:
        apk = APK(apk_path)
    except Exception as e:
        raise APKCorruptedError(
            f"Androguard failed to initialize APK archive '{apk_path}': {e}"
        ) from e

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


def extract_manifest_info(apk_path: str) -> Dict[str, Any]:
    """Statically parse AndroidManifest.xml from an APK file.

    Untrusted-input safety: the archive is first validated against size,
    entry-count, uncompressed-size, and compression-ratio limits (zip-bomb
    guards), and parsing runs under a hard time budget.

    Args:
        apk_path: Absolute or relative file path to the target .apk.

    Returns:
        Structured dictionary containing package metadata, permissions, SDK levels,
        and exported component summaries.

    Raises:
        APKNotFoundError: If the file does not exist.
        APKTooLargeError: If the file exceeds the configured size cap.
        APKCorruptedError: If the file is not a valid APK/ZIP archive.
        APKSecurityError: If the archive matches decompression-bomb patterns.
        APKParseTimeoutError: If parsing exceeds the configured time budget.
        APKExtractionError: If manifest parsing fails.
    """
    limits = APKSecurityLimits.from_settings()
    validate_apk_archive(apk_path, limits=limits)
    return run_with_timeout(
        _parse_manifest_fields,
        apk_path,
        timeout_seconds=limits.parse_timeout_seconds,
    )


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
