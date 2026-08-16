"""Sealed persistence for the optional Online AI provider configuration.

The whole record — provider, base URL, model, and the API key — is sealed as ONE DPAPI
blob (via ``licensing.secret_seal``) and written as two atomic copies under the offline
root's ``config``/``data`` dirs (so it is automatically OUTSIDE backup scope, which only
captures state.json + storage + exports). The plaintext API key therefore lives ONLY in
the sealed blob on disk and briefly in process memory; it is never written to app state,
env, logs, or audit.

The in-memory holder (``get_active``) lazily loads + caches the decrypted record so the
provider resolver can read it on the chat path without re-decrypting each time; ``save``
and ``delete`` invalidate it. Any load/unseal failure fails closed to ``None`` → the
resolver returns the deterministic default.

Path derivation MIRRORS the offline wrapper (``MONDAY_REPORT_OFFLINE_DATA_DIR`` root, or
``%LOCALAPPDATA%/MondayReportOffline``) WITHOUT importing/editing it. When no location is
resolvable (e.g. a bare dev process), the store is simply unavailable.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .licensing.secret_seal import SecretSealUnavailable, seal_available, seal_secret, unseal_secret

PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
KNOWN_PROVIDERS = frozenset({PROVIDER_OPENAI_COMPATIBLE})

_PRIMARY_NAME = "online_ai_settings.bin"
_SECONDARY_NAME = ".online_ai_settings.bin"


class OnlineSettingsUnavailable(RuntimeError):
    """No writable, protected settings location is available on this platform."""


@dataclass(frozen=True)
class OnlineAiSettings:
    provider: str
    base_url: str
    model: str
    # plaintext lives here ONLY in process memory; repr=False keeps it out of any
    # accidental repr()/str()/locals-including traceback formatter.
    api_key: str = field(repr=False)
    created_at: str = ""
    updated_at: str = ""


def _root() -> Path | None:
    override = os.getenv("MONDAY_REPORT_OFFLINE_DATA_DIR", "").strip()
    if override:
        return Path(override)
    local = os.getenv("LOCALAPPDATA", "").strip()
    if local:
        return Path(local) / "MondayReportOffline"
    return None


def _paths() -> tuple[Path, Path] | None:
    root = _root()
    if root is None:
        return None
    return (root / "config" / _PRIMARY_NAME, root / "data" / _SECONDARY_NAME)


def _serialize(settings: OnlineAiSettings) -> bytes:
    return json.dumps(
        {
            "provider": settings.provider,
            "base_url": settings.base_url,
            "model": settings.model,
            "api_key": settings.api_key,
            "created_at": settings.created_at,
            "updated_at": settings.updated_at,
        }
    ).encode("utf-8")


def _deserialize(raw: bytes) -> OnlineAiSettings:
    data = json.loads(raw.decode("utf-8"))
    return OnlineAiSettings(
        provider=str(data["provider"]),
        base_url=str(data["base_url"]),
        model=str(data["model"]),
        api_key=str(data["api_key"]),
        created_at=str(data.get("created_at", "")),
        updated_at=str(data.get("updated_at", "")),
    )


def storage_available() -> bool:
    return _paths() is not None and seal_available()


def load() -> OnlineAiSettings | None:
    """Best surviving sealed copy, or ``None`` if absent/unreadable (fail closed)."""
    paths = _paths()
    if paths is None:
        return None
    for path in paths:
        try:
            if not path.exists():
                continue
            return _deserialize(unseal_secret(path.read_bytes()))
        except Exception:
            continue  # try the other copy; any failure -> treated as absent
    return None


def save(settings: OnlineAiSettings) -> None:
    """Seal the whole record and write both copies atomically. Raises
    ``OnlineSettingsUnavailable`` when no protected location exists."""
    paths = _paths()
    if paths is None:
        raise OnlineSettingsUnavailable("no settings location configured")
    if not seal_available():
        raise OnlineSettingsUnavailable("no protected secret store on this platform")
    try:
        blob = seal_secret(_serialize(settings))
    except SecretSealUnavailable as exc:
        raise OnlineSettingsUnavailable(str(exc)) from exc
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, path)
    invalidate()


def delete() -> None:
    """Remove both sealed copies. Always invalidates the in-memory holder."""
    paths = _paths()
    if paths is not None:
        for path in paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
    invalidate()


# --- in-memory holder -------------------------------------------------------

_UNLOADED = object()
_cache: object = _UNLOADED


def get_active() -> OnlineAiSettings | None:
    """The active online config (lazy-loaded + cached). ``None`` when unconfigured."""
    global _cache
    if _cache is _UNLOADED:
        _cache = load()
    return _cache if isinstance(_cache, OnlineAiSettings) else None


def set_active(settings: OnlineAiSettings | None) -> None:
    """Directly set the in-memory holder (used by tests / an explicit startup load)."""
    global _cache
    _cache = settings


def invalidate() -> None:
    global _cache
    _cache = _UNLOADED
