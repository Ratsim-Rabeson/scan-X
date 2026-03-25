"""File-based API response cache."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ResponseCache:
    """Simple file-based cache for API responses.

    Each entry is stored as a JSON file named by the SHA-256 hash of
    ``source + key``.  Files contain metadata (``cached_at``, ``source``,
    ``key``) alongside the cached ``data`` payload.
    """

    def __init__(self, cache_dir: Path | None = None, ttl_hours: int = 1) -> None:
        self._cache_dir = cache_dir or Path.home() / ".cache" / "scan-x"
        self._ttl_seconds = ttl_hours * 3600

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _hash_key(self, source: str, key: str) -> str:
        return hashlib.sha256(f"{source}:{key}".encode()).hexdigest()

    def _entry_path(self, source: str, key: str) -> Path:
        return self._cache_dir / f"{self._hash_key(source, key)}.json"

    def _is_expired(self, cached_at: str) -> bool:
        ts = datetime.fromisoformat(cached_at)
        age = (datetime.now(UTC) - ts).total_seconds()
        return age > self._ttl_seconds

    # ------------------------------------------------------------------
    # sync file helpers (run via asyncio.to_thread)
    # ------------------------------------------------------------------

    def _read_entry(self, path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]

    def _write_entry(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, default=str), encoding="utf-8")

    # ------------------------------------------------------------------
    # public async API
    # ------------------------------------------------------------------

    async def get(self, source: str, key: str) -> Any | None:
        """Return cached data or *None* if expired / missing."""
        path = self._entry_path(source, key)
        entry = await asyncio.to_thread(self._read_entry, path)
        if entry is None:
            return None
        if self._is_expired(entry["cached_at"]):
            return None
        return entry["data"]

    async def set(self, source: str, key: str, data: Any) -> None:
        """Store *data* under *source*/*key*."""
        path = self._entry_path(source, key)
        payload = {
            "cached_at": datetime.now(UTC).isoformat(),
            "source": source,
            "key": key,
            "data": data,
        }
        await asyncio.to_thread(self._write_entry, path, payload)

    async def clear(self, source: str | None = None) -> int:
        """Delete cache entries. If *source* is given only that source is cleared.

        Returns the number of deleted entries.
        """

        def _clear_sync() -> int:
            if not self._cache_dir.is_dir():
                return 0
            deleted = 0
            for path in list(self._cache_dir.glob("*.json")):
                if source is not None:
                    try:
                        entry = json.loads(path.read_text(encoding="utf-8"))
                        if entry.get("source") != source:
                            continue
                    except (json.JSONDecodeError, KeyError):
                        pass
                path.unlink(missing_ok=True)
                deleted += 1
            return deleted

        return await asyncio.to_thread(_clear_sync)

    async def stats(self) -> dict[str, int]:
        """Return cache statistics.

        Keys: ``total_entries``, ``total_size_bytes``, ``expired_entries``.
        """

        def _stats_sync() -> dict[str, int]:
            total_entries = 0
            total_size_bytes = 0
            expired_entries = 0
            if not self._cache_dir.is_dir():
                return {
                    "total_entries": 0,
                    "total_size_bytes": 0,
                    "expired_entries": 0,
                }
            for path in self._cache_dir.glob("*.json"):
                total_entries += 1
                total_size_bytes += path.stat().st_size
                try:
                    entry = json.loads(path.read_text(encoding="utf-8"))
                    if self._is_expired(entry["cached_at"]):
                        expired_entries += 1
                except (json.JSONDecodeError, KeyError):
                    expired_entries += 1
            return {
                "total_entries": total_entries,
                "total_size_bytes": total_size_bytes,
                "expired_entries": expired_entries,
            }

        return await asyncio.to_thread(_stats_sync)
