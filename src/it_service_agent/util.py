"""Small shared helpers: canonical JSON, hashing, and an injectable clock."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every hash and signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class Clock:
    """Wall clock with an optional fixed start and manual advance (for tests)."""

    def __init__(self, fixed: datetime | None = None, offset_seconds: float = 0.0):
        self._fixed = fixed
        self._offset = offset_seconds

    def now(self) -> datetime:
        base = self._fixed or datetime.now(timezone.utc)
        return (base + timedelta(seconds=self._offset)).replace(microsecond=0)

    def advance(self, seconds: float) -> None:
        self._offset += seconds

    def iso(self) -> str:
        return self.now().strftime(ISO_FMT)


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, ISO_FMT).replace(tzinfo=timezone.utc)


def fmt_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO_FMT)
