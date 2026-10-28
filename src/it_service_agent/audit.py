"""Tamper-evident audit log: append-only JSONL with a SHA-256 hash chain.

Each entry's hash covers the previous entry's hash plus its own canonical body, so editing,
deleting, inserting, or reordering any earlier line breaks every later hash. Truncating the
*tail* is only detectable against an external anchor (count + head hash) stored elsewhere
(e.g. Azure Monitor / Sentinel, immutable blob storage), which `anchor()` produces.
"""
from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import Clock, canonical_json, sha256_hex

GENESIS = "0" * 64


class AuditError(RuntimeError):
    pass


@dataclass
class VerifyResult:
    ok: bool
    entries: int = 0
    errors: list[str] = field(default_factory=list)
    head: str = GENESIS


def _entry_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return sha256_hex(prev_hash.encode() + canonical_json(body))


class AuditLog:
    def __init__(self, path: str | Path, clock: Clock | None = None):
        self.path = Path(path)
        self.clock = clock or Clock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # -- writing ---------------------------------------------------------------------
    def append(self, event: str, actor: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        with open(self.path, "a+", encoding="utf-8") as fh:  # append-only; never rewrite
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                seq, prev = self._tail(fh)
                body = {"seq": seq + 1, "ts": self.clock.iso(), "event": event,
                        "actor": actor, "data": data or {}, "prev_hash": prev}
                entry = dict(body, hash=_entry_hash(prev, body))
                fh.seek(0, os.SEEK_END)
                fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
        return entry

    def _tail(self, fh) -> tuple[int, str]:
        fh.seek(0)
        last = None
        for line in fh:
            if line.strip():
                last = line
        if last is None:
            return 0, GENESIS
        try:
            e = json.loads(last)
            return int(e["seq"]), str(e["hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError(f"audit log tail is unreadable; refusing to append: {exc}") from exc

    # -- reading / verification ------------------------------------------------------
    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"_unparseable": line})
        return out

    def verify(self, anchor: dict[str, Any] | None = None) -> VerifyResult:
        res = VerifyResult(ok=True)
        prev = GENESIS
        if not self.path.exists():
            res.ok = anchor is None or anchor.get("count", 0) == 0
            if not res.ok:
                res.errors.append("log file missing but anchor expects entries")
            return res
        n = 0
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                res.errors.append(f"line {lineno}: blank line")
                continue
            try:
                e = json.loads(line)
                body = {k: e[k] for k in ("seq", "ts", "event", "actor", "data", "prev_hash")}
                claimed = e["hash"]
            except (ValueError, KeyError, TypeError):
                res.errors.append(f"line {lineno}: malformed entry")
                continue
            n += 1
            if e["seq"] != n:
                res.errors.append(f"line {lineno}: sequence {e['seq']} != expected {n} (deleted/reordered entry?)")
            if e["prev_hash"] != prev:
                res.errors.append(f"line {lineno}: prev_hash does not match previous entry (chain broken)")
            if _entry_hash(e["prev_hash"], body) != claimed:
                res.errors.append(f"line {lineno}: entry hash mismatch (content modified)")
            prev = claimed
        res.entries, res.head = n, prev
        if anchor is not None:
            if n < anchor.get("count", 0):
                res.errors.append(f"log has {n} entries but anchor recorded {anchor['count']} (truncated?)")
            else:
                # the anchored head must still be present at the anchored position
                lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
                try:
                    at = json.loads(lines[anchor["count"] - 1])["hash"] if anchor["count"] else GENESIS
                except (ValueError, KeyError, IndexError):
                    at = None
                if at != anchor.get("head"):
                    res.errors.append("anchored head hash not found at the anchored position (rewritten history)")
        res.ok = not res.errors
        return res

    def anchor(self) -> dict[str, Any]:
        """Checkpoint to be stored OUTSIDE this file (and outside the agent's write access)."""
        v = self.verify()
        return {"count": v.entries, "head": v.head}

    # -- queries used by the approval gate -------------------------------------------
    def consumed_approvals(self) -> set[str]:
        """Approval ids and nonces already spent (derived from the tamper-evident log)."""
        spent: set[str] = set()
        for e in self.entries():
            if e.get("event") == "approval.consumed":
                d = e.get("data", {})
                spent.update(x for x in (d.get("approval_id"), d.get("nonce")) if x)
        return spent
