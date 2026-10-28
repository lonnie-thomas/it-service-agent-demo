"""Ticket loading (JSON or Markdown with simple front matter) and shared agent factory."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Ticket


def load_ticket(path: str | Path) -> Ticket:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return Ticket.from_dict(json.loads(text))
    if p.suffix.lower() in (".md", ".markdown"):
        return _parse_markdown(text)
    raise ValueError(f"unsupported ticket format: {p.suffix} (use .json or .md)")


def _parse_markdown(text: str) -> Ticket:
    """Markdown ticket:

        ---
        id: INC-1001
        requester: a@example.test
        affected_user: a@example.test      (optional)
        group: SG-Collab-Basic             (optional; any extra key becomes a structured field)
        ---
        # Title line
        Body text...
    """
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
    if not m:
        raise ValueError("markdown ticket needs '---' front matter with at least id and requester")
    meta: dict[str, Any] = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.strip().startswith("#"):
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    rest = m.group(2).strip().splitlines()
    title = ""
    if rest and rest[0].startswith("#"):
        title = rest[0].lstrip("# ").strip()
        rest = rest[1:]
    known = {"id", "requester", "affected_user"}
    return Ticket.from_dict({
        "id": meta.get("id"), "requester": meta.get("requester"), "affected_user": meta.get("affected_user"),
        "title": title, "body": "\n".join(rest).strip(),
        "fields": {k: v for k, v in meta.items() if k not in known}})
