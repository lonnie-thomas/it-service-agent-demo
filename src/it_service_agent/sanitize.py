"""Input hygiene: normalise hidden text, flag likely prompt-injection, redact secrets.

IMPORTANT: this is a *detection and hygiene* layer, not the security boundary.
The boundary is structural: allowlist + grounding in runbooks + human approval.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from .models import Ticket

HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
# Unicode "tag" characters (U+E0000-U+E007F) are invisible but can smuggle ASCII.
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")

INJECTION_PATTERNS = [
    (r"ignore (all |any )?(the )?(previous|prior|above) (instructions|rules|prompts?)", "override-instructions"),
    (r"disregard (all |any )?(the )?(previous|prior|above|system)", "override-instructions"),
    (r"you are now|new instructions?:|system prompt|developer message", "role-reassignment"),
    (r"\b(pre-?approved|approval (is )?(waived|granted|not required)|skip (the )?approval)\b", "approval-bypass"),
    (r"\b(run|execute|perform)\b[^.\n]{0,40}\b(add_user_to_group|disable_|delete_|grant_|reset_all)", "action-smuggling"),
    (r"\bdomain[ -]admins?\b|\bglobal admin(istrator)?\b", "privilege-target"),
    (r"(send|forward|post|email)\b[^.\n]{0,50}\b(credentials?|passwords?|secrets?|api keys?|tokens?)", "exfiltration"),
    (r"https?://\S+\.(zip|exe|ps1)\b", "suspicious-link"),
]
_COMPILED = [(re.compile(p, re.I), label) for p, label in INJECTION_PATTERNS]

SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\b(\s*[:=]\s*)(\S+)"),
     r"\1\2[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "[REDACTED-KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-KEY]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"), "Bearer [REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
]


def redact(text: str) -> str:
    for pat, repl in SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


def normalise(text: str) -> tuple[str, list[str]]:
    """Return visible text plus a list of hygiene findings."""
    findings: list[str] = []
    if HTML_COMMENT.search(text):
        findings.append("html-comment")
        text = HTML_COMMENT.sub(" ", text)
    if TAG_CHARS.search(text):
        findings.append("unicode-tag-characters")
        text = TAG_CHARS.sub("", text)
    if BIDI_CONTROLS.search(text):
        findings.append("bidi-control-characters")
        text = BIDI_CONTROLS.sub("", text)
    if any(unicodedata.category(c) == "Cf" for c in text):
        findings.append("zero-width-or-format-characters")
        text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = unicodedata.normalize("NFKC", text)
    return text, findings


def scan_injection(text: str) -> list[str]:
    return sorted({label for pat, label in _COMPILED if pat.search(text)})


def inspect_ticket(ticket: Ticket) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Return sanitised text per source and the flags a human approver should see.

    Flags are computed on the RAW text too, because hidden content (HTML comments,
    tag characters) is exactly what normalisation removes.
    """
    sources = {"title": ticket.title, "body": ticket.body}
    for a in ticket.attachments:
        sources[f"attachment:{a.name}"] = a.text
    clean: dict[str, str] = {}
    flags: list[dict[str, Any]] = []
    for src, raw in sources.items():
        text, findings = normalise(raw)
        clean[src] = text
        for f in findings:
            flags.append({"type": "hidden-content", "source": src, "detail": f})
        # Scan raw text, cleaned text, and any ASCII smuggled via Unicode tag characters.
        smuggled = "".join(chr(ord(c) - 0xE0000) for c in raw if "\U000E0000" <= c <= "\U000E007F")
        found = set(scan_injection(raw)) | set(scan_injection(text)) | set(scan_injection(smuggled))
        for label in sorted(found):
            flags.append({"type": "possible-prompt-injection", "source": src, "detail": label})
    return clean, flags
