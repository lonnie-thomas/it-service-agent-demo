"""Core data models: Ticket, Citation, Action, Plan."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .util import canonical_json, sha256_hex


@dataclass(frozen=True)
class Attachment:
    name: str
    text: str


@dataclass(frozen=True)
class Ticket:
    id: str
    title: str
    body: str
    requester: str
    affected_user: str = ""
    attachments: tuple[Attachment, ...] = ()
    fields: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Ticket":
        missing = [k for k in ("id", "title", "body", "requester") if not d.get(k)]
        if missing:
            raise ValueError(f"ticket is missing required field(s): {', '.join(missing)}")
        atts = tuple(Attachment(str(a.get("name", "attachment")), str(a.get("text", "")))
                     for a in d.get("attachments", []) or [])
        return cls(
            id=str(d["id"]), title=str(d["title"]), body=str(d["body"]),
            requester=str(d["requester"]),
            affected_user=str(d.get("affected_user") or d["requester"]),
            attachments=atts, fields=dict(d.get("fields") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "body": self.body,
            "requester": self.requester, "affected_user": self.affected_user,
            "attachments": [{"name": a.name, "text": a.text} for a in self.attachments],
            "fields": self.fields,
        }

    def sha256(self) -> str:
        return sha256_hex(canonical_json(self.to_dict()))

    @property
    def scope_users(self) -> set[str]:
        """The only user identities an action in this ticket may target."""
        return {u for u in (self.affected_user, self.requester) if u}


@dataclass(frozen=True)
class Citation:
    file: str
    runbook_id: str
    section: str
    start_line: int
    end_line: int
    section_sha256: str
    snippet: str = ""

    @property
    def ref(self) -> str:
        return f"{self.file}#{self.section}"

    def pretty(self) -> str:
        return f"{self.file} § {self.section} (lines {self.start_line}-{self.end_line}, {self.runbook_id})"

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Citation":
        return cls(**{k: d[k] for k in
                      ("file", "runbook_id", "section", "start_line", "end_line", "section_sha256")},
                   snippet=d.get("snippet", ""))


@dataclass(frozen=True)
class Action:
    name: str
    params: dict[str, str]
    citation: Citation
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "params": dict(self.params),
                "citation": self.citation.to_dict(), "rationale": self.rationale}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Action":
        return cls(d["name"], dict(d["params"]), Citation.from_dict(d["citation"]), d.get("rationale", ""))

    def digest_view(self) -> dict[str, Any]:
        c = self.citation
        return {"name": self.name, "params": dict(self.params),
                "citation": {"file": c.file, "section": c.section, "section_sha256": c.section_sha256}}


@dataclass
class Plan:
    ticket_id: str
    ticket_sha256: str
    requester: str
    affected_user: str
    actions: list[Action]
    citations: list[Citation]
    summary: str
    provider: str
    created_at: str
    flags: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def digest(self) -> str:
        """What a human approves. Covers the ticket and every action + its grounding."""
        return sha256_hex(canonical_json({
            "ticket_id": self.ticket_id, "ticket_sha256": self.ticket_sha256,
            "actions": [a.digest_view() for a in self.actions],
        }))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id, "ticket_sha256": self.ticket_sha256,
            "requester": self.requester, "affected_user": self.affected_user,
            "actions": [a.to_dict() for a in self.actions],
            "citations": [c.to_dict() for c in self.citations],
            "summary": self.summary, "provider": self.provider, "created_at": self.created_at,
            "flags": self.flags, "rejected": self.rejected, "notes": self.notes,
            "plan_digest": self.digest(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Plan":
        return cls(
            ticket_id=d["ticket_id"], ticket_sha256=d["ticket_sha256"],
            requester=d["requester"], affected_user=d["affected_user"],
            actions=[Action.from_dict(a) for a in d["actions"]],
            citations=[Citation.from_dict(c) for c in d.get("citations", [])],
            summary=d.get("summary", ""), provider=d.get("provider", "unknown"),
            created_at=d.get("created_at", ""), flags=list(d.get("flags", [])),
            rejected=list(d.get("rejected", [])), notes=list(d.get("notes", [])),
        )
