"""Human approval gate: signed, time-boxed, single-use approvals bound to one exact plan.

DEMO CAVEAT: signatures are HMAC-SHA256 with per-approver keys held in a local registry file.
That is symmetric, so whoever can verify can also forge. In production the approval would be
issued by a service OUTSIDE the agent's trust boundary (for example an Entra ID-authenticated
approval app or ServiceNow approval record) and signed asymmetrically. See THREAT_MODEL.md.
"""
from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from .models import Plan
from .policy import RISK_ORDER, plan_risk
from .util import Clock, canonical_json, fmt_iso, parse_iso

SIGNED_FIELDS = ("approval_id", "plan_digest", "ticket_id", "approver", "issued_at", "expires_at", "nonce")
MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 900


@dataclass
class Approver:
    id: str
    role: str
    max_risk: str          # highest plan risk this approver may authorise
    key: bytes


class ApproverRegistry:
    """Who may approve what. Loaded from a JSON file (synthetic demo keys only)."""

    def __init__(self, approvers: dict[str, Approver]):
        self._a = approvers

    @classmethod
    def from_file(cls, path: str | Path) -> "ApproverRegistry":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls({k: Approver(k, v["role"], v["max_risk"], bytes.fromhex(v["key_hex"]))
                    for k, v in raw["approvers"].items()})

    def get(self, approver_id: str) -> Approver | None:
        return self._a.get(approver_id)

    def ids(self) -> list[str]:
        return sorted(self._a)


def _sign(key: bytes, fields: dict[str, Any]) -> str:
    payload = canonical_json({k: fields[k] for k in SIGNED_FIELDS})
    return hmac.new(key, payload, sha256).hexdigest()


@dataclass
class VerifyOutcome:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    approver: str | None = None
    approval_id: str | None = None
    nonce: str | None = None


class ApprovalAuthority:
    def __init__(self, registry: ApproverRegistry, clock: Clock | None = None,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS, clock_skew_seconds: int = 30):
        self.registry = registry
        self.clock = clock or Clock()
        self.ttl = min(ttl_seconds, MAX_TTL_SECONDS)
        self.skew = clock_skew_seconds

    # -- issuing: called only after a human has reviewed the plan and confirmed ----------
    def issue(self, plan: Plan, approver_id: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        approver = self.registry.get(approver_id)
        if approver is None:
            raise PermissionError(f"unknown approver '{approver_id}'")
        now = self.clock.now()
        ttl = min(ttl_seconds or self.ttl, MAX_TTL_SECONDS)
        body = {
            "approval_id": "apr-" + secrets.token_hex(6),
            "plan_digest": plan.digest(), "ticket_id": plan.ticket_id,
            "approver": approver_id, "issued_at": fmt_iso(now),
            "expires_at": fmt_iso(now + timedelta(seconds=ttl)),
            "nonce": secrets.token_hex(12),
        }
        body["signature"] = _sign(approver.key, body)
        return body

    # -- verifying: called by the agent before ANY state-changing action ------------------
    def verify(self, approval: Any, plan: Plan, consumed: set[str]) -> VerifyOutcome:
        out = VerifyOutcome(ok=False)
        if not isinstance(approval, dict):
            out.reasons.append("no approval presented")
            return out
        missing = [f for f in SIGNED_FIELDS + ("signature",) if not approval.get(f)]
        if missing:
            out.reasons.append(f"approval missing field(s): {missing}")
            return out
        out.approver, out.approval_id, out.nonce = approval["approver"], approval["approval_id"], approval["nonce"]
        approver = self.registry.get(approval["approver"])
        if approver is None:
            out.reasons.append(f"approver '{approval['approver']}' is not a registered approver")
            return out
        expected = _sign(approver.key, approval)
        if not hmac.compare_digest(expected, str(approval["signature"])):
            out.reasons.append("signature invalid (approval altered or not signed by the approver's key)")
            return out
        if approval["plan_digest"] != plan.digest() or approval["ticket_id"] != plan.ticket_id:
            out.reasons.append("approval is bound to a different plan/ticket than the one being executed")
        try:
            issued, expires = parse_iso(approval["issued_at"]), parse_iso(approval["expires_at"])
            now = self.clock.now()
            if now >= expires:
                out.reasons.append(f"approval expired at {approval['expires_at']}")
            if issued - timedelta(seconds=self.skew) > now:
                out.reasons.append("approval issued in the future")
            if (expires - issued).total_seconds() > MAX_TTL_SECONDS:
                out.reasons.append(f"approval lifetime exceeds the {MAX_TTL_SECONDS}s maximum")
        except ValueError:
            out.reasons.append("approval timestamps are malformed")
        need = plan_risk([a.name for a in plan.actions])
        if RISK_ORDER[approver.max_risk] < RISK_ORDER[need]:
            out.reasons.append(f"approver clearance '{approver.max_risk}' is below plan risk '{need}'")
        if approval["approver"] in {plan.requester, plan.affected_user}:
            out.reasons.append("separation of duties: requester/affected user cannot approve their own ticket")
        if approval["approval_id"] in consumed or approval["nonce"] in consumed:
            out.reasons.append("approval already used (replay)")
        out.ok = not out.reasons
        return out
