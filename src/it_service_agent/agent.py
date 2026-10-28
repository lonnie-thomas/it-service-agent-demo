"""The IT service agent: triage -> (human approval) -> controlled execution -> honest report.

Control flow guarantees (each is covered by tests):
  * Nothing the LLM says is trusted: every proposed action is re-validated against the allowlist,
    the ticket scope, and the exact ACTION template in the runbook section it cites.
  * No state-changing action runs without a valid, signed, unexpired, single-use human approval
    bound to the exact plan digest. There is no auto-approve path.
  * Every step is written to a hash-chained audit log; execution fails closed if that log is broken.
  * Success is reported only from the executor's result AND an independent post-condition check.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import policy
from .approvals import ApprovalAuthority
from .audit import AuditLog
from .executor import ExecutionGrant, MockExecutor
from .llm import MockProvider, PlanProvider, ProposalRequest, ProviderError
from .models import Action, Plan, Ticket
from .retrieval import RunbookStore
from .sanitize import inspect_ticket, redact
from .util import Clock


@dataclass
class ActionOutcome:
    index: int
    name: str
    params: dict[str, str]
    status: str    # succeeded | failed | denied | skipped
    detail: str


@dataclass
class ExecutionReport:
    ticket_id: str
    plan_digest: str
    approval_id: str | None
    approved: bool
    outcomes: list[ActionOutcome] = field(default_factory=list)
    refusal_reasons: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {"succeeded": 0, "failed": 0, "denied": 0, "skipped": 0}
        for o in self.outcomes:
            c[o.status] += 1
        return c

    @property
    def all_succeeded(self) -> bool:
        return bool(self.outcomes) and all(o.status == "succeeded" for o in self.outcomes)

    def summary(self) -> str:
        c = self.counts
        total = len(self.outcomes)
        head = "ALL ACTIONS SUCCEEDED (verified)" if self.all_succeeded else "NOT FULLY COMPLETED"
        if total == 0:
            head = "NO ACTIONS EXECUTED"
        return (f"{head}: {c['succeeded']}/{total} succeeded, {c['failed']} failed, "
                f"{c['denied']} denied, {c['skipped']} skipped.")

    def to_dict(self) -> dict[str, Any]:
        return {"ticket_id": self.ticket_id, "plan_digest": self.plan_digest, "approval_id": self.approval_id,
                "approved": self.approved, "refusal_reasons": self.refusal_reasons, "counts": self.counts,
                "all_succeeded": self.all_succeeded, "summary": self.summary(),
                "outcomes": [o.__dict__ for o in self.outcomes]}


class ITServiceAgent:
    def __init__(self, store: RunbookStore, executor: MockExecutor, audit: AuditLog,
                 authority: ApprovalAuthority, provider: PlanProvider | None = None, clock: Clock | None = None):
        self.store, self.executor, self.audit, self.authority = store, executor, audit, authority
        self.provider = provider or MockProvider()
        self.clock = clock or Clock()

    # ---------------------------------------------------------------- triage (read-only)
    def triage(self, ticket: Ticket) -> Plan:
        self.audit.append("ticket.received", "intake", {
            "ticket_id": ticket.id, "ticket_sha256": ticket.sha256(), "requester": ticket.requester,
            "affected_user": ticket.affected_user, "title": redact(ticket.title)[:200],
            "attachments": [a.name for a in ticket.attachments]})
        clean, flags = inspect_ticket(ticket)
        if flags:
            self.audit.append("injection.flagged", "sanitizer", {"ticket_id": ticket.id, "flags": flags})
        query = clean["title"] + " " + clean["title"] + " " + clean["body"]
        sections = self.store.search(query)
        self.audit.append("retrieval.completed", "retriever", {
            "ticket_id": ticket.id, "sections": [{"ref": s.ref, "runbook": s.runbook_id,
                                                  "lines": f"{s.start_line}-{s.end_line}"} for s in sections]})
        notes: list[str] = []
        try:
            proposal = self.provider.propose(ProposalRequest(ticket, clean, sections))
        except ProviderError as exc:
            notes.append(f"provider error: {exc}")
            self.audit.append("provider.error", "agent", {"ticket_id": ticket.id, "error": str(exc)[:300]})
            proposal = None

        actions: list[Action] = []
        rejected: list[dict[str, Any]] = []
        by_ref = {s.ref: s for s in sections}
        if proposal is not None:
            notes.extend(proposal.notes)
            for pa in proposal.actions:
                reasons = self._ground_and_validate(pa.name, pa.params, pa.section_ref, by_ref, ticket)
                if reasons:
                    rejected.append({"name": pa.name, "params": pa.params, "section_ref": pa.section_ref,
                                     "reasons": reasons})
                else:
                    actions.append(Action(pa.name, dict(pa.params), by_ref[pa.section_ref].citation(), pa.rationale))
        summary = redact(proposal.summary) if proposal else "Provider unavailable; routing to a human technician."
        plan = Plan(ticket.id, ticket.sha256(), ticket.requester, ticket.affected_user, actions,
                    [s.citation() for s in sections], summary, self.provider.name, self.clock.iso(),
                    flags, rejected, notes)
        self.audit.append("plan.proposed", "agent", {
            "ticket_id": ticket.id, "plan_digest": plan.digest(), "provider": plan.provider,
            "actions": [{"name": a.name, "params": a.params, "cite": a.citation.ref} for a in actions],
            "rejected": rejected, "risk": policy.plan_risk([a.name for a in actions])})
        return plan

    def _ground_and_validate(self, name: str, params: dict[str, str], ref: str,
                             by_ref: dict, ticket: Ticket) -> list[str]:
        reasons = policy.validate_action(name, params, scope_users=ticket.scope_users)
        sec = by_ref.get(ref)
        if sec is None:
            reasons.append(f"cited section '{ref}' was not retrieved for this ticket (ungrounded)")
            return reasons
        tpl = next((t for t in sec.actions if t.name == name), None)
        if tpl is None:
            reasons.append(f"action '{name}' is not an ACTION template in the cited section (ungrounded)")
            return reasons
        if set(tpl.params) != set(params):
            reasons.append("parameters do not match the runbook template")
        for k, v in tpl.params.items():
            if not (v.startswith("{") and v.endswith("}")) and params.get(k) != v:
                reasons.append(f"parameter '{k}' must equal the runbook literal '{v}'")
        return reasons

    # ---------------------------------------------------------------- approval helpers
    def request_approval_text(self, plan: Plan) -> str:
        """What the human approver is shown. Includes risk, citations and any injection flags."""
        lines = [f"Ticket {plan.ticket_id}: {redact(plan.summary)}",
                 f"Plan digest: {plan.digest()}",
                 f"Plan risk: {policy.plan_risk([a.name for a in plan.actions])}"]
        for i, a in enumerate(plan.actions, 1):
            kind = "STATE-CHANGING" if policy.is_state_changing(a.name) else "read-only"
            lines.append(f"  {i}. [{kind}] {a.name} {a.params}  <- {a.citation.pretty()}")
        for f in plan.flags:
            lines.append(f"  ! flag: {f['type']} / {f['detail']} in {f['source']}")
        for r in plan.rejected:
            lines.append(f"  x rejected proposal: {r['name']} {r['params']} -> {'; '.join(r['reasons'])}")
        return "\n".join(lines)

    # ---------------------------------------------------------------- execution (gated)
    def execute(self, plan: Plan, approval: dict[str, Any] | None = None) -> ExecutionReport:
        digest = plan.digest()
        report = ExecutionReport(plan.ticket_id, digest, (approval or {}).get("approval_id") if isinstance(approval, dict) else None, False)
        self.audit.append("execution.requested", "agent", {
            "ticket_id": plan.ticket_id, "plan_digest": digest, "actions": [a.name for a in plan.actions]})

        # Fail closed if the audit trail is not trustworthy.
        integrity = self.audit.verify()
        if not integrity.ok:
            report.refusal_reasons.append("audit log integrity check failed: " + "; ".join(integrity.errors[:3]))
            for i, a in enumerate(plan.actions, 1):
                report.outcomes.append(ActionOutcome(i, a.name, a.params, "skipped", "audit log integrity failure"))
            return report

        # Re-validate the plan we were handed (it may have been edited on disk since triage).
        violations = []
        for a in plan.actions:
            v = policy.validate_action(a.name, a.params)
            if v:
                violations.append(f"{a.name}: {'; '.join(v)}")
        if violations:
            self.audit.append("plan.rejected", "approval-gate", {"plan_digest": digest, "violations": violations})
            for i, a in enumerate(plan.actions, 1):
                report.outcomes.append(ActionOutcome(i, a.name, a.params, "denied", "plan failed policy re-validation"))
            report.refusal_reasons.extend(violations)
            return report

        needs_approval = any(policy.is_state_changing(a.name) for a in plan.actions)
        grant: ExecutionGrant | None = None
        if needs_approval:
            consumed = self.audit.consumed_approvals()
            outcome = self.authority.verify(approval, plan, consumed)
            if not outcome.ok:
                self.audit.append("approval.rejected", "approval-gate", {
                    "plan_digest": digest, "approver": outcome.approver, "approval_id": outcome.approval_id,
                    "reasons": outcome.reasons})
                report.refusal_reasons.extend(outcome.reasons)
            else:
                # Consume BEFORE acting so a crash mid-run cannot leave a replayable approval.
                self.audit.append("approval.verified", "approval-gate", {
                    "plan_digest": digest, "approver": outcome.approver, "approval_id": outcome.approval_id})
                self.audit.append("approval.consumed", "approval-gate", {
                    "plan_digest": digest, "approval_id": outcome.approval_id, "nonce": outcome.nonce})
                grant = ExecutionGrant(digest, outcome.approval_id or "")
                report.approved = True
                report.approval_id = outcome.approval_id

        halted = False
        for i, a in enumerate(plan.actions, 1):
            changing = policy.is_state_changing(a.name)
            if halted:
                report.outcomes.append(ActionOutcome(i, a.name, a.params, "skipped", "halted after an earlier failure"))
                continue
            if changing and grant is None:
                report.outcomes.append(ActionOutcome(i, a.name, a.params, "skipped", "valid human approval required"))
                self.audit.append("action.skipped", "agent", {"plan_digest": digest, "index": i, "action": a.name,
                                                              "reason": "no valid approval"})
                continue
            res = self.executor.execute(a.name, a.params, grant if changing else None)
            status, detail = res.status, res.detail
            if status == "success":
                if changing and not self.executor.check_postcondition(a.name, a.params):
                    status, detail = "failed", "executor reported success but post-condition check failed"
                else:
                    status = "succeeded"
            report.outcomes.append(ActionOutcome(i, a.name, a.params, status, detail))
            self.audit.append("action.result", "executor", {
                "plan_digest": digest, "index": i, "action": a.name, "params": a.params,
                "status": status, "detail": detail})
            if status in ("failed", "denied"):
                halted = True
        self.audit.append("execution.completed", "agent", {
            "plan_digest": digest, "counts": report.counts, "all_succeeded": report.all_succeeded})
        return report
