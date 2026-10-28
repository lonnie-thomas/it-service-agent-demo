"""Command line interface.

  itsa triage  TICKET            -> writes a plan (never executes anything)
  itsa approve PLAN              -> a HUMAN reviews the plan and signs an approval (typed confirmation)
  itsa execute PLAN [APPROVAL]   -> executes via the mock executor ONLY if the approval verifies
  itsa verify-log                -> checks the audit hash chain (optionally against an anchor)
  itsa manifest                  -> re-pins runbook hashes after a reviewed runbook change
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agent import ITServiceAgent
from .approvals import ApprovalAuthority, ApproverRegistry
from .audit import AuditLog
from .executor import MockExecutor
from .llm import ProviderError, provider_from_env
from .loader import load_ticket
from .models import Plan
from .retrieval import RunbookIntegrityError, RunbookStore, write_manifest

ROOT = Path(__file__).resolve().parents[2]


def _paths(a):
    wd = Path(a.workdir)
    return wd, wd / "audit.jsonl", wd / "state.json"


def _build(a) -> ITServiceAgent:
    wd, audit_path, state_path = _paths(a)
    wd.mkdir(parents=True, exist_ok=True)
    store = RunbookStore(a.runbooks)
    registry = ApproverRegistry.from_file(a.approvers)
    return ITServiceAgent(store, MockExecutor(state_path=state_path), AuditLog(audit_path),
                          ApprovalAuthority(registry), provider_from_env(a.provider))


def cmd_triage(a) -> int:
    agent = _build(a)
    plan = agent.triage(load_ticket(a.ticket))
    out = Path(a.out or Path(a.workdir) / f"plan-{plan.ticket_id}.json")
    out.write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")
    print(agent.request_approval_text(plan))
    print("\nCitations:")
    for c in plan.citations:
        print(f"  - {c.pretty()}")
    print(f"\nPlan written to {out}\nNOTHING HAS BEEN EXECUTED. A human must run `itsa approve` next.")
    return 0


def cmd_approve(a) -> int:
    agent = _build(a)
    plan = Plan.from_dict(json.loads(Path(a.plan).read_text(encoding="utf-8")))
    print(agent.request_approval_text(plan))
    digest = plan.digest()
    if not a.confirm_digest:
        if not sys.stdin.isatty():
            print("\nRefusing: no interactive terminal and no --confirm-digest given.", file=sys.stderr)
            return 2
        typed = input(f"\n{a.approver}: to approve exactly this plan, type the first 8 characters of its digest: ")
    else:
        typed = a.confirm_digest
    if typed.strip() != digest[:8]:
        print("Digest confirmation did not match; no approval issued.", file=sys.stderr)
        return 2
    try:
        approval = agent.authority.issue(plan, a.approver, a.ttl)
    except PermissionError as exc:
        print(f"Not issued: {exc}", file=sys.stderr)
        return 2
    agent.audit.append("approval.issued", a.approver, {"plan_digest": digest, "approval_id": approval["approval_id"],
                                                         "expires_at": approval["expires_at"]})
    out = Path(a.out or Path(a.workdir) / f"approval-{plan.ticket_id}.json")
    out.write_text(json.dumps(approval, indent=2), encoding="utf-8")
    print(f"Approval {approval['approval_id']} by {a.approver} valid until {approval['expires_at']} -> {out}")
    return 0


def cmd_execute(a) -> int:
    agent = _build(a)
    plan = Plan.from_dict(json.loads(Path(a.plan).read_text(encoding="utf-8")))
    approval = json.loads(Path(a.approval).read_text(encoding="utf-8")) if a.approval else None
    report = agent.execute(plan, approval)
    print(report.summary())
    for o in report.outcomes:
        print(f"  {o.index}. {o.name} {o.params}: {o.status} - {o.detail}")
    for r in report.refusal_reasons:
        print(f"  refused: {r}")
    return 0 if report.all_succeeded or not any(o.status in ('failed', 'denied') for o in report.outcomes) else 1


def cmd_verify(a) -> int:
    _, audit_path, _ = _paths(a)
    log = AuditLog(audit_path)
    anchor = json.loads(Path(a.anchor).read_text()) if a.anchor else None
    res = log.verify(anchor)
    print(f"audit log: {res.entries} entries, head {res.head[:16]}…  -> {'OK' if res.ok else 'TAMPERING DETECTED'}")
    for e in res.errors:
        print("  -", e)
    if a.write_anchor:
        Path(a.write_anchor).write_text(json.dumps(log.anchor()))
        print(f"anchor written to {a.write_anchor} (store it somewhere the agent cannot write)")
    return 0 if res.ok else 1


def cmd_manifest(a) -> int:
    print(f"wrote {write_manifest(a.runbooks)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="itsa", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", default=os.environ.get("ITSA_WORKDIR", ".itsa"))
    ap.add_argument("--runbooks", default=os.environ.get("ITSA_RUNBOOKS", str(ROOT / "runbooks")))
    ap.add_argument("--approvers", default=os.environ.get("ITSA_APPROVERS", str(ROOT / "examples/config/approvers.demo.json")))
    ap.add_argument("--provider", default=None, help="mock (default) | azure | openai (or env LLM_PROVIDER)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage"); t.add_argument("ticket"); t.add_argument("--out"); t.set_defaults(fn=cmd_triage)
    p = sub.add_parser("approve"); p.add_argument("plan"); p.add_argument("--approver", required=True)
    p.add_argument("--confirm-digest", help="first 8 chars of the plan digest (what a human types)")
    p.add_argument("--ttl", type=int, default=None); p.add_argument("--out"); p.set_defaults(fn=cmd_approve)
    e = sub.add_parser("execute"); e.add_argument("plan"); e.add_argument("approval", nargs="?"); e.set_defaults(fn=cmd_execute)
    v = sub.add_parser("verify-log"); v.add_argument("--anchor"); v.add_argument("--write-anchor"); v.set_defaults(fn=cmd_verify)
    m = sub.add_parser("manifest"); m.set_defaults(fn=cmd_manifest)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (RunbookIntegrityError, ProviderError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
