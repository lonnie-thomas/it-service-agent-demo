"""Forged, expired, replayed, mis-bound and under-privileged approvals must all be refused."""
import copy

import pytest

from conftest import ANALYST, LEAD, MANAGER


def run(env, plan, approval):
    rep = env.agent.execute(plan, approval)
    return rep, " | ".join(rep.refusal_reasons)


def locked(env):
    return env.executor.state["users"]["jordan.lee@example.test"]["locked"]


def test_missing_approval(env):
    rep, why = run(env, env.plan_for("INC-1001"), None)
    assert not rep.approved and "no approval presented" in why and locked(env)


def test_malformed_approval(env):
    rep, why = run(env, env.plan_for("INC-1001"), {"approver": LEAD})
    assert not rep.approved and "missing field" in why and locked(env)


def test_tampered_signature(env):
    plan = env.plan_for("INC-1001")
    a = env.authority.issue(plan, LEAD)
    a["signature"] = a["signature"][:-1] + ("0" if a["signature"][-1] != "0" else "1")
    rep, why = run(env, plan, a)
    assert not rep.approved and "signature invalid" in why and locked(env)


def test_tampered_field_invalidates_signature(env):
    plan = env.plan_for("INC-1001")
    a = env.authority.issue(plan, LEAD)
    a["expires_at"] = "2099-01-01T00:00:00Z"   # try to extend lifetime
    rep, why = run(env, plan, a)
    assert not rep.approved and "signature invalid" in why


def test_approver_swapped_to_more_privileged_identity(env):
    plan = env.plan_for("INC-1004")
    a = env.authority.issue(plan, LEAD)
    a["approver"] = MANAGER   # claim a manager signed it
    rep, why = run(env, plan, a)
    assert not rep.approved and "signature invalid" in why


def test_unknown_approver(env):
    plan = env.plan_for("INC-1001")
    a = env.authority.issue(plan, LEAD)
    a["approver"] = "mallory@example.test"
    rep, why = run(env, plan, a)
    assert not rep.approved and "not a registered approver" in why


def test_expired_approval(env):
    plan = env.plan_for("INC-1001")
    a = env.authority.issue(plan, LEAD, ttl_seconds=60)
    env.clock.advance(61)
    rep, why = run(env, plan, a)
    assert not rep.approved and "expired" in why and locked(env)


def test_not_yet_expired_approval_still_works(env):
    plan = env.plan_for("INC-1001")
    a = env.authority.issue(plan, LEAD, ttl_seconds=60)
    env.clock.advance(59)
    assert env.agent.execute(plan, a).approved


def test_ttl_is_capped(env):
    plan = env.plan_for("INC-1001")
    a = env.authority.issue(plan, LEAD, ttl_seconds=10_000_000)
    from it_service_agent.util import parse_iso
    assert (parse_iso(a["expires_at"]) - parse_iso(a["issued_at"])).total_seconds() <= 3600


def test_replay_of_consumed_approval(env):
    plan = env.plan_for("INC-1002")
    a = env.authority.issue(plan, LEAD)
    assert env.agent.execute(plan, a).all_succeeded
    env.executor.state["printers"]["PRN-FL2-01"]["queue"] = 5   # problem comes back
    rep, why = run(env, plan, a)
    assert not rep.approved and "replay" in why
    assert env.executor.state["printers"]["PRN-FL2-01"]["queue"] == 5


def test_approval_for_one_ticket_cannot_authorise_another(env):
    p1, p2 = env.plan_for("INC-1001"), env.plan_for("INC-1007")
    a = env.authority.issue(p1, LEAD)
    rep, why = run(env, p2, a)
    assert not rep.approved and "different plan" in why


def test_insufficient_clearance(env):
    plan = env.plan_for("INC-1004")          # high risk
    rep, why = run(env, plan, env.authority.issue(plan, ANALYST))
    assert not rep.approved and "clearance" in why
    plan2 = env.plan_for("INC-1007")         # medium risk
    rep2, why2 = run(env, plan2, env.authority.issue(plan2, ANALYST))
    assert not rep2.approved and "clearance" in why2


def test_separation_of_duties(env, make_env):
    from it_service_agent.models import Ticket
    # requester is also a registered approver: they must not approve their own ticket
    t = Ticket.from_dict({"id": "INC-60", "title": "Locked out of my account",
                          "body": "my account is locked after too many sign-in attempts",
                          "requester": LEAD})
    env.executor.state["users"][LEAD] = {"locked": True, "sessions": 0, "groups": []}
    plan = env.agent.triage(t)
    rep, why = run(env, plan, env.authority.issue(plan, LEAD))
    assert not rep.approved and "separation of duties" in why


def test_unknown_approver_cannot_even_be_issued(env):
    plan = env.plan_for("INC-1001")
    with pytest.raises(PermissionError):
        env.authority.issue(plan, "mallory@example.test")


def test_rejections_are_audited(env):
    plan = env.plan_for("INC-1001")
    env.agent.execute(plan, None)
    assert any(e["event"] == "approval.rejected" for e in env.audit.entries())
