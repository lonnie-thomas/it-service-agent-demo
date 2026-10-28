import json

from conftest import LEAD, MANAGER

JORDAN = "jordan.lee@example.test"


def state(env, user=JORDAN):
    return env.executor.state["users"][user]


def test_triage_never_changes_state(env):
    before = env.executor.snapshot()
    env.plan_for("INC-1001")
    assert env.executor.snapshot() == before and env.executor.ledger == []


def test_happy_path_with_human_approval(env):
    plan = env.plan_for("INC-1001")
    approval = env.authority.issue(plan, LEAD)
    report = env.agent.execute(plan, approval)
    assert report.approved and report.all_succeeded
    assert state(env)["locked"] is False
    assert [o.name for o in report.outcomes] == ["check_account_status", "unlock_account"]


def test_no_approval_means_no_state_change(env):
    plan = env.plan_for("INC-1001")
    report = env.agent.execute(plan, None)
    assert not report.approved and not report.all_succeeded
    assert state(env)["locked"] is True
    by_name = {o.name: o for o in report.outcomes}
    assert by_name["unlock_account"].status == "skipped"
    assert by_name["check_account_status"].status == "succeeded"   # read-only is allowed
    assert all(e["action"] != "unlock_account" for e in env.executor.ledger)


def test_high_risk_plan_needs_manager_clearance(env):
    plan = env.plan_for("INC-1004")
    rep = env.agent.execute(plan, env.authority.issue(plan, LEAD))
    assert not rep.approved and any("clearance" in r for r in rep.refusal_reasons)
    plan2 = env.plan_for("INC-1004")
    rep2 = env.agent.execute(plan2, env.authority.issue(plan2, MANAGER))
    assert rep2.all_succeeded


def test_plan_edited_after_approval_is_rejected(env):
    plan = env.plan_for("INC-1002")
    approval = env.authority.issue(plan, LEAD)
    d = plan.to_dict()
    d["actions"][0]["params"]["printer"] = "PRN-FL3-02"
    from it_service_agent.models import Plan
    rep = env.agent.execute(Plan.from_dict(d), approval)
    assert not rep.approved and any("different plan" in r for r in rep.refusal_reasons)
    assert env.executor.state["printers"]["PRN-FL2-01"]["queue"] == 17


def test_plan_edited_to_non_allowlisted_action_is_rejected(env):
    from it_service_agent.models import Plan
    plan = env.plan_for("INC-1001")
    d = plan.to_dict()
    d["actions"][1] = dict(d["actions"][1], name="delete_user")
    rep = env.agent.execute(Plan.from_dict(d), env.authority.issue(plan, LEAD))
    assert all(o.status == "denied" for o in rep.outcomes) and env.executor.ledger == []


def test_failure_is_reported_as_failure(make_env):
    env = make_env(fail_actions={"unlock_account"})
    plan = env.plan_for("INC-1001")
    rep = env.agent.execute(plan, env.authority.issue(plan, LEAD))
    assert not rep.all_succeeded and rep.counts["failed"] == 1
    assert rep.summary().startswith("NOT FULLY COMPLETED")
    assert state(env)["locked"] is True


def test_silent_noop_is_caught_by_postcondition_check(make_env):
    env = make_env(noop_actions={"unlock_account"})
    plan = env.plan_for("INC-1001")
    rep = env.agent.execute(plan, env.authority.issue(plan, LEAD))
    bad = [o for o in rep.outcomes if o.name == "unlock_account"][0]
    assert bad.status == "failed" and "post-condition" in bad.detail and not rep.all_succeeded


def test_halts_after_first_failure(make_env):
    env = make_env(fail_actions={"check_account_status"})
    plan = env.plan_for("INC-1001")
    rep = env.agent.execute(plan, env.authority.issue(plan, LEAD))
    assert [o.status for o in rep.outcomes] == ["failed", "skipped"]
    assert state(env)["locked"] is True


def test_mock_provider_is_deterministic(env):
    a = env.plan_for("INC-1003")
    b = env.plan_for("INC-1003")
    assert a.digest() == b.digest()


def test_phishing_ticket_executes_nothing(env):
    plan = env.plan_for("INC-1006")
    rep = env.agent.execute(plan, None)
    assert rep.outcomes == [] and rep.summary().startswith("NO ACTIONS EXECUTED")


def test_protected_account_ticket_yields_no_action(env):
    from it_service_agent.models import Ticket
    t = Ticket.from_dict({"id": "INC-50", "title": "Locked out of my account", "body": "My account is locked after too many attempts.",
                          "requester": "admin.breakglass@example.test"})
    plan = env.agent.triage(t)
    assert plan.actions == [] and plan.rejected
    assert any("protected" in r for rej in plan.rejected for r in rej["reasons"])


def test_approval_request_text_shows_citations_and_flags(env):
    plan = env.plan_for("INC-1005")
    text = env.agent.request_approval_text(plan)
    assert "account-lockout.md § Remediation" in text and "flag:" in text and "STATE-CHANGING" in text
