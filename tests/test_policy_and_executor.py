import pytest

from it_service_agent import policy
from it_service_agent.executor import ExecutionGrant, MockExecutor

GRANT = ExecutionGrant("d" * 64, "apr-test")


@pytest.mark.parametrize("name,params", [
    ("delete_user", {"user": "sam.rivera@example.test"}),
    ("disable_conditional_access", {}),
    ("run_powershell", {"cmd": "whoami"}),
])
def test_unlisted_actions_denied_by_default(name, params):
    assert policy.validate_action(name, params)


def test_param_validation():
    ok = {"user": "jordan.lee@example.test"}
    assert policy.validate_action("unlock_account", ok) == []
    assert policy.validate_action("unlock_account", {"user": "x@evil.com"})
    assert policy.validate_action("unlock_account", {**ok, "extra": "1"})
    assert policy.validate_action("unlock_account", {})


@pytest.mark.parametrize("user", ["admin.breakglass@example.test", "svc-backup@example.test"])
def test_protected_accounts_out_of_scope(user):
    assert any("protected" in p for p in policy.validate_action("unlock_account", {"user": user}))


def test_privileged_groups_and_critical_services_blocked():
    assert policy.validate_action("add_user_to_group", {"user": "sam.rivera@example.test", "group": "Domain-Admins"})
    assert policy.validate_action("restart_service", {"service": "mail-relay"})
    assert policy.validate_action("restart_service", {"service": "vpn-gateway"})
    assert policy.validate_action("check_service_status", {"service": "mail-relay"}) == []


def test_scope_users_enforced():
    assert policy.validate_action("unlock_account", {"user": "sam.rivera@example.test"},
                                  scope_users={"jordan.lee@example.test"})


def test_plan_risk_ignores_read_only():
    assert policy.plan_risk(["check_service_status"]) == "low"
    assert policy.plan_risk(["check_account_status", "revoke_user_sessions"]) == "medium"
    assert policy.plan_risk(["unlock_account", "add_user_to_group"]) == "high"


def test_executor_refuses_state_change_without_grant():
    ex = MockExecutor()
    r = ex.execute("unlock_account", {"user": "jordan.lee@example.test"})
    assert r.status == "denied" and ex.state["users"]["jordan.lee@example.test"]["locked"] is True


def test_executor_enforces_allowlist_independently():
    ex = MockExecutor()
    r = ex.execute("add_user_to_group", {"user": "sam.rivera@example.test", "group": "Domain-Admins"}, GRANT)
    assert r.status == "denied"
    assert ex.state["users"]["sam.rivera@example.test"]["groups"] == []
    assert ex.execute("format_disk", {}, GRANT).status == "denied"


def test_executor_ledger_records_every_call():
    ex = MockExecutor()
    ex.execute("unlock_account", {"user": "jordan.lee@example.test"})
    ex.execute("unlock_account", {"user": "jordan.lee@example.test"}, GRANT)
    assert [e["status"] for e in ex.ledger] == ["denied", "success"]
    assert [e["granted"] for e in ex.ledger] == [False, True]


def test_executor_state_persists_across_instances(tmp_path):
    p = tmp_path / "state.json"
    MockExecutor(state_path=p).execute("clear_print_queue", {"printer": "PRN-FL2-01"}, GRANT)
    again = MockExecutor(state_path=p)
    assert again.state["printers"]["PRN-FL2-01"]["queue"] == 0 and len(again.ledger) == 1
