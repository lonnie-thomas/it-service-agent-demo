import json

import pytest

from conftest import LEAD
from it_service_agent.audit import AuditError, AuditLog


def full_run(env):
    plan = env.plan_for("INC-1001")
    env.agent.execute(plan, env.authority.issue(plan, LEAD))


def lines(env):
    return (env.tmp / "audit.jsonl").read_text().splitlines()


def write(env, ls):
    (env.tmp / "audit.jsonl").write_text("\n".join(ls) + "\n")


def test_clean_log_verifies_and_is_chained(env):
    full_run(env)
    res = env.audit.verify()
    assert res.ok and res.entries >= 8
    es = env.audit.entries()
    assert es[0]["prev_hash"] == "0" * 64
    assert all(es[i]["prev_hash"] == es[i - 1]["hash"] for i in range(1, len(es)))
    assert [e["seq"] for e in es] == list(range(1, len(es) + 1))


def test_expected_events_are_recorded_in_order(env):
    full_run(env)
    events = [e["event"] for e in env.audit.entries()]
    for needed in ["ticket.received", "retrieval.completed", "plan.proposed", "execution.requested",
                   "approval.verified", "approval.consumed", "action.result", "execution.completed"]:
        assert needed in events
    assert events.index("approval.consumed") < events.index("action.result")


def test_modified_entry_detected(env):
    full_run(env)
    ls = lines(env)
    e = json.loads(ls[3]); e["data"]["tampered"] = True
    ls[3] = json.dumps(e)
    write(env, ls)
    res = env.audit.verify()
    assert not res.ok and any("line 4" in x for x in res.errors)


def test_deleted_entry_detected(env):
    full_run(env)
    ls = lines(env)
    del ls[2]
    write(env, ls)
    assert not env.audit.verify().ok


def test_reordered_entries_detected(env):
    full_run(env)
    ls = lines(env)
    ls[2], ls[3] = ls[3], ls[2]
    write(env, ls)
    assert not env.audit.verify().ok


def test_inserted_forged_entry_detected(env):
    full_run(env)
    ls = lines(env)
    forged = json.loads(ls[2]); forged["event"] = "approval.verified"
    ls.insert(3, json.dumps(forged))
    write(env, ls)
    assert not env.audit.verify().ok


def test_rehashed_single_entry_still_breaks_chain(env):
    """An attacker who recomputes one entry's hash still breaks every later prev_hash link."""
    from it_service_agent.audit import _entry_hash
    full_run(env)
    ls = lines(env)
    e = json.loads(ls[2]); e["data"]["x"] = 1
    body = {k: e[k] for k in ("seq", "ts", "event", "actor", "data", "prev_hash")}
    e["hash"] = _entry_hash(e["prev_hash"], body)
    ls[2] = json.dumps(e)
    write(env, ls)
    assert not env.audit.verify().ok


def test_tail_truncation_needs_anchor(env):
    full_run(env)
    anchor = env.audit.anchor()
    ls = lines(env)
    write(env, ls[:-2])
    assert env.audit.verify().ok                   # chain alone cannot see tail truncation
    res = env.audit.verify(anchor)                 # an external anchor can
    assert not res.ok and any("truncated" in x for x in res.errors)


def test_rewritten_history_detected_against_anchor(env):
    full_run(env)
    anchor = env.audit.anchor()
    # attacker regenerates a fully consistent chain of the same length with different content
    other = AuditLog(env.tmp / "other.jsonl", env.clock)
    for i in range(anchor["count"]):
        other.append("noop", "attacker", {"i": i})
    (env.tmp / "audit.jsonl").write_text((env.tmp / "other.jsonl").read_text())
    assert env.audit.verify().ok and not env.audit.verify(anchor).ok


def test_append_refuses_unreadable_tail(env):
    full_run(env)
    with open(env.tmp / "audit.jsonl", "a") as fh:
        fh.write("garbage-not-json\n")
    with pytest.raises(AuditError):
        env.audit.append("x", "y")


def test_execution_fails_closed_when_log_is_tampered(env):
    plan = env.plan_for("INC-1001")
    approval = env.authority.issue(plan, LEAD)
    ls = lines(env)
    e = json.loads(ls[0]); e["actor"] = "someone-else"; ls[0] = json.dumps(e)
    write(env, ls)
    rep = env.agent.execute(plan, approval)
    assert not rep.approved and any("integrity" in r for r in rep.refusal_reasons)
    assert env.executor.ledger == []
    assert env.executor.state["users"]["jordan.lee@example.test"]["locked"] is True


def test_log_is_not_rewritten_on_append(env):
    env.plan_for("INC-1001")
    before = lines(env)
    env.plan_for("INC-1002")
    after = lines(env)
    assert after[:len(before)] == before   # append-only: earlier bytes unchanged
