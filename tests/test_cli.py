import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TICKET = ROOT / "examples/tickets/INC-1001-account-lockout.json"


def itsa(tmp, *args, check=False):
    cmd = [sys.executable, "-m", "it_service_agent", "--workdir", str(tmp / "wd"), *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, check=check)


def state(tmp):
    return json.loads((tmp / "wd/state.json").read_text())


def test_cli_end_to_end_requires_explicit_human_approval(tmp_path):
    t = itsa(tmp_path, "triage", str(TICKET), "--out", str(tmp_path / "plan.json"))
    assert t.returncode == 0 and "NOTHING HAS BEEN EXECUTED" in t.stdout
    assert "account-lockout.md § Remediation" in t.stdout
    plan = json.loads((tmp_path / "plan.json").read_text())

    # executing with no approval: refused, state untouched
    e0 = itsa(tmp_path, "execute", str(tmp_path / "plan.json"))
    assert "valid human approval required" in e0.stdout
    assert not (tmp_path / "wd/state.json").exists() or state(tmp_path)["users"]["jordan.lee@example.test"]["locked"] is True

    # wrong confirmation: no approval issued
    bad = itsa(tmp_path, "approve", str(tmp_path / "plan.json"), "--approver", "pat.ortiz@example.test",
               "--confirm-digest", "deadbeef")
    assert bad.returncode == 2 and not (tmp_path / "wd/approval-INC-1001.json").exists()

    # non-interactive without confirmation: refused
    nt = itsa(tmp_path, "approve", str(tmp_path / "plan.json"), "--approver", "pat.ortiz@example.test")
    assert nt.returncode == 2

    ok = itsa(tmp_path, "approve", str(tmp_path / "plan.json"), "--approver", "pat.ortiz@example.test",
              "--confirm-digest", plan["plan_digest"][:8])
    assert ok.returncode == 0, ok.stderr
    ex = itsa(tmp_path, "execute", str(tmp_path / "plan.json"), str(tmp_path / "wd/approval-INC-1001.json"))
    assert ex.returncode == 0 and "ALL ACTIONS SUCCEEDED" in ex.stdout
    assert state(tmp_path)["users"]["jordan.lee@example.test"]["locked"] is False

    replay = itsa(tmp_path, "execute", str(tmp_path / "plan.json"), str(tmp_path / "wd/approval-INC-1001.json"))
    assert "replay" in replay.stdout

    v = itsa(tmp_path, "verify-log")
    assert v.returncode == 0 and "OK" in v.stdout


def test_cli_detects_log_tampering(tmp_path):
    itsa(tmp_path, "triage", str(TICKET), "--out", str(tmp_path / "plan.json"))
    log = tmp_path / "wd/audit.jsonl"
    log.write_text(log.read_text().replace("jordan.lee", "someone.else", 1))
    v = itsa(tmp_path, "verify-log")
    assert v.returncode == 1 and "TAMPERING DETECTED" in v.stdout
