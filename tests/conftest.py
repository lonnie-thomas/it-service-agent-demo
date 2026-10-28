from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from it_service_agent import (ApprovalAuthority, ApproverRegistry, AuditLog, ITServiceAgent, MockExecutor,
                              RunbookStore, load_ticket)
from it_service_agent.util import Clock

ROOT = Path(__file__).resolve().parents[1]
TICKETS = ROOT / "examples" / "tickets"
APPROVERS = ROOT / "examples" / "config" / "approvers.demo.json"

LEAD = "pat.ortiz@example.test"       # clearance: medium
MANAGER = "riley.chen@example.test"   # clearance: high
ANALYST = "jamie.park@example.test"   # clearance: low


class Env:
    """Everything a test needs, wired with an adjustable clock and tmp paths."""

    def __init__(self, tmp: Path, executor_kwargs: dict | None = None):
        self.tmp = tmp
        self.clock = Clock()
        self.registry = ApproverRegistry.from_file(APPROVERS)
        self.audit = AuditLog(tmp / "audit.jsonl", self.clock)
        self.executor = MockExecutor(clock=self.clock, **(executor_kwargs or {}))
        self.authority = ApprovalAuthority(self.registry, self.clock)
        self.store = RunbookStore(ROOT / "runbooks")
        self.agent = ITServiceAgent(self.store, self.executor, self.audit, self.authority, clock=self.clock)

    def ticket(self, name: str):
        return load_ticket(next(TICKETS.glob(f"{name}*")))

    def plan_for(self, name: str):
        return self.agent.triage(self.ticket(name))


@pytest.fixture
def env(tmp_path) -> Env:
    return Env(tmp_path)


@pytest.fixture
def make_env(tmp_path):
    return lambda **kw: Env(tmp_path, kw)


@pytest.fixture
def runbook_copy(tmp_path) -> Path:
    dst = tmp_path / "runbooks"
    shutil.copytree(ROOT / "runbooks", dst)
    return dst
