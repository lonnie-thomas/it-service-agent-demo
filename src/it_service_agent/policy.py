"""Least-privilege policy: the action allowlist, parameter validation, and approver clearance.

Everything not listed here is denied by default. The same table is enforced twice:
once by the agent (before proposing/executing) and again inside the executor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

RISK_ORDER = {"low": 1, "medium": 2, "high": 3}

USER_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}@example\.test$")
PRINTER_RE = re.compile(r"^PRN-[A-Z0-9-]{2,12}$")

# Accounts the agent may never touch, even with approval (break-glass, service, executive tier).
PROTECTED_USER_RE = re.compile(r"^(admin\.|svc-|breakglass|exec\.)", re.I)

READABLE_SERVICES = {"print-spooler", "file-share", "vpn-gateway", "mail-relay"}
RESTARTABLE_SERVICES = {"print-spooler", "file-share"}      # mail-relay is read-only for the agent
ASSIGNABLE_GROUPS = {"SG-Software-Standard", "SG-Collab-Basic"}  # never privileged groups


def _valid_user(v: str) -> str | None:
    if not USER_RE.match(v):
        return "must look like first.last@example.test"
    if PROTECTED_USER_RE.match(v):
        return "protected account: out of scope for the agent"
    return None


def _in_set(allowed: set[str], label: str) -> Callable[[str], str | None]:
    def check(v: str) -> str | None:
        return None if v in allowed else f"{label} '{v}' is not in the allowed set {sorted(allowed)}"
    return check


def _valid_printer(v: str) -> str | None:
    return None if PRINTER_RE.match(v) else "must look like PRN-XXXX"


@dataclass(frozen=True)
class ActionSpec:
    name: str
    description: str
    state_changing: bool
    risk: str
    params: dict[str, Callable[[str], str | None]]


ALLOWLIST: dict[str, ActionSpec] = {s.name: s for s in [
    ActionSpec("check_service_status", "Read the status of a service", False, "low",
               {"service": _in_set(READABLE_SERVICES, "service")}),
    ActionSpec("check_account_status", "Read lock/session state of an account", False, "low",
               {"user": _valid_user}),
    ActionSpec("unlock_account", "Clear a lockout on a standard user account", True, "low",
               {"user": _valid_user}),
    ActionSpec("clear_print_queue", "Purge stuck jobs from one printer queue", True, "low",
               {"printer": _valid_printer}),
    ActionSpec("revoke_user_sessions", "Sign a standard user out of all sessions", True, "medium",
               {"user": _valid_user}),
    ActionSpec("restart_service", "Restart an allowlisted non-critical service", True, "medium",
               {"service": _in_set(RESTARTABLE_SERVICES, "service")}),
    ActionSpec("add_user_to_group", "Add a standard user to a non-privileged group", True, "high",
               {"user": _valid_user, "group": _in_set(ASSIGNABLE_GROUPS, "group")}),
]}


def validate_action(name: str, params: dict[str, str], scope_users: set[str] | None = None) -> list[str]:
    """Return a list of violations (empty list means the action is permitted)."""
    spec = ALLOWLIST.get(name)
    if spec is None:
        return [f"action '{name}' is not on the allowlist"]
    problems: list[str] = []
    extra = set(params) - set(spec.params)
    missing = set(spec.params) - set(params)
    if extra:
        problems.append(f"unexpected parameter(s): {sorted(extra)}")
    if missing:
        problems.append(f"missing parameter(s): {sorted(missing)}")
    for key, check in spec.params.items():
        if key in params:
            if not isinstance(params[key], str):
                problems.append(f"parameter '{key}' must be a string")
                continue
            err = check(params[key])
            if err:
                problems.append(f"parameter '{key}': {err}")
    if scope_users is not None and "user" in params and params["user"] not in scope_users:
        problems.append(f"user '{params['user']}' is outside the ticket scope")
    return problems


def is_state_changing(name: str) -> bool:
    spec = ALLOWLIST.get(name)
    return True if spec is None else spec.state_changing  # unknown => treat as state-changing


def risk_of(name: str) -> str:
    spec = ALLOWLIST.get(name)
    return "high" if spec is None else spec.risk


def plan_risk(action_names: list[str]) -> str:
    """Highest risk among the *state-changing* actions (read-only needs no clearance)."""
    risks = [risk_of(n) for n in action_names if is_state_changing(n)]
    return max(risks, key=RISK_ORDER.__getitem__) if risks else "low"
