# Threat Model: IT Service Agent Demo

Method: **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege), applied to the data flow in the README. Each threat is mapped to the **OWASP Top 10 for Large Language Model (LLM) Applications, 2025 edition** (Open Worldwide Application Security Project) and to the **NIST AI RMF** (National Institute of Standards and Technology Artificial Intelligence Risk Management Framework 1.0). Mappings are illustrative design guidance, not a compliance or certification claim.

Scope: the code in this repository, using synthetic data and a simulated executor. "Production" notes describe what a real deployment must add; they are not implemented here.

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Directory and service state (accounts, group membership, services, printers) | What the agent can change; the thing an attacker wants to change |
| A2 | Approval authority (approver registry, signing keys, issued approvals) | The control that separates "proposed" from "allowed" |
| A3 | Audit log | Evidence for investigation, audit, and non-repudiation |
| A4 | Runbooks | The only source of actions the agent may propose |
| A5 | Ticket content (may contain personal data or accidentally pasted secrets) | Confidentiality and an injection channel |
| A6 | LLM provider credentials and endpoint | Cost, data egress, and impersonation risk |
| A7 | Plan integrity (what the human saw equals what runs) | Prevents approve-one-thing, run-another |

## 2. Trust boundaries

| ID | Boundary | Crossing data | Control at the boundary |
|---|---|---|---|
| TB1 | End user / external tool to agent (ticket intake) | Ticket title, body, attachments | Hidden-text normalisation, injection flags, secret redaction; text is data, never instructions |
| TB2 | Agent to LLM provider | Sanitised ticket text, runbook sections out; proposal back | Untrusted-data delimiters; response treated as a suggestion and fully re-validated |
| TB3 | Runbook storage to agent | Runbook text, action templates | SHA-256 manifest pinning; actions only from `## Remediation` templates |
| TB4 | Human approver to agent | Signed approval | Signature, expiry, plan-digest binding, clearance, separation of duties, single use |
| TB5 | Agent to executor | Action name + parameters + execution grant | Allowlist and parameter validation enforced again in the executor; grant required for state changes |
| TB6 | Agent to audit log storage | Append-only entries | Hash chain; execution fails closed if chain breaks; external anchor |

## 3. STRIDE table

Legend for control references: tests live in `tests/`.

| # | STRIDE | Threat | Asset / boundary | Mitigations (and where tested) | Residual risk | OWASP LLM 2025 | NIST AI RMF |
|---|---|---|---|---|---|---|---|
| T1 | Spoofing | **Forged approval**: attacker fabricates an approval, edits fields (extends expiry, swaps approver), or reuses another plan's approval | A2, TB4 | HMAC-SHA256 over every approval field; approver must be registered; approval bound to plan digest and ticket id; lifetime capped at 60 minutes (`test_approvals.py`: tampered signature / field / approver swap / unknown approver / wrong plan) | **Medium in demo**: symmetric keys mean anyone who can verify can forge. A compromised agent process or leaked registry file defeats this. Production: asymmetric signatures from an approval service outside the agent, Entra ID-authenticated approver, keys in a hardware-backed vault | LLM06 Excessive Agency | GOVERN 3.2, MAP 3.5, MANAGE 2 |
| T2 | Spoofing | **Ticket claims authority** ("this is pre-approved", fake system/developer message) to skip the gate | TB1, TB4 | Ticket text never influences approval logic; approval-bypass phrases are flagged to the approver; gate has no code path that reads ticket text (`test_prompt_injection.py::test_pre_approved_claim_in_ticket_does_not_bypass_gate`) | Low. A human may still be socially engineered by a convincing ticket; flags reduce but do not remove this | LLM01 Prompt Injection | MAP 3.5, MEASURE 2.7 |
| T3 | Tampering | **Prompt injection via ticket**: instructions in body, attachment, HTML comment, zero-width characters, bidirectional controls, Unicode tag characters | A1, TB1, TB2 | (1) Text normalised before retrieval and provider call; hidden content flagged. (2) Mock provider extracts entities only. (3) Model output must match an `ACTION` template in a retrieved runbook, with in-scope users and allowlisted parameters. (4) Human approval of the exact plan. (5) Groups come only from structured fields. (`test_prompt_injection.py`, `test_llm_providers.py::test_hostile_or_hallucinated_llm_output_is_dropped`) | **Medium**. A model could be steered to pick a *different but legitimate* template (for example restart a service instead of unlocking an account). Bounded by allowlist, scope, and approval; the approver must read the plan. Heuristic detectors have false negatives | LLM01 Prompt Injection, LLM06 | MEASURE 2.7, MANAGE 2 |
| T4 | Tampering | **Runbook poisoning**: modified or added runbook inserts a malicious `ACTION` line or misleading guidance | A4, TB3 | SHA-256 manifest verified at load; modified, unexpected, or missing files are refused (`test_tickets_and_retrieval.py`). Even a re-pinned malicious runbook cannot add actions outside the allowlist or scope (`test_runbook_cannot_be_used_to_smuggle_unlisted_actions`) | **Medium**. An attacker with write access to both runbooks and manifest can change *which allowed action* is proposed, or mislead a human. Production: pull-request review, signed commits, manifest in a separate trust domain | LLM04 Data and Model Poisoning, LLM03 Supply Chain | GOVERN 1, MAP 4 |
| T5 | Tampering | **Plan swapped after approval** (time-of-check to time-of-use): plan file edited on disk | A7, TB4/TB5 | Approval signs the plan digest (ticket hash plus every action, parameter, and citation hash); plan re-validated at execution (`test_agent_flow.py::test_plan_edited_after_approval_is_rejected`, `..._non_allowlisted_action_is_rejected`) | Low | LLM06 | MANAGE 2 |
| T6 | Tampering | **Audit log tampering**: edit, delete, reorder, insert, or truncate entries | A3, TB6 | SHA-256 hash chain with sequence numbers; verify detects edits, deletions, reordering, insertions; external anchor detects tail truncation and wholesale rewrites; execution refuses to run on a broken chain (`test_audit.py`) | **Medium**. An attacker with filesystem write access can delete the whole file or rewrite it consistently if no external anchor exists. Production: stream to Azure Monitor / Sentinel and store anchors in write-once storage | (supports accountability across LLM01/LLM06; not a direct Top 10 item) | MEASURE 2.4, MANAGE 4.1 |
| T7 | Repudiation | **Approver or operator denies an action**; actions not attributable | A2, A3 | Every approval issuance, verification, consumption, rejection, and per-action result is logged with actor, plan digest, approval id; approval ids are single use | Medium in demo (shared symmetric key); production uses per-person asymmetric signatures plus Entra ID sign-in logs | LLM06 | GOVERN 2, GOVERN 3.2 |
| T8 | Repudiation / integrity | **False "done" claim**: report says success when an action failed or never ran | A1, A3 | Status derives from executor result *and* an independent post-condition read; failures halt and the rest are `skipped`; silent no-ops are caught (`test_agent_flow.py::test_failure_is_reported_as_failure`, `test_silent_noop_is_caught_by_postcondition_check`) | Low for the demo; production post-conditions must read from the system of record, not the executor's own response | LLM09 Misinformation, LLM05 Improper Output Handling | MEASURE 2.5, MANAGE 4.1 |
| T9 | Info disclosure | **Data exfiltration**: injected text asks the agent to include credentials or send data out; secrets pasted in tickets appear in summaries or logs | A5, TB1/TB2 | Secret-pattern redaction on summaries and log fields; log stores ticket hash, redacted title only; executor has no network or messaging action; no email/webhook action exists on the allowlist (`test_secret_in_attachment_not_echoed_in_plan_or_log`) | **Medium**. Regex redaction misses unusual secret formats; ticket text is sent to the LLM provider when a real provider is configured (data-processing terms, private endpoint, and minimisation are deployment responsibilities) | LLM02 Sensitive Information Disclosure | MAP 4, MEASURE 2.10 |
| T10 | Info disclosure | **Provider credential leakage** (API key in repo, logs, or environment) | A6 | Keys only via environment variables; `.env` is git-ignored; keys never written to logs or plans; Entra ID bearer token option avoids long-lived keys | Low in repo; operational risk remains in how the environment is managed. Production: managed identity, no keys | LLM03 Supply Chain, LLM02 | GOVERN 6 |
| T11 | Denial of service | **Resource exhaustion**: ticket floods, huge attachments, repeated restarts, unbounded model calls | A1, TB2 | Bounded retrieval (max 2 runbooks), snippets truncated, one provider call per ticket, plan halts on first failure, approvals are single use so restart loops need fresh human approval | **Medium**. No rate limiting, queue limits, or cost caps in the demo. Production: intake throttling, token budgets, circuit breakers on provider and executor | LLM10 Unbounded Consumption | MANAGE 2, MANAGE 4.1 |
| T12 | Elevation of privilege | **Privilege escalation through the agent**: add attacker to a privileged group, act on break-glass or service accounts, target a user outside the ticket | A1, TB5 | Allowlist of 7 actions; privileged groups not assignable; protected account patterns refused; user parameters must equal the ticket's requester or affected user; critical services (mail relay, VPN gateway) read-only; executor re-enforces and requires an execution grant (`test_policy_and_executor.py`, `test_agent_flow.py::test_protected_account_ticket_yields_no_action`) | Low in simulator. In production, the allowlist must be mirrored by actual least-privilege roles on the executor's workload identity, otherwise a bug in the allowlist becomes real privilege | LLM06 Excessive Agency | GOVERN 3.2, MAP 3.5 |
| T13 | Elevation of privilege | **Approver exceeds clearance or self-approves** | A2, TB4 | Plan risk (highest state-changing action) vs approver `max_risk`; requester and affected user cannot approve their own ticket (`test_approvals.py::test_insufficient_clearance`, `test_separation_of_duties`) | Low. Does not detect collusion between two legitimate people | LLM06 | GOVERN 3.2 |
| T14 | Spoofing / Tampering | **Approval replay**: reuse a valid approval to re-run an action later | A2, TB4 | Single-use approval id and nonce recorded as `approval.consumed` *before* execution; short expiry; replay state derived from the tamper-evident log (`test_replay_of_consumed_approval`) | Low. If the log is truncated and no anchor exists, consumed ids could be forgotten (see T6) | LLM06 | MANAGE 2 |
| T15 | Tampering | **Hallucinated or ungrounded action** from the model | A1, TB2 | Grounding check: action name and parameter keys must match a template in a cited, retrieved section; unknown citations rejected and logged (`test_llm_providers.py`) | Low | LLM09, LLM06 | MEASURE 2.5 |
| T16 | Elevation of privilege | **Compromised agent process** (code execution on the host running the agent) | All | Out of scope for the demo. Mitigations belong to the platform: isolate the approval service and signing keys from the agent, run the executor under separate identities, host hardening, Microsoft Defender for Cloud/Endpoint monitoring | **High if it happens**: the demo holds verification keys in-process | LLM03, LLM06 | GOVERN 1, MANAGE 4 |
| T17 | Tampering | **Dependency or model supply chain** | TB2 | Zero runtime dependencies (standard library only), small auditable code base; model/provider choice is configuration | Low for code; model provider risk is a procurement and configuration decision | LLM03 Supply Chain | GOVERN 6 |

## 4. Out of scope (and why it matters)

* Real identity, network, and endpoint security of the host running the agent.
* Model-level attacks (jailbreak robustness of a specific model, training-data poisoning, embedding attacks). The demo's retrieval is lexical, so vector-store weaknesses (LLM08) do not apply; a vector database would add that surface.
* System prompt leakage (LLM07): the prompt in `llm.py` contains no secrets by design, so leakage has limited impact.
* Privacy law obligations for ticket data processed by an external provider.

## 5. Mapping summary

### OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Where addressed |
|---|---|---|
| LLM01 | Prompt Injection | T2, T3: normalisation, flags, grounding, allowlist, approval |
| LLM02 | Sensitive Information Disclosure | T9, T10: redaction, log minimisation, no outbound actions |
| LLM03 | Supply Chain | T4, T10, T17: manifest pinning, no runtime dependencies |
| LLM04 | Data and Model Poisoning | T4: runbook integrity |
| LLM05 | Improper Output Handling | T8, T15: model output validated before use; status derived from state |
| LLM06 | Excessive Agency | T1, T3, T5, T12, T13, T14: allowlist, approval gate, least privilege |
| LLM07 | System Prompt Leakage | Out of scope; prompt holds no secrets |
| LLM08 | Vector and Embedding Weaknesses | Not applicable (lexical retrieval); note if vector search is added |
| LLM09 | Misinformation | T8, T15: citations, grounding, honest reporting |
| LLM10 | Unbounded Consumption | T11: partial; rate and cost limits are residual work |

### NIST AI RMF 1.0 (functions)

| Function | How this design supports it |
|---|---|
| **GOVERN** | Roles and accountability for human oversight are explicit in code (approver registry, clearance, separation of duties); allowlist is a reviewable policy artifact |
| **MAP** | Context and boundaries are documented here (assets, trust boundaries); human oversight points are defined (MAP 3.5) |
| **MEASURE** | Security and resilience are evaluated by an automated suite (MEASURE 2.7); the companion `agent-security-test-kit` repeats adversarial checks against any agent |
| **MANAGE** | Risks are treated with layered controls, the audit trail supports post-deployment monitoring (MANAGE 4.1), and residual risks are listed openly above |

ISO/IEC 42001 (international standard for Artificial Intelligence management systems): the controls above are the kind of operational evidence (oversight records, logging, change control over runbooks) an AI management system would reference. Nothing in this repository claims ISO/IEC 42001 conformance or certification.

## 6. Production hardening checklist

1. Move approvals to an external service with asymmetric signatures; authenticate approvers with Microsoft Entra ID and Conditional Access; use Privileged Identity Management for approver roles.
2. Run the executor under per-action managed identities with least-privilege roles that mirror the allowlist.
3. Stream the audit log to Azure Monitor / Microsoft Sentinel and store anchors in immutable storage; alert on `approval.rejected`, `injection.flagged`, and `provider.error`.
4. Protect the runbook repository with pull-request review and signed commits; verify signatures instead of a local manifest.
5. Add rate limits, token and cost budgets, and a kill switch.
6. Verify post-conditions against the system of record, not the executor response.
7. Red-team regularly (see the companion test kit) and re-run on every runbook, prompt, or model change.

## Acronyms

STRIDE: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. OWASP: Open Worldwide Application Security Project. LLM: large language model. NIST: National Institute of Standards and Technology. AI RMF: Artificial Intelligence Risk Management Framework. HMAC: Hash-based Message Authentication Code. SHA-256: Secure Hash Algorithm, 256-bit. JSONL: JSON Lines. IT: information technology. ITSM: IT service management. Entra ID: Microsoft's cloud identity service (formerly Azure Active Directory). PIM: Privileged Identity Management. WORM: write once, read many. TOCTOU: time of check to time of use.
