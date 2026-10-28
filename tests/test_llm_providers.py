import json

import pytest

from it_service_agent import ITServiceAgent, OpenAICompatibleProvider, provider_from_env
from it_service_agent.llm import ProviderError, MockProvider


def fake_transport(actions=None, content=None, capture=None):
    def t(url, headers, body):
        if capture is not None:
            capture.update(url=url, headers=headers, body=json.loads(body))
        obj = content if content is not None else {"summary": "LLM summary", "actions": actions or [], "notes": []}
        return {"choices": [{"message": {"content": obj if isinstance(obj, str) else json.dumps(obj)}}]}
    return t


def agent_with(env, provider):
    return ITServiceAgent(env.store, env.executor, env.audit, env.authority, provider=provider, clock=env.clock)


AZ = {"AZURE_OPENAI_ENDPOINT": "https://example-resource.openai.azure.test/", "AZURE_OPENAI_DEPLOYMENT": "planner",
      "AZURE_OPENAI_API_KEY": "synthetic-key"}


def test_default_provider_is_offline_mock():
    assert isinstance(provider_from_env(env={}), MockProvider)


def test_azure_request_shape_and_untrusted_ticket_delimiting(env):
    cap = {}
    good = [{"name": "unlock_account", "params": {"user": "jordan.lee@example.test"},
             "section_ref": "account-lockout.md#Remediation", "rationale": "r"}]
    prov = OpenAICompatibleProvider("azure", AZ, fake_transport(good, capture=cap))
    plan = agent_with(env, prov).triage(env.ticket("INC-1001"))
    assert cap["url"].startswith("https://example-resource.openai.azure.test/openai/deployments/planner/chat/completions")
    assert cap["headers"]["api-key"] == "synthetic-key" and cap["body"]["temperature"] == 0
    user_msg = cap["body"]["messages"][1]["content"]
    assert "<untrusted_ticket>" in user_msg and "<runbook_sections>" in user_msg
    assert [a.name for a in plan.actions] == ["unlock_account"] and plan.provider == "azure-openai:planner"


def test_openai_adapter_uses_bearer_and_model():
    p = OpenAICompatibleProvider("openai", {"OPENAI_API_KEY": "k", "OPENAI_MODEL": "m1"}, fake_transport())
    assert p.headers["Authorization"] == "Bearer k" and p.model == "m1"


def test_entra_token_auth_supported():
    env = {k: v for k, v in AZ.items() if k != "AZURE_OPENAI_API_KEY"} | {"AZURE_OPENAI_AD_TOKEN": "tok"}
    assert OpenAICompatibleProvider("azure", env, fake_transport()).headers == {"Authorization": "Bearer tok"}


def test_missing_config_fails_clearly():
    with pytest.raises(ProviderError):
        OpenAICompatibleProvider("azure", {}, fake_transport())
    with pytest.raises(ProviderError):
        provider_from_env("openai", {})


@pytest.mark.parametrize("bad,why", [
    ({"name": "delete_user", "params": {"user": "jordan.lee@example.test"}, "section_ref": "account-lockout.md#Remediation"}, "allowlist"),
    ({"name": "add_user_to_group", "params": {"user": "jordan.lee@example.test", "group": "SG-Collab-Basic"},
      "section_ref": "account-lockout.md#Remediation"}, "ungrounded"),
    ({"name": "unlock_account", "params": {"user": "mallory@example.test"}, "section_ref": "account-lockout.md#Remediation"}, "scope"),
    ({"name": "unlock_account", "params": {"user": "jordan.lee@example.test"}, "section_ref": "made-up.md#Remediation"}, "ungrounded"),
    ({"name": "unlock_account", "params": {"user": "jordan.lee@example.test", "extra": "x"}, "section_ref": "account-lockout.md#Remediation"}, "params"),
])
def test_hostile_or_hallucinated_llm_output_is_dropped(env, bad, why):
    """Even if the model is fully compromised by the ticket, nothing out-of-policy reaches the approver as a plan."""
    prov = OpenAICompatibleProvider("azure", AZ, fake_transport([bad]))
    plan = agent_with(env, prov).triage(env.ticket("INC-1001"))
    assert plan.actions == [] and len(plan.rejected) == 1


def test_compromised_llm_cannot_execute_without_approval(env):
    bad = {"name": "unlock_account", "params": {"user": "jordan.lee@example.test"},
           "section_ref": "account-lockout.md#Remediation"}
    ag = agent_with(env, OpenAICompatibleProvider("azure", AZ, fake_transport([bad])))
    plan = ag.triage(env.ticket("INC-1005"))
    rep = ag.execute(plan, None)
    assert not rep.approved and env.executor.state["users"]["jordan.lee@example.test"]["locked"] is True


@pytest.mark.parametrize("content", ["not json at all", {"summary": "x", "actions": [{"name": "unlock_account"}]}])
def test_malformed_model_output_degrades_to_human_routing(env, content):
    plan = agent_with(env, OpenAICompatibleProvider("azure", AZ, fake_transport(content=content))).triage(env.ticket("INC-1001"))
    assert plan.actions == [] and any("provider error" in n for n in plan.notes)
    assert any(e["event"] == "provider.error" for e in env.audit.entries())


def test_transport_failure_degrades_safely(env):
    def boom(url, headers, body):
        raise OSError("network down")
    plan = agent_with(env, OpenAICompatibleProvider("azure", AZ, boom)).triage(env.ticket("INC-1001"))
    assert plan.actions == [] and "human technician" in plan.summary
