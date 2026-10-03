import json
from pathlib import Path

import pytest

from agent_policy import PolicyError, evaluate


FIXTURE = Path(__file__).parent / "../conformance/agent-systems-lab.json"


def policy_fixture():
    return {
        "version": 1,
        "default": "deny",
        "rules": [
            {"id": "source-read", "effect": "allow", "kind": "path", "actions": ["read"], "paths": ["src/**"], "reason": "synthetic source"},
            {"id": "secret-deny", "effect": "deny", "kind": "path", "actions": ["read"], "paths": ["src/secrets/**"], "reason": "synthetic secret boundary"},
        ],
    }


def test_manifest_pins_native_owner_and_agent_proof_adapter():
    manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert manifest["schema"] == "agent-systems-lab-policy-conformance/v1"
    assert manifest["owner"] == "agent-policy"
    assert manifest["native_schema"] == "agent-policy/v1"
    assert manifest["receipt_schema"] == "agent-policy/receipt/v1"
    assert manifest["shared_adapter"]["schema"] == "agent-proof/interop/v1"
    assert manifest["shared_adapter"]["revision"] == "399564d4e4c1fedaec278409a7821b42eaf76563"
    assert manifest["shared_adapter"]["manifest_sha256"] == "62348cb59c986e3bba00af059774d433a5e3d68f48422c419ac6d6852d250de3"
    assert len(manifest["cases"]) == 5
    assert manifest["privacy"]["raw_policy_values_exported"] is False
    assert manifest["privacy"]["request_targets_summarized"] is True


def test_policy_receipt_preserves_explicit_and_default_decisions_without_raw_values():
    result = evaluate(
        policy_fixture(),
        {
            "version": 1,
            "operations": [
                {"type": "path", "action": "read", "path": "src/main.py"},
                {"type": "path", "action": "read", "path": "src/secrets/key"},
                {"type": "path", "action": "write", "path": "src/main.py"},
            ],
        },
    )
    assert result["decision"] == "deny"
    assert [item["decision"] for item in result["operations"]] == ["allow", "deny", "deny"]
    assert [item["decision_source"] for item in result["operations"]] == ["explicit_allow", "explicit_deny", "default_deny"]
    assert len(result["policy"]["sha256"]) == 64
    assert len(result["request"]["sha256"]) == 64
    assert "synthetic secret boundary" in json.dumps(result)
    assert "src/**" not in json.dumps(result)


def test_policy_boundary_refuses_traversal_and_unknown_versions():
    with pytest.raises(PolicyError):
        evaluate(policy_fixture(), {"version": 1, "operations": [{"type": "path", "action": "read", "path": "../secret"}]})
    unknown = policy_fixture()
    unknown["version"] = 2
    with pytest.raises(PolicyError):
        evaluate(unknown, {"version": 1, "operations": []})
