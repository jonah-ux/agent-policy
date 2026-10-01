import pytest

from agent_policy import (
    PolicyError,
    compose_policies,
    evaluate,
    normalize_path,
    policy_digest,
)


@pytest.fixture
def policy():
    return {
        "version": 1,
        "default": "deny",
        "rules": [
            {"id": "source", "effect": "allow", "kind": "path", "actions": ["read"], "paths": ["src/**"]},
            {"id": "secret", "effect": "deny", "kind": "path", "actions": ["read"], "paths": ["src/secrets/**"]},
            {"id": "pytest", "effect": "allow", "kind": "command", "actions": ["run"], "commands": ["pytest"]},
        ],
    }


def test_allowed_and_default_denied(policy):
    result = evaluate(policy, {"version": 1, "operations": [
        {"type": "path", "action": "read", "path": "src/main.py"},
        {"type": "path", "action": "write", "path": "src/main.py"},
    ]})
    assert result["decision"] == "deny"
    assert [item["decision"] for item in result["operations"]] == ["allow", "deny"]


def test_explicit_deny_overrides_allow(policy):
    result = evaluate(policy, {"version": 1, "operations": [
        {"type": "path", "action": "read", "path": "src/secrets/key"},
    ]})
    assert result["operations"][0]["decision"] == "deny"
    assert result["operations"][0]["matched_rules"][1]["id"] == "secret"


def test_all_operation_kinds():
    policy = {"version": 1, "default": "deny", "rules": [
        {"id": "cmd", "effect": "allow", "kind": "command", "actions": ["run"], "commands": ["python"]},
        {"id": "env", "effect": "allow", "kind": "env", "actions": ["read"], "names": ["CI_*"]},
        {"id": "net", "effect": "allow", "kind": "network", "actions": ["connect"], "hosts": ["example.com"], "ports": [443], "protocols": ["tcp"]},
        {"id": "git", "effect": "allow", "kind": "git", "actions": ["status"], "repositories": ["."]},
    ]}
    request = {"version": 1, "operations": [
        {"type": "command", "action": "run", "argv": ["python", "-V"]},
        {"type": "env", "action": "read", "name": "CI_JOB"},
        {"type": "network", "action": "connect", "host": "example.com", "port": 443, "protocol": "tcp"},
        {"type": "git", "action": "status", "repository": "."},
    ]}
    assert evaluate(policy, request)["decision"] == "allow"


def test_path_normalization_rejects_escape():
    with pytest.raises(PolicyError):
        normalize_path("../outside", "path")
    with pytest.raises(PolicyError):
        normalize_path("/absolute", "path")
    assert normalize_path("./src\\main.py", "path") == "src/main.py"


def test_malformed_policy_is_rejected():
    with pytest.raises(PolicyError, match="default"):
        evaluate({"version": 1, "default": "allow", "rules": []}, {"version": 1, "operations": []})


def test_explanation_binds_policy_and_request_and_rule_position(policy):
    result = evaluate(policy, {"version": 1, "operations": [
        {"type": "path", "action": "read", "path": "src/main.py"},
    ]})
    assert result["policy"] == {
        "version": 1,
        "sha256": policy_digest(policy),
        "rule_count": 3,
    }
    assert result["request"]["operation_count"] == 1
    operation = result["operations"][0]
    assert operation["decision_source"] == "explicit_allow"
    assert operation["matched_rules"][0]["index"] == 0


def test_composition_rejects_duplicate_rule_ids_and_preserves_order(policy):
    extra = {
        "version": 1,
        "default": "deny",
        "rules": [{"id": "network", "effect": "allow", "kind": "network", "actions": ["connect"], "hosts": ["example.com"]}],
    }
    composed = compose_policies([policy, extra])
    assert [rule["id"] for rule in composed["rules"]] == ["source", "secret", "pytest", "network"]
    with pytest.raises(PolicyError, match="duplicates rule id 'source'"):
        compose_policies([policy, policy])


def test_composition_is_fail_closed_for_empty_or_invalid_layers():
    with pytest.raises(PolicyError, match="non-empty list"):
        compose_policies([])
    with pytest.raises(PolicyError, match="policy default"):
        compose_policies([{"version": 1, "default": "allow", "rules": []}])
