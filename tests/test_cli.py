from agent_policy.cli import main


def test_cli_import():
    assert callable(main)


def test_compose_cli_emits_canonical_policy(tmp_path, capsys):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text('{"version": 1, "default": "deny", "rules": [{"id": "read", "effect": "allow", "kind": "path", "actions": ["read"], "paths": ["src/**"]}]}', encoding="utf-8")
    second.write_text('{"version": 1, "default": "deny", "rules": [{"id": "tests", "effect": "allow", "kind": "command", "actions": ["run"], "commands": ["pytest"]}]}', encoding="utf-8")
    assert main(["compose", "--policy", str(first), "--policy", str(second)]) == 0
    output = capsys.readouterr().out
    assert '"id": "read"' in output
    assert '"id": "tests"' in output


def test_compose_cli_rejects_duplicate_ids(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text('{"version": 1, "default": "deny", "rules": [{"id": "same", "effect": "allow", "kind": "path", "actions": ["read"], "paths": ["src/**"]}]}', encoding="utf-8")
    assert main(["compose", "--policy", str(policy), "--policy", str(policy)]) == 2
    assert "duplicates rule id 'same'" in capsys.readouterr().err


def test_receipt_cli_declares_versioned_boundary_and_bounded_result(tmp_path, capsys):
    import json
    policy = tmp_path / "policy.json"
    request = tmp_path / "request.json"
    policy.write_text(
        '{"version":1,"default":"deny","rules":[{"id":"read","effect":"allow","kind":"path","actions":["read"],"paths":["src/**"]}]}',
        encoding="utf-8",
    )
    request.write_text(
        '{"version":1,"operations":[{"type":"path","action":"read","path":"src/app.py"}]}',
        encoding="utf-8",
    )
    assert main(["explain", "--policy", str(policy), "--request", str(request), "--receipt"]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["schema"] == "agent-policy/receipt/v1"
    assert receipt["receipt_version"] == 1
    assert receipt["result"]["policy"]["rule_count"] == 1
    assert receipt["result"]["request"]["operation_count"] == 1
