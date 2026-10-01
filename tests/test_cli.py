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
