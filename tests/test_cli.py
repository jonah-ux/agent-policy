from agent_policy.cli import main


def test_cli_import():
    assert callable(main)
