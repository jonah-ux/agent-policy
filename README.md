# Agent Policy

![agent capability policy checker workflow](docs/header.svg)

**Explain whether a requested agent action is allowed before it runs.**

[![CI](https://github.com/jonah-ux/agent-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/jonah-ux/agent-policy/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Agent Policy evaluates a JSON request against explicit allow rules and returns a compact,
machine-readable allow or deny decision. It defaults to deny when no rule matches, making the
decision visible before a command or capability is handed to an agent.

## Try it in 30 seconds

```bash
python -m pip install git+https://github.com/jonah-ux/agent-policy.git@main
python demos/demo.py
```

The smallest useful policy and request look like this:

```json
{"allow":[{"kind":"command","pattern":"git status"}]}
```

```json
{"kind":"command","value":"git status"}
```

```bash
agent-policy check request.json --policy policy.json
```

The output uses the `agent-policy/v1` schema and exits `0` for an allowed request or `1` for a
denied request, so a shell, CI job, or agent can stop before acting.

## Development

```bash
python -m unittest discover -s tests
python -m build --sdist --wheel
python demos/demo.py
```

This is a policy decision helper, not an operating-system sandbox. Enforce the decision in the
caller that owns the action.

MIT licensed.
