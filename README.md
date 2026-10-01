# agent-policy

[![CI](https://github.com/jonah-ux/agent-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/jonah-ux/agent-policy/actions/workflows/ci.yml)

A small, standalone Python 3.11+ CLI for reviewing agent operations against an explicit, deny-by-default JSON (or optional YAML) policy. It handles paths, commands, environment variables, network destinations, and Git operations. Every decision includes an inspectable receipt when requested.

> This is a policy evaluator, not a kernel sandbox. It does not intercept, authorize, or prevent operating-system calls. Use a platform sandbox such as bubblewrap, containers, or a VM when enforcement is required.

<img src="docs/workflow.svg" alt="Workflow: author policy, submit request, evaluate, inspect receipt, then optionally enforce with a separate sandbox" width="900">

## Install

```console
python3 -m pip install agent-policy
agent-policy --help
```

From a checkout:

```console
python3 -m pip install .
```

No runtime dependencies are required. YAML input is optional: `python3 -m pip install 'agent-policy[yaml]'`. Platform sandbox helpers are optional and never invoked by this package.

## Quick start

A policy has exactly `version`, `default: deny`, and `rules`. See [`examples/policy.json`](examples/policy.json) and [`examples/request.json`](examples/request.json).

```console
$ agent-policy dry-run --policy examples/policy.json --request examples/request.json --receipt
{
  "mode": "dry-run",
  "notice": "This evaluates policy; it is not a kernel sandbox and does not enforce system operations.",
  "performed": false,
  "receipt_version": 1,
  "result": {
    "decision": "deny",
    ...
  },
  "tool": "agent-policy"
}
```

Exit status is `0` only when every operation is allowed, `1` when any operation is denied, and `2` for malformed input. `check` emits only the aggregate decision; `explain` emits rule matches and reasons; `dry-run` makes the non-execution mode explicit. None of these commands perform the requested operation.

Operations are exact structured data, not shell strings. For commands, the first argv item is matched against `commands`; optional `argv_patterns` match the complete argv. Paths and Git repository identifiers are workspace-relative and reject absolute paths, home paths, NUL bytes, and `..` components. The evaluator never expands variables, follows symlinks, or resolves a filesystem path.

## Related tools

Pair [Agent Policy](https://github.com/jonah-ux/agent-policy) with [Agent Sandbox Run](https://github.com/jonah-ux/agent-sandbox-run) for execution receipts, [Agent Proof](https://github.com/jonah-ux/agent-proof) for evidence, and [MCP Doctor](https://github.com/jonah-ux/mcp-doctor) for tool-contract checks.

## Development

```console
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
python -m build
```

Fixtures are synthetic and contain no credentials or live network calls. See [`SECURITY.md`](SECURITY.md) for the threat model and [`CONTRIBUTING.md`](CONTRIBUTING.md) for changes.

## License

MIT. See [`LICENSE`](LICENSE).
