# Contributing

Thanks for contributing. Keep the project standalone, deterministic, and dependency-free at runtime.

## Local setup

```console
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
python -m build
```

Add focused tests for policy validation and every behavior change. Fixtures must be synthetic: do not add credentials, private hostnames, or live network calls. Keep CLI output JSON and preserve exit codes: `0` all allowed, `1` denied, `2` malformed input.

## Pull requests

Explain the threat-model impact and whether a change affects the explicit receipt. Keep commits focused. CI runs the supported Python versions on Ubuntu and macOS. A maintainer will review security-sensitive changes before merge.
