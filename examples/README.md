# Agent Policy Demo

This fixture is deliberately synthetic. Run it from the repository root after installing the package:

```console
python3 -m pip install .
set +e
agent-policy dry-run --policy examples/policy.json --request examples/request.json --receipt
status=$?
set -e
# status is 1 because the fixture intentionally includes denied .env access.
printf 'decision exit status: %s\n' "$status"
```

The output receipt says `performed: false`; no command, network connection, or file operation is made by the evaluator.
