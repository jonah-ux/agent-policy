# `agent-policy/error/v1`

Agent Policy keeps malformed-input handling separate from a policy decision.
The evaluator never treats unreadable or invalid policy/request input as an
implicit deny or an allow. Callers can request a stable JSON error on stdout by
passing `--receipt` or `--json` to `check`, `explain`, `dry-run`, or `compose`.

```json
{
  "schema": "agent-policy/error/v1",
  "status": "error",
  "ok": false,
  "performed": false,
  "tool": "agent-policy",
  "mode": "dry-run",
  "error": {
    "code": "request_encoding_invalid",
    "input": "request",
    "message": "request input must be valid UTF-8"
  }
}
```

## Stable fields

- `schema` identifies this error contract.
- `status` is always `error`; it is not an allow or deny decision.
- `ok` is always `false`.
- `performed` is always `false`; Agent Policy never performs the requested operation.
- `tool` is `agent-policy` and `mode` is the invoked subcommand.
- `error.code` identifies the input boundary that refused the request.
- `error.input` is `policy`, `request`, or `policy` for composed layers.
- `error.message` is bounded and does not contain source text, parser locations,
  credentials, or local paths.
- `receipt_version: 1` is included when `--receipt` was supplied.

The CLI exits `2` for this envelope. Without `--receipt` or `--json`, the same
failure stays a human-readable stderr diagnostic for shell users. A machine
error proves only that evaluation could not start; it does not prove that an
operation would have been allowed or denied.

## Current error codes

- `policy_file_unreadable`, `request_file_unreadable`
- `policy_encoding_invalid`, `request_encoding_invalid`
- `policy_json_invalid`, `request_json_invalid`
- `policy_yaml_invalid`, `request_yaml_invalid`
- `yaml_extra_missing`
- `policy_invalid`, `request_invalid`

The policy and request values remain local inputs. This contract adds no
runtime dependency, network call, sandbox, or execution behavior.
