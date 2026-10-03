"""Command-line interface for agent-policy."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

from . import PolicyError, compose_policies, evaluate


ERROR_SCHEMA = "agent-policy/error/v1"


class InputError(PolicyError):
    """A stable input-boundary error with a human and machine form."""

    def __init__(
        self,
        code: str,
        machine_message: str,
        human_message: str,
        *,
        input_kind: str,
    ) -> None:
        super().__init__(human_message)
        self.code = code
        self.machine_message = machine_message
        self.input_kind = input_kind


def _load(path: str, *, input_kind: str) -> Any:
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(
            f"{input_kind}_encoding_invalid",
            f"{input_kind} input must be valid UTF-8",
            f"invalid UTF-8 in {path}: {exc}",
            input_kind=input_kind,
        ) from exc
    except OSError as exc:
        raise InputError(
            f"{input_kind}_file_unreadable",
            f"{input_kind} input file could not be read",
            f"cannot read {path}: {exc}",
            input_kind=input_kind,
        ) from exc
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise InputError(
                "yaml_extra_missing",
                "YAML input needs the optional 'yaml' extra",
                "YAML input needs the optional 'yaml' extra: pip install agent-policy[yaml]",
                input_kind=input_kind,
            ) from exc
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise InputError(
                f"{input_kind}_yaml_invalid",
                f"{input_kind} input is not valid YAML",
                f"invalid YAML in {path}: {exc}",
                input_kind=input_kind,
            ) from exc
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise InputError(
            f"{input_kind}_json_invalid",
            f"{input_kind} input is not valid JSON",
            f"invalid JSON in {path}: {exc}",
            input_kind=input_kind,
        ) from exc


def _dump(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-policy",
        description="Deny-by-default policy evaluator (decision only; not a kernel sandbox).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("check", "evaluate a request and return a decision"),
        ("explain", "evaluate a request with rule explanations"),
        ("dry-run", "evaluate planned operations without performing them"),
    ):
        sub = subparsers.add_parser(command, help=help_text)
        sub.add_argument("--policy", required=True, help="JSON policy file (or YAML with the yaml extra)")
        sub.add_argument("--request", required=True, help="JSON request file (or YAML with the yaml extra)")
        sub.add_argument("--receipt", action="store_true", help="emit a machine-readable receipt envelope")
        sub.add_argument("--json", action="store_true", help="emit machine-readable errors as JSON")
    compose = subparsers.add_parser(
        "compose",
        help="compose policy layers and reject ambiguous rule identities",
    )
    compose.add_argument(
        "--policy",
        dest="policies",
        action="append",
        required=True,
        help="policy layer (repeat in evaluation order)",
    )
    compose.add_argument("--json", action="store_true", help="emit machine-readable errors as JSON")
    return parser


def _error_envelope(error: InputError, *, command: str, receipt: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": ERROR_SCHEMA,
        "status": "error",
        "ok": False,
        "performed": False,
        "tool": "agent-policy",
        "mode": command,
        "error": {
            "code": error.code,
            "input": error.input_kind,
            "message": error.machine_message,
        },
    }
    if receipt:
        result["receipt_version"] = 1
    return result


def _as_input_error(error: PolicyError, *, input_kind: str) -> InputError:
    return InputError(
        f"{input_kind}_invalid",
        f"{input_kind} input failed validation",
        str(error),
        input_kind=input_kind,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    machine_errors = getattr(args, "receipt", False) or getattr(args, "json", False)
    try:
        if args.command == "compose":
            _dump(compose_policies([_load(path, input_kind="policy") for path in args.policies]))
            return 0
        try:
            policy = _load(args.policy, input_kind="policy")
        except InputError:
            raise
        try:
            request = _load(args.request, input_kind="request")
        except InputError:
            raise
        try:
            result = evaluate(policy, request)
        except PolicyError as exc:
            input_kind = "request" if str(exc).startswith("request") else "policy"
            raise _as_input_error(exc, input_kind=input_kind) from exc
        if args.command == "dry-run":
            result = {**result, "mode": "dry-run", "performed": False}
        elif args.command == "check":
            result = {"decision": result["decision"]}
        if args.receipt:
            result = {
                "schema": "agent-policy/receipt/v1",
                "receipt_version": 1,
                "tool": "agent-policy",
                "mode": args.command,
                "performed": False,
                "result": result,
                "notice": "This evaluates policy; it is not a kernel sandbox and does not enforce system operations.",
            }
        _dump(result)
        evaluated = result.get("result", result)
        return 0 if evaluated.get("decision") == "allow" else 1
    except InputError as exc:
        if machine_errors:
            _dump(_error_envelope(exc, command=args.command, receipt=getattr(args, "receipt", False)))
        else:
            print(f"agent-policy: error: {exc}", file=sys.stderr)
        return 2
    except (PolicyError, OSError) as exc:
        error = _as_input_error(exc, input_kind="policy")
        if machine_errors:
            _dump(_error_envelope(error, command=args.command, receipt=getattr(args, "receipt", False)))
        else:
            print(f"agent-policy: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
