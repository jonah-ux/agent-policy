"""Command-line interface for agent-policy."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

from . import PolicyError, evaluate


def _load(path: str) -> Any:
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc
    try:
        if path.lower().endswith(('.yaml', '.yml')):
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise PolicyError("YAML input needs the optional 'yaml' extra: pip install agent-policy[yaml]") from exc
            try:
                class UniqueKeyLoader(yaml.SafeLoader):
                    pass

                def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[str, Any]:
                    mapping: dict[str, Any] = {}
                    for key_node, value_node in node.value:
                        key = loader.construct_object(key_node, deep=deep)
                        if key in mapping:
                            raise PolicyError(f"duplicate mapping key: {key}")
                        mapping[key] = loader.construct_object(value_node, deep=deep)
                    return mapping

                UniqueKeyLoader.add_constructor(
                    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                    construct_mapping,
                )
                return yaml.load(text, Loader=UniqueKeyLoader)
            except yaml.YAMLError as exc:
                raise PolicyError(f"invalid YAML in {path}: {exc}") from exc
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"invalid JSON in {path}: {exc}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate object key: {key}")
        result[key] = value
    return result


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = _load(args.policy)
        request = _load(args.request)
        result = evaluate(policy, request)
        if args.command == "dry-run":
            result = {**result, "mode": "dry-run", "performed": False}
        elif args.command == "check":
            result = {"decision": result["decision"]}
        if args.receipt:
            result = {
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
    except (PolicyError, OSError) as exc:
        print(f"agent-policy: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
