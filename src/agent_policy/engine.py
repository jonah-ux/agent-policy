"""Deterministic, deny-by-default policy evaluation; never performs operations."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from typing import Any


class PolicyError(ValueError):
    """Raised when a policy or request is malformed or unsafe to interpret."""


_ACTIONS = {
    "path": {"read", "write", "execute", "delete"},
    "command": {"run"},
    "env": {"read", "set", "unset"},
    "network": {"connect"},
    "git": {
        "status", "diff", "add", "commit", "push", "pull", "fetch",
        "branch", "checkout", "merge", "rebase", "reset", "clean", "tag",
        "config", "clone", "init", "worktree", "cherry-pick", "revert",
    },
}
_RULE_FIELDS = {
    "path": {"paths"},
    "command": {"commands", "argv_patterns"},
    "env": {"names"},
    "network": {"hosts", "ports", "protocols"},
    "git": {"repositories"},
}
_RULE_COMMON = {"id", "effect", "kind", "actions", "reason"}
_OP_FIELDS = {
    "path": {"type", "action", "path"},
    "command": {"type", "action", "argv"},
    "env": {"type", "action", "name"},
    "network": {"type", "action", "host", "port", "protocol"},
    "git": {"type", "action", "repository"},
}
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise PolicyError(f"{label} must be a mapping with string keys")
    return value


def _strings(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise PolicyError(f"{label} must be a non-empty list of strings")
    if any(not isinstance(item, str) or not item for item in value):
        raise PolicyError(f"{label} must contain only non-empty strings")
    return value


def normalize_path(value: Any, label: str) -> str:
    """Return a workspace-relative POSIX path, rejecting traversal and absolutes."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PolicyError(f"{label} must be a non-empty path without NUL")
    path = value.replace("\\", "/")
    if path.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", path):
        raise PolicyError(f"{label} must be relative to the workspace")
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise PolicyError(f"{label} must not contain parent traversal ('..')")
    return "/".join(parts) or "."


def _path_pattern(value: str, label: str) -> str:
    if "\x00" in value:
        raise PolicyError(f"{label} must not contain NUL")
    pattern = value.replace("\\", "/")
    if pattern.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", pattern):
        raise PolicyError(f"{label} must be workspace-relative")
    if ".." in pattern.split("/"):
        raise PolicyError(f"{label} must not contain a '..' path component")
    return "/".join(part for part in pattern.split("/") if part not in ("", ".")) or "."


def validate_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, "policy")
    if set(policy) != {"version", "default", "rules"}:
        extra = sorted(set(policy) - {"version", "default", "rules"})
        missing = sorted({"version", "default", "rules"} - set(policy))
        raise PolicyError(f"policy fields mismatch (missing={missing}, unknown={extra})")
    if policy["version"] != 1 or isinstance(policy["version"], bool):
        raise PolicyError("policy version must be integer 1")
    if policy["default"] != "deny":
        raise PolicyError("policy default must be 'deny'")
    if not isinstance(policy["rules"], list):
        raise PolicyError("policy rules must be a list")

    seen: set[str] = set()
    rules: list[dict[str, Any]] = []
    for index, raw in enumerate(policy["rules"]):
        label = f"policy.rules[{index}]"
        rule = _mapping(raw, label)
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id or rule_id in seen:
            raise PolicyError(f"{label}.id must be a unique non-empty string")
        seen.add(rule_id)
        kind = rule.get("kind")
        if not isinstance(kind, str) or kind not in _RULE_FIELDS:
            raise PolicyError(f"{label}.kind must be one of {sorted(_RULE_FIELDS)}")
        unknown = set(rule) - (_RULE_COMMON | _RULE_FIELDS[kind])
        missing = {"id", "effect", "kind", "actions"} - set(rule)
        if unknown or missing:
            raise PolicyError(f"{label} fields mismatch (missing={sorted(missing)}, unknown={sorted(unknown)})")
        if not isinstance(rule["effect"], str) or rule["effect"] not in {"allow", "deny"}:
            raise PolicyError(f"{label}.effect must be 'allow' or 'deny'")
        actions = _strings(rule["actions"], f"{label}.actions")
        if len(set(actions)) != len(actions) or any(
            action not in _ACTIONS[kind] for action in actions
        ):
            raise PolicyError(f"{label}.actions contains an unsupported or duplicate action for {kind}")
        reason = rule.get("reason", "")
        if not isinstance(reason, str):
            raise PolicyError(f"{label}.reason must be a string")
        normalized = dict(rule)
        if kind == "path":
            normalized["paths"] = [_path_pattern(p, f"{label}.paths") for p in _strings(rule.get("paths"), f"{label}.paths")]
        elif kind == "command":
            normalized["commands"] = _strings(rule.get("commands"), f"{label}.commands")
            if "argv_patterns" in rule:
                patterns = rule["argv_patterns"]
                if not isinstance(patterns, list) or not patterns:
                    raise PolicyError(f"{label}.argv_patterns must be a non-empty list of argument-pattern lists")
                normalized_patterns = []
                for pattern in patterns:
                    normalized_patterns.append(_strings(pattern, f"{label}.argv_patterns item"))
                normalized["argv_patterns"] = normalized_patterns
        elif kind == "env":
            names = _strings(rule.get("names"), f"{label}.names")
            if any(not re.fullmatch(r"[A-Za-z_*?][A-Za-z0-9_*?]*", name) for name in names):
                raise PolicyError(f"{label}.names contains an invalid environment-name pattern")
            normalized["names"] = names
        elif kind == "network":
            normalized["hosts"] = _strings(rule.get("hosts"), f"{label}.hosts")
            for host in normalized["hosts"]:
                if any(char.isspace() for char in host) or "/" in host or "\x00" in host:
                    raise PolicyError(f"{label}.hosts contains an invalid host pattern")
            ports = rule.get("ports", [])
            if not isinstance(ports, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
                raise PolicyError(f"{label}.ports must contain integers from 1 through 65535")
            protocols = rule.get("protocols", [])
            if not isinstance(protocols, list) or any(
                not isinstance(protocol, str) or protocol not in {"tcp", "udp"}
                for protocol in protocols
            ):
                raise PolicyError(f"{label}.protocols may contain only 'tcp' and 'udp'")
            normalized["ports"] = ports
            normalized["protocols"] = protocols
        else:
            normalized["repositories"] = [
                _path_pattern(path, f"{label}.repositories")
                for path in _strings(rule.get("repositories"), f"{label}.repositories")
            ]
        rules.append(normalized)
    return {"version": 1, "default": "deny", "rules": rules}


def _validate_operation(raw: Any, index: int) -> dict[str, Any]:
    label = f"request.operations[{index}]"
    operation = _mapping(raw, label)
    kind = operation.get("type")
    if not isinstance(kind, str) or kind not in _OP_FIELDS:
        raise PolicyError(f"{label}.type must be one of {sorted(_OP_FIELDS)}")
    if set(operation) != _OP_FIELDS[kind]:
        missing = sorted(_OP_FIELDS[kind] - set(operation))
        unknown = sorted(set(operation) - _OP_FIELDS[kind])
        raise PolicyError(f"{label} fields mismatch (missing={missing}, unknown={unknown})")
    action = operation["action"]
    if not isinstance(action, str) or action not in _ACTIONS[kind]:
        raise PolicyError(f"{label}.action is unsupported for {kind}")
    normalized = dict(operation)
    if kind in {"path", "git"}:
        key = "path" if kind == "path" else "repository"
        normalized[key] = normalize_path(operation[key], f"{label}.{key}")
    elif kind == "command":
        argv = _strings(operation["argv"], f"{label}.argv")
        normalized["argv"] = argv
    elif kind == "env":
        name = operation["name"]
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            raise PolicyError(f"{label}.name must be a valid environment variable name")
    elif kind == "network":
        host = operation["host"]
        port = operation["port"]
        protocol = operation["protocol"]
        if not isinstance(host, str) or not host or any(char.isspace() for char in host) or "/" in host:
            raise PolicyError(f"{label}.host must be a hostname or IP address")
        if type(port) is not int or not 1 <= port <= 65535:
            raise PolicyError(f"{label}.port must be an integer from 1 through 65535")
        if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
            raise PolicyError(f"{label}.protocol must be 'tcp' or 'udp'")
        normalized["host"] = host.rstrip(".").lower()
    return normalized


def validate_request(value: Any) -> dict[str, Any]:
    request = _mapping(value, "request")
    if set(request) != {"version", "operations"}:
        extra = sorted(set(request) - {"version", "operations"})
        missing = sorted({"version", "operations"} - set(request))
        raise PolicyError(f"request fields mismatch (missing={missing}, unknown={extra})")
    if request["version"] != 1 or isinstance(request["version"], bool):
        raise PolicyError("request version must be integer 1")
    if not isinstance(request["operations"], list):
        raise PolicyError("request operations must be a list")
    return {"version": 1, "operations": [_validate_operation(op, i) for i, op in enumerate(request["operations"])]}


def _digest(value: Any) -> str:
    """Hash normalized JSON without exposing policy or request contents."""
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def policy_digest(value: Any) -> str:
    """Return the SHA-256 identity of a normalized policy."""
    return _digest(validate_policy(value))


def compose_policies(values: Any) -> dict[str, Any]:
    """Compose validated policy layers while keeping rule identity unambiguous.

    Rules are evaluated in the supplied layer order. Explicit deny rules still
    override allows, while duplicate rule IDs are rejected so an explanation
    can always identify one source rule without silently shadowing a layer.
    """
    if not isinstance(values, (list, tuple)) or not values:
        raise PolicyError("policies must be a non-empty list")
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(values):
        policy = validate_policy(value)
        for rule in policy["rules"]:
            rule_id = rule["id"]
            if rule_id in seen:
                raise PolicyError(f"policies[{index}] duplicates rule id '{rule_id}'")
            seen.add(rule_id)
            rules.append(rule)
    return {"version": 1, "default": "deny", "rules": rules}


def _matches(rule: dict[str, Any], operation: dict[str, Any]) -> bool:
    kind = operation["type"]
    if rule["kind"] != kind or operation["action"] not in rule["actions"]:
        return False
    if kind == "path":
        return any(fnmatch.fnmatchcase(operation["path"], pattern) for pattern in rule["paths"])
    if kind == "command":
        if not any(fnmatch.fnmatchcase(operation["argv"][0], pattern) for pattern in rule["commands"]):
            return False
        if "argv_patterns" in rule:
            return any(
                len(pattern) == len(operation["argv"])
                and all(fnmatch.fnmatchcase(arg, mask) for arg, mask in zip(operation["argv"], pattern))
                for pattern in rule["argv_patterns"]
            )
        return True
    if kind == "env":
        return any(fnmatch.fnmatchcase(operation["name"], pattern) for pattern in rule["names"])
    if kind == "network":
        return (
            any(fnmatch.fnmatchcase(operation["host"], pattern.lower().rstrip(".")) for pattern in rule["hosts"])
            and (not rule["ports"] or operation["port"] in rule["ports"])
            and (not rule["protocols"] or operation["protocol"] in rule["protocols"])
        )
    return any(fnmatch.fnmatchcase(operation["repository"], pattern) for pattern in rule["repositories"])


def _summary(operation: dict[str, Any]) -> dict[str, Any]:
    kind = operation["type"]
    target: str
    if kind == "path":
        target = operation["path"]
    elif kind == "command":
        # Do not echo arguments: they can contain credentials or other sensitive values.
        target = operation["argv"][0]
    elif kind == "env":
        target = operation["name"]
    elif kind == "network":
        target = f"{operation['host']}:{operation['port']}/{operation['protocol']}"
    else:
        target = operation["repository"]
    return {"kind": kind, "action": operation["action"], "target": target}


def evaluate(policy_value: Any, request_value: Any) -> dict[str, Any]:
    policy = validate_policy(policy_value)
    request = validate_request(request_value)
    results: list[dict[str, Any]] = []
    for index, operation in enumerate(request["operations"]):
        matched = [
            (rule_index, rule)
            for rule_index, rule in enumerate(policy["rules"])
            if _matches(rule, operation)
        ]
        matched_rules = [rule for _, rule in matched]
        denies = [rule for rule in matched_rules if rule["effect"] == "deny"]
        allows = [rule for rule in matched_rules if rule["effect"] == "allow"]
        if denies:
            decision = "deny"
            decision_source = "explicit_deny"
            explanation = "explicit deny rule matched; deny rules override allows"
        elif allows:
            decision = "allow"
            decision_source = "explicit_allow"
            explanation = "one or more allow rules matched and no deny rule matched"
        else:
            decision = "deny"
            decision_source = "default_deny"
            explanation = "no allow rule matched; default is deny"
        results.append({
            "index": index,
            **_summary(operation),
            "decision": decision,
            "decision_source": decision_source,
            "explanation": explanation,
            "matched_rules": [
                {
                    "index": rule_index,
                    "id": rule["id"],
                    "effect": rule["effect"],
                    "reason": rule.get("reason", ""),
                }
                for rule_index, rule in matched
            ],
        })
    overall = "allow" if all(result["decision"] == "allow" for result in results) else "deny"
    return {
        "decision": overall,
        "policy": {
            "version": policy["version"],
            "sha256": _digest(policy),
            "rule_count": len(policy["rules"]),
        },
        "request": {
            "version": request["version"],
            "sha256": _digest(request),
            "operation_count": len(request["operations"]),
        },
        "operations": results,
    }
