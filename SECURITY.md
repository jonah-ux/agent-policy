# Security policy

## Scope and threat model

`agent-policy` is a pure decision engine. It parses structured policy and request data and returns allow/deny results. It does not execute commands, open sockets, read or write requested paths, alter environment variables, invoke Git, or install a kernel/OS hook. The receipt explicitly records `performed: false`.

The package is therefore not a sandbox and cannot contain a malicious or compromised process by itself. Pair it with a separately configured OS sandbox, container, VM, or platform policy enforcement layer when actual prevention is required. Treat policy and request files as configuration and validate their provenance before use.

Path checks are lexical workspace-relative checks. They reject absolute paths, home-directory syntax, NUL bytes, and parent traversal. They do not resolve symlinks or establish filesystem boundaries. Command matching is structured argv matching; it is not shell parsing.

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability. Email the maintainers through the security contact configured for the repository, including a minimal reproduction, affected version, Python version, and impact. Do not include credentials or personal data. We will acknowledge reports when practicable and coordinate a fix and disclosure timeline.

If no private contact is configured, open a GitHub issue with only the title `Private security contact requested`; do not include vulnerability details.
