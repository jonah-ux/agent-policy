# Changelog

All notable changes to this project are documented here.

## [0.2.0] - Unreleased

- Added structured deny-by-default policy evaluation for paths, commands, environment variables, network destinations, and Git operations.
- Added validation, explicit deny precedence, explainable operation results, and non-executing CLI receipts.
- Added deterministic policy and request SHA-256 identities plus decision-source and rule-position fields for audit-friendly explanations.
- Added ordered `compose_policies` layers and the `compose` CLI; duplicate rule IDs fail closed instead of silently shadowing a layer.
- Added synthetic fixtures and cross-platform CI/build checks.

## [0.1.0] - 2026-09-30

- Initial public release.
- Added deny-by-default JSON policy evaluator for paths, commands, environment variables, networks, and Git.
- Added `check`, `explain`, and non-executing `dry-run` CLI commands with optional receipts.
- Added safe lexical workspace path normalization and synthetic fixtures.
