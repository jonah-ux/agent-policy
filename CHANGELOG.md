# Changelog

All notable changes to this project are documented here.

## [0.2.0] - Unreleased

- Added structured deny-by-default policy evaluation for paths, commands, environment variables, network destinations, and Git operations.
- Added validation, explicit deny precedence, explainable operation results, and non-executing CLI receipts.
- Added synthetic fixtures and cross-platform CI/build checks.

## [0.1.0] - 2026-09-30

- Initial public release.
- Added deny-by-default JSON policy evaluator for paths, commands, environment variables, networks, and Git.
- Added `check`, `explain`, and non-executing `dry-run` CLI commands with optional receipts.
- Added safe lexical workspace path normalization and synthetic fixtures.
