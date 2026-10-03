# Release provenance

Agent Policy is a standalone, local policy evaluator. Its public release workflow requires an
annotated version tag to identify the checked-out commit, builds wheel and source distributions,
writes `SHA256SUMS`, and runs isolated package consumers before publishing a prerelease.

The `scripts/audit_public_surface.py` command emits `agent-policy-public-audit/v1`, covering
declared dependencies, the MIT license, release markers, tracked-text high-signal credential
patterns, and optional artifact checks. It is a release inspection aid, not complete DLP, a
security certification, or proof of deployment, adoption, or production readiness.
