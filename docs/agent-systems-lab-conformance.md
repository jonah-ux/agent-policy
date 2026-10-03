# Agent Systems Lab policy conformance

Agent Policy remains the owner of `agent-policy/v1` and its additive
`agent-policy/receipt/v1` machine-readable receipt envelope. This fixture and test make
its native decision boundary explicit without importing Agent Proof or changing
the policy evaluator's runtime behavior.

The manifest records the reviewed Agent Proof `agent-proof/interop/v1` adapter
as the downstream handoff owner, with an immutable revision and manifest SHA-256
pin. Agent Policy proves the fields it owns locally:
explicit allow, explicit deny, default deny, normalized policy/request hashes,
and fail-closed handling for traversal and unknown policy versions. The receipt
does not copy raw policy patterns into the normalized evidence surface; request
targets remain the bounded operation summaries owned by Agent Policy. `check --receipt`
may emit only the decision because that command deliberately omits detailed evaluation
fields; `explain` and `dry-run` receipts carry bounded policy/request digests and counts.

Run the focused test with `pytest tests/test_agent_systems_lab_conformance.py`.
The fixture is synthetic and contains no credentials, live paths, or provider
state.
