# Release provenance

Agent Policy publishes source releases from annotated `vMAJOR.MINOR.PATCH` tags. The release
workflow checks that the tag version matches `pyproject.toml`, that the annotated tag resolves to
the checked-out commit, builds a wheel and sdist, writes `SHA256SUMS`, and installs the wheel in a
clean virtual environment before publishing prerelease assets.

The public audit checks these workflow markers and the tracked source surface. It does not claim
that GitHub, the package index, or a downstream machine provides a complete supply-chain guarantee.
Artifact verification is only `pass` when an explicit distribution directory and checksum manifest
are supplied; otherwise the audit reports `unavailable`.
