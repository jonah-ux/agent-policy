# Releasing

1. Update the version in `pyproject.toml`, `src/agent_policy/__init__.py`, and `CHANGELOG.md`.
2. Run the supported test matrix locally where available:

   ```console
   python -m pip install -e '.[dev]'
   pytest
   python -m build
   ```

3. Inspect wheel and source archive contents with `python -m zipfile -l dist/*.whl` and `tar -tzf dist/*.tar.gz`.
4. Create a signed, reviewed annotated tag only after CI is green. Build artifacts must be generated from the tag in a clean checkout.
5. The configured release workflow validates the tag identity, builds wheel/source/checksum assets, installs both artifact types in fresh environments, runs the CLI smoke check, and creates a GitHub prerelease.
6. Verify the published artifact in a fresh Python 3.11+ environment and run the installed demo using only synthetic fixtures.

A release is not an enforcement mechanism. Document any separately deployed sandbox or platform controls in the release notes.
