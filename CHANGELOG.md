# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is `0.x`,
minor releases may contain breaking changes.

Entries that change a security guarantee are marked **[security]**.

## [Unreleased]

### Added

- Apache-2.0 license, `NOTICE`, contribution guide, code of conduct, and security policy with a
  scope statement distinguishing vulnerabilities from documented non-guarantees.
- `docs/ARCHITECTURE.md` describing components, the request lifecycle, and the trust boundary.
- GitHub Actions CI running tests and lint on Linux, macOS, and Windows against Python 3.12 and 3.13,
  plus a package build check.
- `ruff` lint configuration and `pytest-cov`, wired into the `dev` extra.
- Issue and pull request templates, and Dependabot for Actions and pip.

### Fixed

- **[security]** SQLite connections in the secret vault, policy repository, and audit log were never
  closed. `sqlite3`'s connection context manager governs the transaction, not the handle, so every
  operation leaked a file descriptor and left the database file locked on Windows — including the
  file holding encrypted secret material.
- Test collection failed on Linux and macOS because `tests/test_isolation.py` imported the Windows
  AppContainer backend at module scope, which binds `ctypes.wintypes` at import time. The import is
  now deferred into the platform-guarded tests.
- CLI exits raised from exception handlers now chain the originating error with `raise ... from`,
  so a policy or resolution failure is no longer masked in tracebacks.

### Changed

- Strict warning filters (`-W error`) in the pytest configuration, so resource and deprecation
  warnings fail the build instead of accumulating silently.

## [0.1.0] - 2026-08-21

Initial implementation.

### Added

- `secret://` reference parsing and normalization.
- AES-GCM encrypted local vault with a metadata-only administrative surface.
- Policy engine evaluating destination, method, and scheme **before** secret resolution.
- Explicit local transport at `/proxy/{host}/{path}` with external HTTPS origination, and rejection
  of HTTPS `CONNECT` rather than tunneling traffic the broker cannot inspect.
- Secret substitution across query strings, form bodies, JSON bodies, and headers, with exact-value
  redaction of responses, headers, and error traces.
- Metadata-only SQLite audit log with resolved URLs redacted before persistence.
- Reference-only session profiles, `.env` reference validation, and an environment allowlist that
  strips inherited credentials from managed children.
- Agent-agnostic `secretruntime run` launcher for Codex, Claude Code, Cursor, and Gemini CLI.
- Windows AppContainer isolation backend with loopback firewall rules scoped to the container SID.
- Administrative FastAPI application with no endpoint that returns a secret value.
- `secure-exec` limited compatibility mode for tools the broker cannot mediate.

[Unreleased]: https://github.com/MickaelCoelho/secret-runtime/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MickaelCoelho/secret-runtime/releases/tag/v0.1.0
