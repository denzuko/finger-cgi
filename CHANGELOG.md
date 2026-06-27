# Changelog

All notable changes to finger-cgi are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.0] — 2026-06-27

### Added

- Initial release. CGI finger gateway — C99/kcgi, arena allocation, BSD sandbox, Da Planet stack.
- `matrix_id.h` — net.matrix CMDB identity strings baked into binary at
  compile time. All survive `-O2`. Canonical owner: `main.c` (stub).
- `nob.c` — tsoding-style build driver; VERSION + MATRIX_FLAGS as single
  source of truth. Targets: build, test, install, clean.
- `tests.c` — xUnit suite: domain tests + net.matrix identity assertions +
  SLSA provenance path tests (`fopen`/`fseek`/`errno` pattern).
- `policy/slsa.rego` — SLSA provenance gate (3 deny rules).
- `policy/c_quality.rego` — SARIF quality gate + 7-prefix net.matrix
  attribution check.
- `policy/code_conventions.rego` — forbidden call gate (`system`,
  `popen`, `exec*`).
- `.github/workflows/ci.yml` — test / sast / sbom / opa-gate pipeline.
  No containers job (panix CGI deploy, out of scope).
- `.github/workflows/slsa.yml` — SLSA Level 3 provenance pipeline.
- Full governance scaffold: BSD-2-Clause, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md, CODEOWNERS, issue templates.

---
