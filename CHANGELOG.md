# Changelog

All notable changes to finger-cgi are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.0] — 2026-06-27

### Added

- `main.c` — functional CGI binary. See README for feature list.
- `policy/ast.rego` — 90% coverage gate, forbidden call gate,
  unchecked strcmp result gate.
- Initial release. `main.c` functional CGI. SSRF-safe host whitelist, username sanitiser, BAIL macro, BSD sandbox via #ifdef HAS_SANDBOX, StrTable enum, htmx async form.
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
- `policy/ast.rego` — 90% coverage gate, forbidden call gate, unchecked strcmp gate.
- Full governance scaffold: BSD-2-Clause, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md, CODEOWNERS, issue templates.
  SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md, CODEOWNERS, issue templates.

---
