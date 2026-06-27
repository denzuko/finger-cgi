# CLAUDE.md — finger-cgi

AI assistant context for this repository.

## Project

`finger-cgi` is a C99 CGI application deployed on NetBSD (panix.com).
Stack: kcgi/kcgihtml, tsoding arena.h/sv.h/nob.h, htmx, Alpine.js.

## Semver

- MAJOR — CGI API/interface break only
- MINOR — new non-breaking capability
- PATCH — everything else; freely exceeds 100; never bump MAJOR for restructuring

## Workflow (BDD-first)

Order is mandatory:

1. Open a GitHub Issue
2. Branch: `feat/N-description` or `fix/N-description`
3. Write or update Rego gate(s) in `policy/`
4. Write or update xUnit tests in `tests.c`
5. Write or fix code until `./nob test` passes and all Rego gates pass
6. Update `CHANGELOG.md` under `[Unreleased]`
7. Push → PR → review → squash merge
8. Semver tag on main

## Standards in force

- C99 (ISO/IEC 9899:1999), no GNU extensions
- BSD 2-Clause Licence; SPDX header in every source file
- NASA Power of Ten rules
- Tsoding conventions: arena.h zero-init, sv.h string views, Yoda conditions,
  single-exit with `goto cleanup` or `do-while(0)` + BAIL
- No `system()`, `popen()`, or `exec*()` — enforced by Rego AST gate
- `nob.h` as sole build driver: `cc nob.c -o nob && ./nob`
- net.matrix identity strings baked into binary (see `matrix_id.h`)
- `policy/c_quality.rego` verifies 7 required net.matrix prefixes in binary
- SLSA Level 3 provenance via `.github/workflows/slsa.yml`

## Deployment

Target: panix.com NetBSD shell account.
Binary installed to `~/public_html/cgi-bin/finger-cgi`.
No container target; `containers.rego` is out of scope.
