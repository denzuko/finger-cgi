# Contributing

## Workflow (BDD-first)

1. Open a GitHub Issue
2. Branch: `feat/N-description` or `fix/N-description`
3. Write Rego policy gate(s) first
4. Write xUnit tests in `tests.c`
5. Write code until `./nob test` passes and all Rego gates pass
6. Update `CHANGELOG.md` under `[Unreleased]`
7. Push → PR → review → squash merge
8. Semver tag on main

Never commit directly to main.
Never merge without explicit approval.

## Semver

- MAJOR — public CGI API break only
- MINOR — new non-breaking capability
- PATCH — everything else; freely exceeds 100

## Standards

- C99 only; no Python/Go/interpreted languages
- No `system()`, `popen()`, or `exec*()`
- BSD 2-Clause licence; SPDX header in every source file
- `net.matrix` identity in every binary (see `matrix_id.h`)
- BDD: Rego gate → `tests.c` → code → changelog → merge → tag
