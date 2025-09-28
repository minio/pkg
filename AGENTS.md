# Repository Guidelines

## Project Structure & Module Organization
Packages are scoped by capability at the repo root (for example `policy`, `ldap`, `randreader`, `sync`). Shared primitives live in `env`, `net`, `safe`, and `xtime`, while integration helpers such as certificates sit under `certs/`. Tests follow Go’s convention of co-locating `_test.go` files beside the code they exercise. No secondary Go modules exist; the single `go.mod` at the root governs builds.

## Build, Test, and Development Commands
- `make lint` – installs tooling via `make getdeps` when missing, then runs `golangci-lint` with the repo’s strict config.
- `make test` – executes `make lint` and `go test -race -tags kqueue ./...` to cover all packages.
- `make test-ldap` – focuses on the `ldap` package against the endpoint defined in `LDAP_TEST_SERVER`.
- `make clean` – removes cache binaries and editor swap artifacts.
Run these commands before opening a pull request; they mirror the CI stack.

## Coding Style & Naming Conventions
Always format Go sources with `gofmt`/`goimports`. Follow the CLAUDE guidance from `miniohq/eos`: keep comments minimal, explaining **why** the code exists, never **what**, and do not leave “removed because” notes when deleting code. Use descriptive package names that mirror directory names and exported identifiers with GoDoc-ready sentences. Stick to tab-indented Go style and avoid introducing logging or HTTP helpers that bypass established patterns in sibling MinIO repos without prior discussion.

## Testing Guidelines
Write focused unit tests in `_test.go` files and organize table-driven tests for edge cases (credentials, policy evaluation, network fallbacks). Include subtests for protocol-specific behavior. Always run `make test`; add targeted benchmarks (`go test -bench`) when optimizing hot paths and share before/after numbers in review.

## Commit & Pull Request Guidelines
Structure commits around single concerns with imperative subjects (e.g., `Add`, `Fix`, `Remove`). Reference GitHub issues where applicable. Pull requests must describe motivation, list validation commands, call out performance impact, and note any documentation updates. Keep feedback actionable—mirroring CLAUDE’s expectations—and ensure CI is green before requesting review.

## Security & Configuration Tips
Treat secrets, certificates, and credentials as sensitive: never commit real values. Validate inputs touching filesystem or network boundaries, rely on existing policy enforcement helpers, and update `README.md` when new environment variables or configuration flags are introduced.
