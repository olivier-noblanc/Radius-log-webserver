# Codex Instructions

## Philosophy: 10-Year, No-Maintenance Rust
- Prefer using crates (including GitHub-sourced) to reduce custom code when it improves clarity and long-term stability.
- This project is Windows-only and will not be ported; optimize for Windows APIs and behavior.
- Prefer deterministic behavior and reproducible builds (pin versions, avoid time-based logic in core paths).
- Keep public interfaces conservative; avoid breaking changes unless necessary.
- Use explicit error handling and clear logging for future debugging with no maintainer context.

## Shell Usage
- Run all terminal commands with PowerShell profile disabled to avoid PSReadLine noise.
- Implementation: use `login: false` for `shell_command` tool calls.
- Prefer `cmd /c` for shell commands when possible.

## Repo Map (Primary Navigation)
Use this map before searching:
- Entry points: `src/main.rs`, `src/lib.rs`, `build.rs`, `Cargo.toml`, `Cargo.lock`
- API handlers: `src/api/handlers/audit.rs`, `src/api/handlers/logs.rs`, `src/api/handlers/stats.rs`, `src/api/handlers/websocket.rs`, `src/api/handlers/web_ui.rs`
- UI components: `src/components/security_audit.rs`, `src/components/dashboard.rs`, `src/components/header.rs`, `src/components/layout.rs`, `src/components/log_detail.rs`, `src/components/log_filters.rs`, `src/components/log_table.rs`, `src/components/modals.rs`
- Infrastructure: `src/infrastructure/tls.rs`, `src/infrastructure/security_audit.rs`, `src/infrastructure/win32.rs`, `src/infrastructure/file_watcher.rs`, `src/infrastructure/cache.rs`
- Assets/i18n: `assets/`, `locales/`
- CI workflows: `.github/workflows/*.yml` (codeql, deny, frontend-lint, nightly, osv-scanner, release, rust-ci, typos, zizmor)
- Tooling/policy: `deny.toml`, `typos.toml`, `dprint.json`, `DEPENDENCIES.md`, `scripts/`

## Search Strategy (Avoid Broad Searches)
- Use the repo map first.
- If needed, run scoped searches (e.g., `rg -n --glob src/infrastructure/** pattern`).
- Avoid repo-wide `rg` unless the map is insufficient.
 - When using `cmd /c`, remember that `|`, `(`, `)` are command operators. Escape them with `^` inside quoted patterns, or wrap the whole command in `powershell -NoProfile -Command` to avoid cmd parsing issues.
 - Prefer `rg` over PowerShell pipelines for quick counts or searches; if you need a line count, use a tiny `python -c` one-liner instead of `Measure-Object` (it avoids PS parsing pitfalls in this environment).

## CI/CD
- For GitHub Actions failures: list runs, then fetch failed logs first (`gh run view <id> --log-failed`).
- Summarize failures briefly, apply minimal fixes, avoid workflow churn unless needed.

## Formatting
- Run `cargo fmt` after Rust changes.

## Default Proposals I Will Apply
- Prefer targeted fixes that unblock CI without broad refactors.
- Keep changes small and localized to the failing area.
- Add comments only when future maintenance would otherwise be unclear.

## Frontend Lint
- `oxlint assets/js` can be run directly to validate JS lint without building the Rust `frontend_lint` binary.
