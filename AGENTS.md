# AGENTS.md

Guidance for coding agents operating in this repository.

## Project Snapshot

- App: **PDWN** (Personal Data Watch & Neutralize)
- Stack: **Tauri 2 + Rust backend + TypeScript/Vite frontend + Bun tooling**
- Primary code roots:
  - Frontend: `src/`
  - Tauri/Rust: `src-tauri/src/`
  - CI/workflows: `.github/workflows/`

## Rules Files Check

- `.cursor/rules/`: **not present**
- `.cursorrules`: **not present**
- `.github/copilot-instructions.md`: **not present**

If any of these are added later, treat them as authoritative and update this file.

## Install / Setup

```bash
bun install
```

Optional (hooks):

```bash
bun run prepare
```

## Build / Dev Commands

- Frontend dev server:

```bash
bun run dev
```

- Tauri desktop app in dev:

```bash
bun tauri dev
```

- Frontend build:

```bash
bun run build
```

- Desktop production bundle:

```bash
bun tauri build
```

## Lint / Format / Typecheck

- Lint:

```bash
bun run lint
```

- Format (write):

```bash
bun run fmt
```

- Format check (CI-style):

```bash
bun run fmt:check
```

- TypeScript typecheck:

```bash
bun run typecheck
```

- i18n consistency check:

```bash
bun run i18n:check
```

## Test Commands

- Run all Rust tests:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

- Run one Rust test by name (exactly):

```bash
cargo test --manifest-path src-tauri/Cargo.toml integration_dataset_detection_consistency -- --nocapture
```

- Run tests in one Rust module/file pattern (example):

```bash
cargo test --manifest-path src-tauri/Cargo.toml secrets::tests
```

- Run one specific test in a module (example):

```bash
cargo test --manifest-path src-tauri/Cargo.toml secrets::tests::detects_bearer_tokens
```

Note: there is no standalone frontend unit-test runner configured in `package.json` currently.

## Integration Dataset Commands

- Refresh integration dataset:

```bash
bun run dataset:sync
```

- Validate integration dataset behavior:

```bash
bun run test:integration
```

- Refresh + validate in one step:

```bash
bun run test:integration:refresh
```

## Full Local Quality Gate

```bash
bun run check
```

This runs TS checks + formatting + i18n + Rust fmt/clippy/tests.

## Pre-commit / Pre-push Hooks

Configured with `lefthook.yml`:

- `pre-commit`: `fmt:check`, `typecheck`, `i18n:check`, `cargo fmt --check`, `cargo clippy -D warnings`
- `pre-push`: `bun run check`

Agents should run `bun run check` before creating a PR.

## Code Style: TypeScript / Frontend

- Formatter/linter: **Biome** (`biome.json`)
- Indentation: **2 spaces**
- Max line width: **100**
- Quotes: **double quotes**
- Semicolons: **always**
- Organize imports enabled; keep imports tidy and unused imports removed.

Conventions observed in `src/`:

- Use `camelCase` for variables/functions.
- Use `PascalCase` for types and type aliases.
- Use `SCREAMING_SNAKE_CASE` only for true constants.
- Prefer explicit return types for exported functions.
- Prefer narrow unions for domain enums (e.g., risk levels).
- Use `type` imports where possible (`import { type Foo } from ...`).

API shape convention:

- Keep backend wire field names in `snake_case` for Tauri command payloads/DTOs.
- Keep local JS/TS state/function names in `camelCase`.

Error handling:

- Use `try/catch` around async command boundaries.
- Convert unknown errors safely via `error instanceof Error ? error.message : String(error)`.
- Do not swallow errors silently; surface actionable context in UI state/logs.

## Code Style: Rust / Backend

- Formatting: `cargo fmt`
- Lints: `cargo clippy -- -D warnings` (warnings are treated as errors)

Conventions observed in `src-tauri/src/`:

- Modules/files: `snake_case`
- Functions/variables: `snake_case`
- Types/enums/traits: `PascalCase`
- Constants/statics: `SCREAMING_SNAKE_CASE`
- Prefer `Result<T, String>` at Tauri command boundaries.
- Map internal errors with context (`map_err(|e| e.to_string())` or richer messages).
- Use `tracing` for command-level observability.

Error handling:

- Avoid `unwrap()`/`expect()` in runtime paths.
- `unwrap_or_default` is acceptable when default fallback is explicitly safe.
- In tests, panics with detailed messages are acceptable.

## i18n and Content

- Keep locale files (`src/locales/*.json`) structurally aligned.
- Any new translation key should be added for all supported locales.
- Run `bun run i18n:check` after locale updates.

## CI Expectations

Main workflows currently include:

- `ci.yml` (frontend + rust quality)
- `security.yml` (secrets/audits)
- `coverage.yml` (Rust coverage gate)
- `release.yml` and `pages.yml` (release + website)

Agent changes should not weaken these gates without explicit user approval.

## PR Guidance for Agents

- Keep changes scoped and cohesive.
- Prefer minimal diffs over broad refactors.
- Update docs when commands, workflows, or behavior change.
- For security-sensitive paths (detection, deletion, persistence), call out risk explicitly in PR notes.
