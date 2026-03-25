# Contributing to Soroban CrashLab

Thanks for contributing. This project is maintainer-first and contributor-friendly: we optimize for clear issue scope, reproducible changes, and fast review cycles.

## Development setup

### Frontend

```bash
cd apps/web
npm install
npm run dev
```

### Core crate

```bash
cd contracts/crashlab-core
cargo test
```

## Branch and PR flow

1. Create a branch from `main` named `feat/<short-name>` or `fix/<short-name>`.
2. Keep PRs focused on one issue.
3. Link the issue in the PR description using `Closes #<number>`.
4. Include test evidence and reproduction notes for behavior changes.

## Quality bar

- changes are readable and maintainable
- no dead code or placeholder logic in merged PRs
- tests cover the introduced behavior
- docs are updated when user-facing behavior changes

## Security Guidance for Contributors
When adding new fuzz input handling:
- Treat all input as fully adversarial: assume any data entering via `CaseSeed` is malicious.
- Validate using `SeedSchema`: all new entry points that accept external seeds must validate them against a `SeedSchema` (from `seed_validator.rs`). Use the default schema or define appropriate bounds.
- Handle validation errors gracefully: do not panic on malformed input. Return errors or skip execution with a clear log. The `validate` method returns `Result<(), Vec<SeedValidationError>>`; propagate or handle these errors.
- Do not derive storage paths from untrusted data: if your code writes artifacts, never use raw payloads, seed IDs, or user-controlled strings in filenames. Use `compute_signature_hash` to generate safe identifiers.

When modifying artifact storage:
- Sanitize filenames: if deriving a name from untrusted data, remove path separators (`/`, `\`), null bytes, and relative path components (`..`). Prefer the signature hash.
- Prevent path traversal: ensure all path constructions use a safe base directory and resolve the final path to confirm it stays within the intended directory.
- Set file permissions: when creating files or directories, set permissions explicitly (e.g., `0o644` for files, `0o755` for directories). Do not rely on default umask.
- Handle storage exhaustion: catch I/O errors such as `ENOSPC` (no space left) and fail gracefully with a clear error message.

Security review checklist for PRs touching fuzz input or artifact storage:
- [ ] All new seed entry points call `validate` with an appropriate `SeedSchema`.
- [ ] Validation errors are handled without panicking.
- [ ] No code derives filenames directly from payload or seed ID without sanitization.
- [ ] If filenames are derived from untrusted data, is there explicit sanitization (remove path separators, resolve path)?
- [ ] File creation uses explicit permissions (e.g., `OpenOptions::new().mode(0o644)`).
- [ ] Storage I/O errors are handled and do not cause silent data loss.
- [ ] New code does not introduce null-byte vulnerabilities (e.g., by passing payloads to C APIs without checks).


## Review expectations

- Maintainers prioritize active Wave issues during the sprint window
- Contributors should respond to review comments within 24 hours when possible
- Unresolved architectural debates should move to issue discussion to keep PRs focused

## Resolution policy

- If work quality is acceptable but merge is blocked for external reasons, resolve per Wave guidance so contributor effort is credited
- Move partial work to follow-up issues with clear boundaries

## Post-resolution feedback

- Leave practical, direct feedback
- Highlight what was done well and what should improve
- Keep comments specific to code and collaboration behavior
