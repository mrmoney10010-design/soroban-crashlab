# Maintainer Wave Playbook

This document defines how Soroban CrashLab is operated during Drips Wave cycles.

## 🌊 Wave 3 Specific Context
- **Contributor Limit**: Each contributor can resolve a maximum of **4 issues** across this entire org (down from 7 last wave). Keep an eye on assigning too many issues to a single applicant.
- **Application Rejections**: Explicitly and quickly **reject** applicants who are not a fit or if we are waiting for a specific profile. Do not leave them pending; rejecting them immediately returns their application quota.
- **24-Hour Review SLA Alert**: AI point appeals explicitly drop in when maintainers are unresponsive for >24 hours. Given our strict "Definition of Done", we risk automated points bypassing our review if we dawdle. Review inside 24h!

## Issue triage board queries

Use the following saved search queries to filter the issue board during triage.

### Pending review

Issues with open PRs awaiting maintainer review:

```
is:open is:issue label:wave3 linked:pr
```

### Stale

Issues assigned but with no activity in the last 3 days:

```
is:open is:issue label:wave3 assignee:* updated:<YYYY-MM-DD>
```

Replace `<YYYY-MM-DD>` with a date 3 days before today. For example, if today is 2026-03-25, use `updated:<2026-03-22`.

### Blocked

Issues explicitly marked as blocked on dependencies or external factors:

```
is:open is:issue label:wave3 label:blocked
```

If the `blocked` label does not exist, create it with color `d93f0b` and description "Blocked on dependency or external factor".

## Pre-wave checklist

1. Validate that each candidate issue has scope, acceptance criteria, and complexity.
2. Ensure issue labels are consistent:
   - `wave3`
   - `complexity:trivial|medium|high`
   - area labels such as `area:fuzzer`, `area:web`, `area:dx`
3. Confirm issue dependencies are explicit.
4. Keep an adequately sized open issue backlog ready for the new 4-issue org limit (i.e. more issues require spreading out to higher volume of distinct contributors).

## Assignment policy

- Prioritize first-time contributors on trivial and medium issues.
- **Do not** assign more than 4 issues historically to the same contributor across the org.
- Reject misaligned applications quickly using the Wave UI so contributors can reapply elsewhere.
- If no progress update is posted in 24 hours, request a status check and un-assign if unresponsive.

## PR review policy

Review inside 24 hours to prevent unnecessary automated appeals. Review in this order:

1. Correctness and safety
2. Adherence to the strict "Definition of Done" provided in the issue
3. Deterministic reproducibility of behavior
4. Test coverage
5. Clarity and maintainability

## Operational Security Assumptions

### Deployment Trust Assumptions
- The fuzzer runs in an isolated CI environment with no network access to external services during execution.
- Artifact storage is configured by the operator with appropriate permissions (e.g., `0o644` for files, `0o755` for directories) to balance reproducibility and security.
- All security-critical operations (e.g., classification, signature hashing) are deterministic and do not rely on external state.

### Reviewing PRs that touch security-relevant areas
When reviewing changes to fuzz input handling:
- Ensure all new entry points that accept external seeds call `SeedSchema::validate` (or equivalent) before using the seed.
- Verify that validation errors are handled without panicking; the code should return errors or skip execution.
- Confirm that no storage paths are derived directly from untrusted seed data (payload, ID) without sanitization.

When reviewing changes to artifact storage:
- Verify that any filename generation uses either the signature hash (`compute_signature_hash`) or applies strict sanitization (remove path separators, resolve paths).
- Check that path construction uses a safe base directory and resolves the final path to prevent traversal.
- Ensure file creation sets explicit permissions (e.g., `OpenOptions::new().mode(0o644)`) rather than relying on default umask.
- Confirm that I/O errors (e.g., disk full) are handled gracefully and do not cause panics.

### Known gaps and accepted risks
- **Null-byte validation**: The payload validator does not reject null bytes (`0x00`). Contracts that treat payloads as C-style strings may misinterpret them. *Residual risk*: low to medium, depending on contract expectations. *Mitigation*: integrators may add additional checks if needed.
- **Path traversal protection**: The library does not provide built-in sanitization for filenames. If integrators derive names from untrusted data without sanitization, directory traversal is possible. *Residual risk*: high if raw payload is used in paths. *Mitigation*: always use the signature hash for filenames.
- **Automatic validation enforcement**: The library does not prevent use of an invalid `CaseSeed`. If `validate` is not called, invalid seeds may cause panics (e.g., oversized payloads). *Residual risk*: medium. *Mitigation*: code reviews must ensure validation is performed.
- **File permission management**: The library does not set permissions on artifact files. *Residual risk*: artifacts may be world-writable or overly permissive. *Mitigation*: integrators must set explicit permissions.
- **Storage exhaustion**: No built-in handling for full disk or quota errors; these propagate as I/O errors. *Residual risk*: denial of service. *Mitigation*: monitor disk space and handle errors at the storage layer.
- **CI security scanning**: The CI pipeline runs only tests and linting. There is no dependency vulnerability scanning, SAST, or fuzz input security checks. *Residual risk*: undetected vulnerabilities in dependencies or code. *Mitigation*: integrate additional security tools (e.g., `cargo audit`, `cargo clippy` with security lints) – this is a planned improvement.

### CI security checks
- **Existing checks**:
  - Rust: `cargo test --all-targets` (compilation and unit tests)
  - Web: `npm run lint` and `npm run build`
- **Missing checks** (gaps):
  - Dependency vulnerability scanning for Rust (`cargo audit`) and npm (`npm audit`).
  - Security-focused linter rules (e.g., `cargo clippy` with `--deny=unsafe_code` or similar).
  - Fuzz input validation tests (e.g., property tests for `SeedSchema` edge cases).
  - Artifact storage permission checks (e.g., verify that generated files have expected modes).

## Resolution policy

- If work quality is acceptable but merge is blocked for external reasons, resolve per Wave guidance so contributor effort is credited.
- Move partial work to follow-up issues with clear boundaries.

## Contributor SLA targets

These timers define the maximum response and review windows for every
participant in the Wave sprint. All times are wall-clock hours from the
triggering event.

| Event | Timer | Owner | Escalation after |
|---|---|---|---|
| New application received | 24 h | Wave maintainer | Wave lead at 36 h |
| Issue assigned — first contributor update | 24 h | Assigned contributor | Un-assign + re-open at 48 h |
| PR submitted — first maintainer review | 24 h | Assigned reviewer | Any available maintainer at 36 h |
| PR review comment — contributor response | 48 h | Assigned contributor | Stale label + ping at 60 h |
| Merge-blocked PR — external dependency resolved | 24 h | Blocking maintainer | Wave lead escalation at 36 h |
| New triage issue (unlabelled, unassigned) | 48 h | Triage maintainer | Wave lead at 72 h |

> **Why 24 h for PR review?** Drips Wave automated appeals trigger when
> maintainers are unresponsive for more than 24 hours. Missing this window
> risks automated point grants that bypass our Definition of Done review.

### Escalation path

1. **At threshold** — the owner posts a status update in the issue or PR.
   No action needed from maintainers if an update is present.
2. **At escalation timer** — any wave maintainer may step in, re-assign,
   or apply the `stale` label and request a response within 12 hours.
3. **After stale label + 12 h silence** — wave lead un-assigns, re-opens
   the issue for the next contributor, and notes the outcome in the wave log.
4. **PR review >24 h (automated appeal risk)** — any available maintainer
   must review immediately regardless of original assignment. Comment
   `reviewed-by: @<handle>` to mark ownership.

### Running the SLA check

Use `scripts/check-sla.sh` to surface open items past their SLA window:

```bash
# requires: gh CLI authenticated as a maintainer
bash scripts/check-sla.sh
```

The script lists open PRs with no review past 24 h and assigned issues
with no update past 48 h. It exits non-zero when breaches are found so
it can be wired into a CI schedule.

## Post-resolution feedback

- Leave practical, direct feedback.
- Highlight what was done well and what should improve.
- Keep comments specific to code and collaboration behavior.
