# Team Learnings

This document tracks strict engineering guardrails, root causes of code review failures, and prevention rules established to ensure codebase quality and security.

## Review Failures & Prevention Rules

### 1. Database Concurrency & Race Conditions (Lost Updates)
- **Failure Root Cause:** A client-side read-modify-write pattern on statistics/ledger database columns resulted in concurrent lost updates when the RPC server failed.
- **Rule:** Bypassing atomicity by implementing select-then-update sequences is prohibited. Always use native atomic increments or upserts (e.g., `INSERT ... ON CONFLICT (key) DO UPDATE SET col = col + EXCLUDED.col`) or wrap read-modify-write patterns in transactions with explicit locks (`SELECT ... FOR UPDATE`).

### 2. Client-Controlled Financial & Verification Boundaries
- **Failure Root Cause:** Server actions trusted price/cost values passed directly from the client, allowing malicious users to spoof purchase parameters and bypass the correct database rates.
- **Rule:** Never trust transaction costs or balances submitted by the client. Financial, permission, and pricing values must always be resolved on the server side by querying the database using secure unique identifiers.

### 3. Rich Text Tag Sanitization & Allowlist Consistency
- **Failure Root Cause:** Allowed attributes were defined for tags (such as `div`) that were omitted from the permitted tags allowlist. This caused the HTML sanitization library (Cheerio) to silently delete those tags along with all nested children, resulting in data loss.
- **Rule:** All HTML tags configured with allowed attributes in rich-text sanitizers must be explicitly added to the allowed tags list. Periodically audit sanitization rules to ensure no valid structural tags are silently deleted.

### 4. TypeScript Strict Compilation Constraints
- **Failure Root Cause:** The compilation broke due to unsafe index access (e.g., accessing `array[0]` without checking if it is `undefined` when `noUncheckedIndexedAccess` is enabled) and missing type-only import syntax (`verbatimModuleSyntax` violations).
- **Rule:** Always perform explicit type checking or existence checks on array/object elements fetched by index. When type-only imports are required, strictly use `import type` instead of standard imports to prevent runtime/compiler errors.

### 5. Deployment Orchestration & Race Conditions
- **Failure Root Cause:** The GitHub Actions preview deployment workflow ran in parallel with build tasks, causing image signature verification (`cosign`) to fail because the images were not yet built or signed.
- **Rule:** Deployment pipelines must be sequenced to run *after* successfully building, pushing, and signing release/container images. Use `workflow_run` triggers or job dependencies to enforce correct build ordering.

### 6. Postgres App Migration Mismatch (Fly.io)
- **Failure Root Cause:** Database migrations were applied to a default database before consumer attachment, meaning the newly created, app-specific database remained empty when the application booted.
- **Rule:** Database instances must be fully attached and initialized before running schema migrations. Migrations must target the exact, app-specific database configuration and should be executed using Fly CLI controls or machine-level execution rather than local/mock database connections.
