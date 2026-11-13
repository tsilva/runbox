# Runbox

Read `SPECS.md` and the relevant linked guides before substantive changes. Work
on the current branch and preserve other tools and unmigrated consumers.

Use `.runbox.yaml` as data. Keep credentials and machine approvals outside Git.
Never add raw-key fallback, automatic approval on failure or repository-loaded
privileged plugins. Keep provider scope and execution policy independent.

Before completion, run the unittest suite, build the archive twice and compare
checksums. Exercise changed transport or sandbox behavior with fake credentials
and the actual selected client. Preserve existing restrictions during migration.
Use bounded read-only live checks only after fake checks pass. Never use real
inference or user documents as migration fixtures.

Keep public docs reproducible and operator-independent. Private reports and
captures belong under ignored `.internal/`. Preserve archived repository state; publication requires the authorized scope
and any necessary explicit archive-state exception. Preserve existing scopes,
schedules, concurrent edits and ordinary standalone use.
Track every configured route and verify it before removing its old launcher.
