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
captures belong under ignored `.internal/`. Do not unarchive or push the archived
Repologogen pilot; its migration remains local. Existing broker jobs, global
defaults and other repository launchers are outside this pilot's scope.
