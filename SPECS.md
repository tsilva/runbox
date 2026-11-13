# Runbox

## Accepted scope

Runbox is a separate provider-neutral runner, named `runbox`, with one maintained
repository file, `.runbox.yaml`. It replaces duplicated repository credential
launchers progressively, beginning with the local archived Repologogen checkout.
Existing consumers remain installed and unchanged until individually migrated.

Infisical Agent Vault is the initial provider. Translate approved options into
native CLI arguments without maintaining another native YAML file. Retain source
metadata without retrieving secret values. Provider adapters and execution
policies remain separate so another provider or sandbox can be added later.

Ordinary commands use placeholders, scoped process-local proxy sessions, a
pinned instance and CA, bounded TTL and native revocation. They never renew keys,
fetch raw credentials or widen service permissions. The renewal broker remains a separate privileged component while consuming the
same Runbox configuration; it must preserve its registered scope and schedules. Repository configuration cannot approve itself; trusted local
approval binds configuration, runtime and relevant source integrity.

Preserve Repologogen's existing service scope, Python command, macOS sandbox,
staging-only writes and credential-read/egress restrictions. Keep its GitHub
repository archived and retain its deprecation notice. Verify with synthetic
actual-client requests, application tests and a bounded read-only live check;
do not submit real inference or personal data for migration testing.

## Fleet migration

Migrate every previously configured repository and local service setup to Runbox.
The maintained inventory determines completion. Consolidate native and broker
Infisical YAML into `.runbox.yaml`; leave no `.infisical.yaml` or
`.infisical.*.yaml` files in the maintained fleet. Replace duplicated credential
launch wrappers with shared Runbox capabilities and verify each established route
without weakening scopes or protections. Preserve concurrent work and existing
credential-renewal behavior. Previously unavailable upstream access remains an
explicit limitation, never a reason for fallback.

Runbox invocation belongs outside ordinary application/package commands. Agents
read each root configuration and use its declared command profiles. Explicit
neutral executor inputs may be supplied externally; applications must not
automatically discover a personal runner or require it for normal operation.

Keep active applications, scheduled jobs and admitted remote workloads running.
Preserve their reviewed session lifetimes and ownership; controller cleanup must
not revoke an already admitted detached worker. Command compatibility can use
links to the shared runner with owner-reviewed metadata, without copied wrapper code.

Runbox is optional personal agent tooling. Normal repository commands and
end-user setup must work without it. Remove obsolete agent-specific launch
instructions from consumer docs; retain only essential routing/security guidance
and necessary integration hooks. Do not replace domain-specific application logic
with launcher machinery. Archived repositories remain archived.

## Renewable daemon sessions

Explicitly approved fixed HTTPS daemons may opt into finite session rotation.
A shared authenticated loopback CONNECT relay selects a fresh lease for new
connections while established tunnels drain on their original lease. Native
session lifetimes and service scope remain unchanged; no service keys are read.
Every replacement requires unchanged approved configuration, source, runtime,
public CA and release, followed by its configured read-only verification.

Rotation failure or approval drift denies new connections without restarting the
application or replaying requests. Existing tunnels retain only their original
finite lifetime. Owned daemon leases are revoked after draining or shutdown;
detached workers retain their separate admission and ownership rules.

## Deferred

Additional secret providers and new sandbox engines remain future extensions.
Unsupported transports need compatibility review and must fail explicitly without
raw-key injection or broadened permissions.
