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

Every configured profile has a bounded read-only online service check. Adding a
check must preserve ordinary command behavior, scopes, required sandboxes and
existing jobs; a write-capable command is verified without performing its writes.

## Complete secret-access coverage

Find remaining active secret-access usages across repositories and local agent
and service setups, including usages outside the original migration inventory.
Agent-operated secret injection must use Runbox externally through declared,
reviewed profiles. Normal application commands remain independent of Runbox.
Hosted CI and production secret injection are outside this migration; discuss
that separate expansion with the owner before working on it.

Verify discovered usages individually: source and scope mapping, actual-client
compatibility, explicit activation and bounded read-only online access. Preparation
or metadata alone does not establish working coverage. Unsupported transports and
missing authorization remain explicit gaps; never hide them with raw credentials,
alternate logins or automatic trust renewal. Preserve separate trusted provisioning,
renewal, Git authentication and managed SSH policies. Exclude archived repositories
unless the owner currently authorizes a named archived operation.

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
System sleep must not extend a lease's local expiry or postpone renewal past
its server expiry. Either elapsed-time or wall-clock bounds can shorten access.

## Browser-public configuration — 17 November 2026

An explicitly selected `infisical-public-config` mode may retrieve named
browser-public settings from an approved Secret Manager source and supply them
to an exact, source-pinned local command through its process environment. This
mode intentionally exposes public browser configuration to the application and
browser. It is separate from Agent Vault and is never an authentication fallback.

Require explicit browser-public classification, public-prefixed variable names,
bounded format checks and lifetime, pinned native CLI/source trust and the same
owner-only configuration/runtime/source/release approvals as other profiles.
Fetch only selected settings with imports, expansion, recursion and personal
overrides disabled. Validate the complete set before starting the child. Keep
values out of argv, files, approval records and logs; sanitize errors and child
output. Reject broad command policies, inherited credentials and proxy/session
composition. Offline checks do not fetch; online checks read and validate only
the declared settings and report safe counts. Application commands remain
independent of Runbox. Existing credential-proxy routes retain their policies.

## Deferred

Additional secret providers and new sandbox engines remain future extensions.
Unsupported transports need compatibility review and must fail explicitly without
raw-key injection or broadened permissions.
