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
fetch raw credentials or widen service permissions. The existing renewal broker
remains separate. Repository configuration cannot approve itself; trusted local
approval binds configuration, runtime and relevant source integrity.

Preserve Repologogen's existing service scope, Python command, macOS sandbox,
staging-only writes and credential-read/egress restrictions. Keep its GitHub
repository archived and retain its deprecation notice. Verify with synthetic
actual-client requests, application tests and a bounded read-only live check;
do not submit real inference or personal data for migration testing.

## Deferred

Additional secret providers, new sandbox engines, automatic fleet migration,
broker integration and unsupported transports require future implementation and
compatibility review. They are not prerequisites for the initial pilot.
