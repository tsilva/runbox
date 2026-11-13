# Migration

Inventory every configured route, including protected runtime profiles, generated
local-service metadata, MCP adapters, global commands and scheduled jobs. Migrate
one complete root at a time; a shared native file cannot disappear while another
maintained route still depends on it. Existing consumers keep their behavior until
their own cutover is ready.

1. Inventory the old source identity, native Vault project/bundle, exact service
   routes, placeholder, runtime, public CA and existing sandbox protections.
2. Preserve the old files and local bindings for recovery. Prepare one
   `.runbox.yaml` with the same scope and a compatible execution policy.
3. Test fake credentials with the actual client, including denied routes,
   rejected credentials, failure sanitization and existing filesystem/network
   restrictions. Do not submit real prompts or documents as a migration test.
4. Remove the duplicate launcher and conflicting native configuration from the
   selected checkout, then explicitly approve the new configuration and runtime.
5. Run offline validation, applicable application checks and a bounded read-only
   probe. Record existing missing/stale dependency environments. Keep unsupported transports blocked; never widen a service
   or inject a real key to make a test pass.
6. Update authoritative usage instructions. Keep recovery material private and
   report exactly which repositories have migrated.

Preserve current branches, unrelated edits, active applications and running
workloads. Compatibility callers can keep their command paths through hard links
to the shared runner with exact argument translations. Owner-only approval records
are independent of the single maintained YAML. Historical source snapshots and
credential stores are not live configuration files to merge or delete.

Restore ordinary commands that use their normal environment; keep personal
`.runbox.yaml` locally ignored when appropriate. Remove pure launch/session/sandbox
wrappers and their copied tests. Retain genuine domain transport, API, signing,
renewal and provisioning logic with necessary integration checks. Do not disguise
an unsupported route as a working migration or fetch raw keys to make it pass.

Preserve scheduled renewal definitions and token lifetimes. If a running broker
must load a new configuration format, prepare and validate the replacement before
a controlled restart of that broker only. Never stop shared jobs as per-task
cleanup. Immutable active workload snapshots remain provenance until their owner
can retire them safely; maintained source and new invocations use Runbox.

## Repologogen pilot

The first pilot is the local checkout of archived Repologogen. It retains the
existing dedicated AgentBridge bundle, two exact model/chat routes, public
placeholder, reviewed Python environment, pinned proxy CA and macOS staging
sandbox. Source metadata remains Development `/agents/agentbridge`; source and
Vault projects retain their distinct identities. No keys are copied or fetched.

The local command becomes:

```sh
runbox check
runbox check --online
runbox run -- repologogen --help
```

The YAML replaces the native metadata file; shared Runbox code replaces the four
per-repository bootstrap files. Application code, model defaults, hosted routes
and the credential-renewal broker remain unchanged. GitHub stays archived;
local pilot edits are not pushed to the archived repository. Its existing
deprecation notice remains in place.

The model catalog proves only that the proxy/gateway reader is reachable. It
does not prove upstream model authentication, inference, image downloads or
external conversion tools. Those operations retain their existing limitations
and content-approval requirements.
