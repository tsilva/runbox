# Migration

Migrate one explicitly selected repository at a time. Existing global launchers,
broker jobs and other repository bindings keep their current behavior.

1. Inventory the old source identity, native Vault project/bundle, exact service
   routes, placeholder, runtime, public CA and existing sandbox protections.
2. Preserve the old files and local bindings for recovery. Prepare one
   `.runbox.yaml` with the same scope and a compatible execution policy.
3. Test fake credentials with the actual client, including denied routes,
   rejected credentials, failure sanitization and existing filesystem/network
   restrictions. Do not submit real prompts or documents as a migration test.
4. Remove the duplicate launcher and conflicting native configuration from the
   selected checkout, then explicitly approve the new configuration and runtime.
5. Run offline validation, CLI help, the application suite and a bounded online
   catalog check. Keep unsupported transports blocked; never widen a service
   or inject a real key to make a test pass.
6. Update authoritative usage instructions. Keep recovery material private and
   report exactly which repositories have migrated.

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
