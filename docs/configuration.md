# Configuration

Runbox reads one `.runbox.yaml` at the Git root, or the selected directory for a
non-Git service. It is data, never privileged repository code. Unknown fields,
duplicate keys, aliases, explicit YAML tags, unsupported providers and invalid
scopes fail explicitly. There is no profile inheritance or environment override.

| Top-level field | Meaning |
| --- | --- |
| `version: 1` | Required schema version |
| `profiles` | Named, complete runnable policies |
| `default` | Required when runnable profiles exist |
| `bindings` | Optional source inventories; these grant no runnable access |
| `brokers` | Optional metadata validated by the separately installed trusted renewal broker |

`runbox run -- COMMAND ...` selects a unique profile matching the command and
argument policy. Ambiguous matches require `--profile NAME`; `check` uses the
default unless one is selected. Metadata-only configurations have no runnable
profile and cannot authenticate a command.

Retired `.access.toml`, `.access.local.toml`, `.infisical.yaml`, broker sidecars
and native `.infisical.json` conflict with a completed migration. They are not
merged or used as fallbacks. Keep personal configuration ignored locally when
other contributors do not need it; ordinary app commands should remain independent.

## Profiles and source inventories

Each profile requires `provider`, `session`, `environment` and `execution`.
Optional `http`, `services` and `ready` add reviewed behavior. `ready: false`
blocks ordinary execution before authentication; it does not establish that an
upstream route works merely because its metadata parses.

The initial provider is `type: infisical`, with `instance`, `project-id` and
`access-bundle`. The instance is an HTTPS origin. The project identifies Agent
Vault. Optional `source` retains a different Secret Manager `project-id`,
`environment` and absolute `secret-path`; it never authorizes retrieving values.
Optional `login-profile` selects the existing native CLI login profile;
`no-mcp-servers: true` retains an existing MCP-disabled session policy.
Runbox passes explicit native CLI flags and writes no native configuration file.
`native-config` renders the metadata view only.

A `bindings` entry uses `type: infisical`, `instance` and `source`, with optional
`description`, `variables`, `administration-only` and `branch-environments`.
Historical inventories may omit an unknown environment or path; runnable provider
sources must be complete. Inventory-only legacy `/api` instance prefixes are
preserved as metadata. An unbound inventory uses `type: unconfigured` with its
description and variable names, without a source or instance. `runbox bindings`
prints these validated inventories as JSON without authenticating.

`brokers` contains named renewal definitions. The trusted broker validates its
closed provider schema, identities, scopes, lifetimes and registered destinations.
Runbox does not renew credentials or turn broker metadata into ordinary access.

## Session and public environment

`session` requires a loopback `proxy` and bounded `ttl` between `1m` and `8h`.
Use the existing reviewed lifetime. Longer app or worker sessions are not a
reason to extend unrelated profiles. Optional reviewed `tunnel` and `worker`
settings are described in [execution](execution.md).

`environment` contains strings only: public settings and public placeholders.
Service credential variables require values ending in `_placeholder`. The
explicit public controls for disabled implicit Hugging Face credentials and
Clerk development configuration are validated separately. Real service keys,
passwords, private keys and OAuth tokens never belong here or in runtime JSON.

The parent starts from a clean environment. Proxy capabilities remain local to
the bounded native session; they must not be printed, saved, placed in command
arguments or exported into shell startup files. Public path substitutions resolve
only from approved runtime metadata. `{ca-base64}` encodes the reviewed public CA,
never its private key.

## Machine runtime and approvals

Keep the runtime JSON outside the checkout and owner-only. Required fields are
`infisical`, `ca-file` and `ca-fingerprint`. Optional fields are:

| Field | Verification |
| --- | --- |
| `python`, `python-root`, optional `venv` | Interpreter hash and canonical runtime relationship |
| `node` | Executable hash |
| `binaries: {name: path}` | Named executable hashes |
| `files: {name: {path, private?}}` | Canonical file hashes and required ownership/permissions |
| `directories: {name: {path, private?}}` | Canonical directory identity, owner and mode; dynamic contents are not hashed |
| `imports: [path]` | Approved Python dependency roots and directory identities |
| `integrity-files: [path]` | Explicit external SDK or installed-program file hashes |
| `path: [directory]` | Reviewed canonical directories prepended to child PATH; contents are not implicitly attested |

Named files, directories and binaries provide `{name}` substitutions; reserved
names and collisions are rejected. `macos-staging` also requires `venv`, with
`python` at `VENV/bin/python` resolving into `python-root`.

Owner-only approvals under `~/.config/runbox/approvals` bind the canonical root,
profile, complete YAML, selected source files, runtime, CA, archive, policy and
shared resources. `approve` is explicit trusted administration after reviewing
changes, never an automatic response to drift. A copied checkout or worktree
needs its own approval. Installing a new release preserves existing approvals:
ordinary commands first select their approved protected release, then validate it.
Missing releases or failed checks never trigger another credential route.

## Checks and command links

`runbox check` is offline. `check --online` executes only the configured bounded
read-only probe. Built-in HTTP probes support model catalogs, explicit JSON
identity/status assertions or status-only GETs that discard bodies. Optional
`http.additional-probes` are existing exact GET routes whose bodies are also
discarded. Other reviewed clients can provide a fixed `probe-argv`; their code
and runtime must remain pinned. Successful output contains only the safe result
schema, with optional model/item counts, never provider bodies or capabilities.

Compatibility commands can be hard links to the identical shared launcher:

```sh
runbox --repo /absolute/checkout --profile reader link /absolute/bin/read-data \
  --command your-command
```

The owner-only command registry records the target root, profile, fixed prefix
and launcher hash. Optional `--strip-prefix` accepts an exact JSON argument prefix;
`--rewrite-first` accepts a JSON pair. They preserve existing callers without
copied wrapper code. Every invocation still checks the target's existing approval.
Links do not approve configuration, broaden arguments or create service access.

Compatibility links that must retain a JSON stdin protocol can declare
`--stdin-dispatch` as reviewed JSON: `max-bytes`, a key `path`, scalar `equals`,
matching `profile`, matching `timeout`, `otherwise-timeout`, integer-record
`output-field` and `max-output-bytes`. The default link profile handles other
values. Both profiles must already pass approval checks. The dispatcher rejects
malformed/duplicate-key or oversized JSON before authentication, forwards the
exact bytes in memory, enforces the selected timeout and response bound, and
emits exactly one matching response record. No payload file or shell command is
created. This compatibility layer does not authorize the request's content.

## Explicit Node service composition

A shared `node-http` or `node-next` client can combine reviewed services without
repository modules importing Runbox. An additional HTTP route declares all three
fields together: exact `origin`, `credential-header` and public `placeholder`.
Its placeholder must also appear in the profile environment. Only HTTPS or
explicit loopback HTTP origins are supported; wildcard hosts, origin path
prefixes, credential-bearing URLs and forwarded-host overrides are rejected.
The guard keeps each service's authentication header isolated and rejects mixed
credentials before transport. Python and unsupported clients reject these
Node-only route overrides. Required network/sandbox rules remain independent.
