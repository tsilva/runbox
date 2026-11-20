# Execution policies

Provider access and process restrictions are independent. A provider change does
not remove an execution policy, and a failed required sandbox has no fallback.
All argv vectors are arrays, without shell interpolation.

## Ordinary and fixed commands

`execution: {sandbox: none}` permits an ordinary command that honors the native
proxy. It adds no OS isolation. For an existing restricted launcher that did not
use an OS sandbox, `none` can instead use the fixed-command fields below; source
and argument checks still apply without adding a sandbox.

A fixed command declares `command`, `argv`, `arguments` and `integrity`.
`arguments` is either `any` or a list of allowed argument arrays. Each token is an
exact string or `{pattern: '[0-9]{9}'}`. Patterns use full matching, flat character
classes and literals; groups, alternation and backreferences are excluded. Input
length is bounded. Prefer an exact policy whenever the existing command has one.

`integrity.files` lists relative source files; `integrity.directories` includes
complete reviewed source trees, excluding bytecode. Symlinked source is rejected.
Dependency installations require separate runtime review. Optional `dependencies`
checks exact installed Node package versions against the app manifest before run.

`probe-argv` is a separate fixed read-only check. `cwd` is `repo` or `workspace`;
`workspace` must name a staging directory under `.internal/`. A staging override
must remain beneath that approved root. Staging HOME is isolated there.

## macOS policies

`macos-staging` retains the original fixed Python console-entrypoint workflow:
`workspace`, `python.source`, `python.package`, `python.command` and
`python.entrypoint`, with optional exact `python.arguments`. Its built-in policy
allows reviewed runtime/source reads, staging writes and proxy-only egress.

`macos-command` uses the fixed-command fields and a data-only `permissions` map:

- `read`, `write` and optional `deny-read`: lists of `{file: path}`,
  `{directory: path}` or rooted `{pattern: regex}` predicates.
- `execute`: explicit approved executable paths.
- Optional `deny-all-writes: true`: deny writes globally before declared exceptions.
- Optional `network`: existing reviewed `localhost:PORT` relays in addition to
  the native proxy. `listen: true` permits local listeners; alternatively
  `listen-ports: [PORT]` confines binding to reviewed loopback ports.
- Optional `workspace-ipc: true` permits Unix socket binding and connections
  inside the private staging home and sets `TMPDIR` there. This requires a
  declared workspace and canonical, owner-only staging directories. Regular
  filesystem and TCP permissions still apply independently.

Paths expand from approved substitutions such as `{repo}`, `{release}`, `{home}`,
`{workspace}`, `{python}`, `{node}`, `{ca-file}` and named runtime paths. Regex
permissions must be rooted in the selected repo/workspace; substituted roots are
escaped. Credential-file denials remain in the compiled policy. Repository Scheme
is never evaluated. Required `sandbox-exec` support is checked before launch.

## Shared clients and input boundaries

Shared Python clients validate the native session, optionally install the HTTP
guard, add approved dependency roots and execute an integrity-pinned `script`.
Their fixed vector uses `python -I -S -B {release}/runbox.pyz --command-child`.
Alternatively `client.entrypoint: module:function` selects an installed entrypoint
from the approved dependency roots; script and entrypoint are mutually exclusive.
The public argv begins with the declared logical command. Read-only checks can use exact
`client.probe-arguments` or an HTTP `client.probe` with `checks`, optional `count`
and `format: json|status`. Status-only probes require no response assertions.

With an HTTP policy, the Python guard also adapts installed Google API
`httplib2` requests to its verified urllib CONNECT/TLS transport. It retains the
SDK response protocol without disk caching or the optional SOCKS dependency.
Redirects, extra authentication headers and requests after a failure are rejected;
wire and decoded responses are each bounded to 64 MiB. Gzip and deflate responses
are decompressed for the SDK; invalid, oversized or unsupported encodings stop
the session. Consumer code must explicitly select finite
access-token credentials and avoid local OAuth refresh or credential discovery.
Installed HTTPX and HTTPX2 clients share the same synchronous and asynchronous
route, placeholder, redirect, sanitized-error and failure-latch checks. This
does not authorize native Xet or off-host presigned upload transports.

`client: {type: s3-head, targets: [...]}` provides a shared bucket-only check
without repository probe scripts. Each of one to four targets declares a `bucket`
and the public environment selectors `endpoint-variable`, `access-variable` and
`secret-variable`. Endpoints must be explicit HTTP loopback signers at
`127.0.0.1` on unprivileged ports; both credential values must be placeholders.
The approved runtime supplies Boto3/Botocore. Every target is validated before
SDK construction. The checker uses explicit credentials, path-style SigV4, one
HEAD per bucket, bounded timeouts and no retry, then closes each client. It
accepts no arguments and returns only a success flag and bucket count. Failures
may report a validated integer HTTP status and a closed failure stage from the
reviewed signer. SDK messages, arbitrary headers and provider bodies remain
withheld. A validated non-success upstream status can clarify an adapter's generic
failure; it never makes the probe successful or enables redirects. The checker
does not list objects, fetch contents, refresh credentials or qualify
write transport.
Use it as a separate fixed probe execution with the same reviewed session and
required sandbox. Native routes and separately reviewed trusted signers still
enforce their own destinations and operations; this checker grants no access.

`client: {type: http-json}` runs one guarded JSON API request with the built-in
transport. It uses the same Python `--command-child` vector, requires an
HTTP policy, accepts no command arguments, and needs a separate read-only probe.
Stdin is a JSON object with `method: GET|POST`, absolute `url`, optional JSON
`body` and optional public `context`. Requests are limited to 4 MiB; GET bodies,
extra fields, duplicate JSON keys, non-finite numbers and redirects are rejected.
The response is one `{status: INTEGER, body: OBJECT_OR_ARRAY}` JSON record bounded
to 16 MiB. Authentication comes only from the profile's public placeholder;
request input cannot supply headers or credentials. Failures return a fixed safe
error without provider details. An optional `HTTP_EXECUTOR_CONTEXT` public JSON
environment setting must match the request context exactly, including value types.
Use it to compare application account selectors with reviewed profile metadata.

Optional `client.validator: module:function` selects an integrity-pinned ordinary
consumer policy. It runs under the selected sandbox after the HTTP guard is
installed, before forwarding the original request. The function receives a copy
of the parsed request, a guarded GET callback (at most four reads), and public
profile environment data. It returns `None` or raises. Request mutations are not
forwarded. The separately privileged renewal broker never imports this code.
Use these policies for domain rules such as generated tabs or manual-column
protection that native host/method/path scopes cannot express.

For related writes, `{requests: [...], context: {...}}` submits up to three
ordered POST requests with the same method/URL/body shape. A pinned validator is
required. Every member's route and the complete domain plan are checked before
the first write. Success returns `{status: 200, body: {responses: [...]}}`.
This is preflight validation, not an upstream transaction: any execution failure
stops the sequence without retry or fallback, and earlier writes may have applied.

Applications may select this executor through an explicit neutral executable
input. A registered shared command link can dispatch GET to an approved read
profile and other requests to a separately approved write profile. The HTTP
policy still decides whether a request is admitted. This keeps public collection
outside credential sessions and creates no ordinary-command Runbox dependency.

Python GET routes may declare `query-parameters` instead of an exact `queries`
list. Each named parameter has a full-match `pattern` and optional boolean
`required`. Duplicate names are rejected unless that specific parameter declares
an integer `max-count` from 1 to 16; every repeated value must match its pattern.
Unknown names, malformed encoding, control characters,
more than 32 fields, queries over 4096 characters and values over 2048 characters
are rejected. Keep patterns narrow to the selected operation and account. The
fixed `probe-query` must satisfy the same schema.

A `macos-command` Python client with an integrity-pinned `script` may declare one
literal `name=value` pair in a POST route's `queries` list. Each side must contain
only letters, digits, `.`, `_`, `~` or `-`. The guard requires the exact query,
for example `queries: ["wait=10000"]`. Use a separate GET route for the online check.

Shared Node resources support guarded HTTP clients, Sentry readers and Next app
startup. `execution.preloads` lists pinned domain transport modules; generic
bootstrap and process lifecycle stay in Runbox. `client.type: node-next` supports
an optional relative app `root`, pinned `prepare` scripts, loopback `hostname`,
and an owned temporary tsconfig. Existing domain adapters can retain their own
transport checks or compose the shared HTTP guard. Multi-service apps need their
complete reviewed routes; a single-provider HTTP guard is not a universal proxy.

`resources/sentry-delivery-reader.mjs` checks a previously captured production
event through an existing project read grant. Pin the organization, project,
site origin, event ID, release and SHA-256 of the deployed public DSN in the
profile. Both `read` and `check` are fixed commands without caller-supplied
arguments. The reader uses only the project keys and exact event GETs, and
prints only the verified receipt fields or probe status.

`resources/github-actions-reader.py` supports GitHub CLI-shaped read operations
for runtime receipts. Configure `GITHUB_ACTIONS_READER_POLICY` with the repository
name and numeric ID, approved workflow names and IDs, allowed artifact names, and
exact signed-storage hosts. The approved `GH_TOKEN` placeholder goes only to
GitHub through Agent Vault. The reader follows one HTTPS archive redirect using
the separate pinned `GITHUB_ACTIONS_ARCHIVE_CA` and sends no proxy or GitHub
authorization on that connection. It verifies the archive size and SHA-256
against GitHub's metadata. Choose a current receipt ID for the `check` probe.
The fixed reader requires direct, credential-free storage egress and has no
workflow dispatch operation.

`resources/hf-benchmark-publish.py` freezes the inventory from a verified
TurboBench staging directory. A read-only Runbox profile can run
`inspect-parent` through the fixed benchmark parent gateway. It returns the
verified public dataset commit or a null parent after a typed repository-not-found
response. The `check-parent` probe reports only read-only success and a count of
zero or one. For an existing dataset, `fetch-index` takes that receipt, repository,
and project and downloads only `benchmark-index.json` anonymously at the pinned
commit. Use that index to stage the next bundle. Use `prepare` with the repository,
project, version, and verified parent, or `absent` after confirmed absence.
Pass the stage path, plan path, and SHA-256 digest as the three
arguments to `publish`. The Runbox profile confines both paths to the selected
checkout and supplies the same plan and digest to the scoped Hub gateway.
`publish` checks the staged bytes, commits against the reviewed parent, and
verifies the version tag. The configured `check` only reads account identity.
Use `probe.services` to select a fixed identity gateway for the read-only check
when the normal gateway requires per-run inputs. A probe service can declare
fixed local processes with the ordinary service lock and runtime pins, but
cannot accept forwarded arguments or manage PostgreSQL or transient files.
`download-back` runs anonymously against the
exact acknowledged commit and verifies every planned file. The benchmark's
own snapshot verifier still needs to complete before claiming publication.

The archive's `--imagefolder prepare` command freezes a verified ImageFolder
export, its expected parent commit and its commit message without opening a
service session. Pass `--stage` with the absolute export directory, `--parent`
with the observed commit, and `--message` with the reviewed message. The tool
leaves a local `export.json` receipt out of the plan.

A compatible Runbox profile can execute `--imagefolder publish` with the exact
checkout-relative stage path, owner-only plan path and SHA-256 digest. Pin the
same plan and digest in the `--imagefolder-plan` gateway, declare the dataset as
`HF_IMAGEFOLDER_REPOSITORY`, and use the fixed loopback destination and public
Hub placeholder. The client rechecks the staged bytes before contacting the Hub and
submits one expected-parent commit. Use `--imagefolder check` with an independent
identity-only gateway for the bounded read-only probe. Upload authorization
and download-back verification remain part of the consuming workflow.

`inputs` selects only explicit canonical payload arguments before authentication.
Each named rule declares `argument` (index in the full public argv),
`when-prefix`, `root`, `exclude` and `allow`. `root: repo` confines payloads to the
checkout with narrow exceptions beneath excluded roots; `root: any-file` accepts
only exact owned regular files. Symlinks and traversal fail. Input substitutions
may appear in read permissions and pinned host-service argv as public path data.
Optional `path-template` derives a fixed repository-relative payload path from
one safe named argument, for example `.internal/evidence/{argument}/manifest.json`.

`outputs` similarly declares `argument`, `when-prefix`, `kind`, `separate-from`
and `exclude`. `new-file` and `empty-directory` require an empty owner-only
directory; `existing-directory` permits a nonempty owner-only directory.
`working-directory` selects existing ordinary application data owned by the user
and rejects group/other write access; it preserves the folder's existing mode.
Both existing-directory kinds require a strict child of a declared
repository-relative `within` subtree. Protected-path exclusions and separation
from declared input parents still apply; `relative-to: repo` accepts a relative
public argument. The selector creates/deletes nothing. Its substitutions
and `NAME-parent` may appear only in read/write permissions. Nonmatching selectors
use a no-access `/dev/null` sentinel. Exact selected-output read rules follow
parent-directory denials, while credential filename denials remain final. Input
rules and output-parent permissions do not override explicit protected-path
denials. Domain CLI validation remains necessary.

## Local services and delegated workers

Optional profile `services` declares a private `lock`, bounded `processes` with
fixed runtime-pinned argv, cwd, public environment and exact JSON readiness, and
optional `postgres` lifecycle. A previously running database is retained. Only a
database started by this invocation is stopped; `start-if-stopped: false` instead
requires it already running. Sidecar failure stops the native command, then owned
process groups are cleaned up. Output is sanitized before forwarding. Only
initially absent, explicitly named, owned transient files may be removed.
`{argument-N}` in service argv forwards one bounded public argument from the full
command vector, or `/dev/null` when absent. It is data, never shell code; the
command policy and domain helper must validate its meaning before using it.

Optional `execution.readiness` checks an owner-only JSON state file beneath a
private runtime directory against a reviewed `field` / `equals` value before
authentication. Pending state blocks ordinary runs; offline checks report false,
and the configured online probe remains available for trusted post-renewal
verification. Mutable readiness state is not a credential store or source pin.
`execution.sanitize-output: true` streams sanitized bounded lines;
`stderr: discard` suppresses private diagnostics for compatible fixed commands.
Protocol clients retain their specific framing and sanitization requirements.
Failed Node checks can report the exact failure stage for client startup,
model catalog, or a follow-up read-only request. The message includes the HTTP
status and a recognized Agent Vault decision when available. Response bodies,
service names and provider error text stay private.

An existing managed SSH master can serve an approved `session.tunnel`. Runbox
checks it and creates or cancels only its own forwarding. It does not authenticate
another master or repair SSH configuration. Set `"shared-tunnel": true` in the
reviewed local runtime for an endpoint reserved for Runbox callers with the same
reviewed SSH alias, target and binary. Runbox tracks callers with owner-only locks and closes the forward
when the last caller exits. An unrelated listener or a changed SSH master
blocks reuse. If all callers are forcibly terminated, a surviving forward
requires normal managed-SSH recovery before that endpoint can be reused.

Optional `session.worker` creates a
separately scoped, finite delegated session for explicit command prefixes. The
capability travels only through validated environment fields. It is revoked if
startup was never attempted; after admission may have been attempted, finite expiry
and the domain workload own its lifetime. A lost acknowledgement cannot justify
terminating an admitted workload.

Optional `execution.handoff` places the native proxy/CA in explicit provider-local
variables and removes global proxy, CA and unrelated credential inheritance. It
can require named loopback services to be stopped before authentication. It does
not stop/restart an existing application or change application defaults.

These controls cover the reviewed child and owned helpers. They do not isolate a
full-access agent or another process running as the same host user. Signing,
OAuth renewal, privileged proxy bootstrap and unsupported transports remain
separate trusted components; no execution policy supplies raw keys as a fallback.

## Renewable fixed HTTPS daemons

Optional `session.renewal` supports a fixed, no-argument daemon with
`sandbox: none`, `cwd: repo`, an explicit provider-local `handoff`, a pinned
`probe-argv` and an HTTPS HTTP policy. Workspace overrides, services, delegated
workers, tunnels, preloads and input/output selectors are unsupported. The daemon
must honor the explicit proxy/CA variables and open new connections for new
operations. Persistent connection pools do not acquire a replacement capability
until they reconnect; transport compatibility requires actual-client review.

Runbox starts one authenticated loopback CONNECT relay for that invocation. It
connects only to the pinned provider proxy and permits only the declared HTTPS
origin. TLS remains opaque; the upstream proxy enforces service permissions. New
connections use the latest verified finite lease. Established tunnels remain on
their original lease until drained or that lease expires. Requests are never
replayed or retargeted. A stream cannot outlive its original finite lease.

Before creating and publishing every replacement, Runbox rechecks the unchanged
approved configuration, source, runtime, CA and release. The configured read-only
probe validates the new capability and native CA fingerprint. Approval drift or
renewal failure closes new admissions without restarting the app; existing
tunnels drain within their original lifetime. Recovery requires explicit review
and a new invocation. Startup port checks run only before starting the daemon.
Renewal failures report the failed stage, such as approval verification, lease
creation or the read-only probe. Runbox withholds provider diagnostics and
session details.

Capabilities stay in memory and scoped child environments. Output is sanitized.
Idle retired leases and all invocation-owned leases on shutdown are revoked;
a lost revocation acknowledgement retains the original TTL as the final bound.
Forced host termination cannot guarantee immediate revocation. Detached-worker
ownership is unchanged. This opt-in host execution remains separate from normal
application commands and never renews source keys or expands service scope.
