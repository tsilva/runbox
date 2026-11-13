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

Shared Node resources support guarded HTTP clients, Sentry readers and Next app
startup. `execution.preloads` lists pinned domain transport modules; generic
bootstrap and process lifecycle stay in Runbox. `client.type: node-next` supports
an optional relative app `root`, pinned `prepare` scripts, loopback `hostname`,
and an owned temporary tsconfig. Existing domain adapters can retain their own
transport checks or compose the shared HTTP guard. Multi-service apps need their
complete reviewed routes; a single-provider HTTP guard is not a universal proxy.

`inputs` selects only explicit canonical payload arguments before authentication.
Each named rule declares `argument` (index in the full public argv),
`when-prefix`, `root`, `exclude` and `allow`. `root: repo` confines payloads to the
checkout with narrow exceptions beneath excluded roots; `root: any-file` accepts
only exact owned regular files. Symlinks and traversal fail. Input substitutions
may appear in read permissions and pinned host-service argv as public path data.
Optional `path-template` derives a fixed repository-relative payload path from
one safe named argument, for example `.internal/evidence/{argument}/manifest.json`.

`outputs` similarly declares `argument`, `when-prefix`, `kind`, `separate-from`
and `exclude`. Kinds are `new-file`, `empty-directory` or `existing-directory`. The existing target
directory must be empty and owner-only, outside protected paths and separate from
selected input parents. `existing-directory` additionally requires a strict child
of a declared repository-relative `within` subtree; `relative-to: repo` accepts
a relative public argument. The selector creates/deletes nothing. Its substitutions
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

An existing managed SSH master can serve an approved `session.tunnel`; Runbox
checks it and creates/cancels only its own forwarding. It does not authenticate
another master or repair SSH configuration. Optional `session.worker` creates a
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
