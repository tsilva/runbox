# Development

```sh
uv --no-config sync --locked --exclude-newer '7 days'
uv --no-config run --locked --exclude-newer '7 days' python -m unittest discover -v
uv --no-config run --locked --exclude-newer '7 days' python scripts/build.py
```

The dependency lock excludes packages newer than seven days. The archive bundles
the locked pure-Python PyYAML implementation and license, with fixed ZIP timestamps
for reproducibility. A second build must produce identical archive/policy hashes.
Install only a reviewed build; checksums detect drift, not source authenticity.

Transport tests additionally need the selected application's reviewed HTTPX
runtime. Run the same unittest command with that Python to exercise HTTPX.
macOS sandbox tests skip on other platforms; such a skip does not establish
compatibility with `macos-staging`. Use synthetic credentials and temporary
fixtures. The migration guide describes required actual-client pilot checks.

To repeat the packaged Repologogen pilot without live credentials:

```sh
/absolute/reviewed/python scripts/verify_python_pilot.py \
  --repo /absolute/repologogen --python /absolute/reviewed/venv/bin/python
```

This copies the application into temporary fixtures, starts a local fake proxy
and substitutes a fake native-session CLI. It exercises the real HTTPX client,
denials, failure sanitization, ignored repository bytecode and command exit
status. It does not prove native API compatibility or live session revocation;
the separately authorized read-only live check covers the native route.

Providers implement validation, native metadata rendering and a session command
in built-in modules. No repository Python is imported by the trusted parent.
Execution policies compose independently with providers; adding a provider does
not grant a sandbox exception. Unknown providers and sandbox policies are errors.
There is no dynamic privileged plugin loading.

Run `ruff check runbox tests scripts` and the Node resource tests with a reviewed
Node runtime. Packaged synthetic checks cover Python HTTP clients, TLS probes,
Node adapters and filesystem/network denials. Service, worker-session, command-link
and input/output tests must verify failure cleanup and pre-authentication refusals,
not only valid metadata. Never install dependencies into a consumer merely to
test an unchanged application; record missing or stale baseline environments.

Runbox is not a secret manager, credential-renewal broker, global process
interceptor or universal sandbox. Initial generic commands must honor native
HTTP proxy settings. gRPC, local signing, OAuth refresh, uploads and other
transports need compatibility review; unsupported cases have no raw-key fallback.
The Python guard reduces accidental misuse; it is not an isolation boundary
against a hostile interpreter or full-access same-user host process. The native
proxy and optional required OS sandbox enforce the child restrictions they cover.

Approvals intentionally become stale after source/runtime/configuration updates.
Trusted review is required to refresh them. Runtime dependency directories are
reviewed installations, not individually attested distribution contents; the
Python executable, native CLI and public CA are hash-pinned. Session cleanup is
owned by the native CLI; cancellation is forwarded and bounded probes allow it
time to revoke. Force-killing the host cannot guarantee immediate revocation;
the configured TTL bounds a surviving session. Delegated workers deliberately
retain their reviewed finite lifetime after admission may have been attempted;
lost acknowledgements cannot justify revoking an admitted workload. Installing a
new release leaves existing approvals on their exact protected version. Retain
releases referenced by approvals, command links or administrative parser pins.
