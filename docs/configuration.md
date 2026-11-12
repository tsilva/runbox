# Configuration

`.runbox.yaml` is the sole maintained repository configuration. Version 1 has
`version`, `default` and `profiles`. Profile names select a complete policy;
there is no implicit inheritance or environment override. Unknown fields,
duplicate keys, aliases, unsupported providers and invalid scopes fail closed.

Each profile contains:

| Field | Purpose |
| --- | --- |
| `provider` | Adapter type and provider-specific metadata |
| `session` | Loopback proxy and bounded TTL, from 1m through 30m |
| `environment` | Public configuration and explicitly named placeholders |
| `execution` | Required sandbox policy and optional Python entrypoint |
| `http` | Exact Python request routes and read-only catalog probe |

Infisical's `project-id` identifies the **Agent Vault project**. Optional
`source` preserves Secret Manager project/environment/path metadata for trusted
administration; ordinary runs never retrieve it. These projects may differ.
`runbox native-config` renders the native metadata view without maintaining a
second file. Agent Vault receives its instance, Vault project and access bundle
through explicit flags, since native Secret Manager configuration cannot select
those scopes. No `.infisical.yaml` is generated on disk during execution.

Legacy `.access.toml`, `.access.local.toml`, `.infisical.yaml` and
`.infisical.json` conflict with the migrated contract. Runbox rejects them; it
does not silently merge configuration or select a fallback.

## Machine runtime

Store a reviewed owner-only JSON file outside the repository:

```json
{
  "infisical": "/absolute/reviewed/infisical",
  "ca-file": "/absolute/public-proxy-ca.pem",
  "ca-fingerprint": "SHA256:REPLACE_WITH_REVIEWED_CERTIFICATE_FINGERPRINT"
}
```

For `macos-staging`, also provide `python`, `python-root` and `venv`. `python`
must be `VENV/bin/python`, resolving into the reviewed `python-root`. Runbox
checks file hashes and the public certificate fingerprint before starting the
native CLI. Runtime metadata contains no login tokens, private keys or service
credentials. Infisical uses its existing separately authorized login.

Approvals are owner-only JSON snapshots under `~/.config/runbox/approvals`.
They bind canonical checkout path, selected profile, configuration, complete
Python package file set, dependency manifests, runtime, Runbox archive and
sandbox policy. Ordinary checks never rewrite an approval. Review changes
before running `approve` again; it is not an automatic repair command.

## Commands

```sh
runbox --repo /absolute/checkout --profile dev check
runbox --repo /absolute/checkout --profile dev run -- your-command arg
runbox --repo /absolute/checkout --profile dev native-config
```

`check` is offline. `check --online` makes the exact configured GET probe for a
Python HTTP profile and reports only a model count. It never performs inference.
Its response must be an object with a `data` list. Other service probe formats
are not implemented. `run --workspace PATH` selects a subdirectory of the
approved staging root. Ordinary arguments are passed as an array, without shell
interpolation; a staging profile permits only its configured console command.

Public placeholder variables must end in `_placeholder`; the Python guard
requires the configured Bearer placeholder and rejects additional credentials.
Other authentication schemes need a reviewed adapter/client extension. Proxy
sessions are process-local and must not be printed, persisted or exported into
shell startup or the parent application.
