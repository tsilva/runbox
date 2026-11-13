# Agent command routing

Install Runbox separately from consumer applications. Normal package scripts and
CLI commands consume their usual environment and must not discover or invoke
Runbox automatically. An agent or explicit host launcher adds the runner.

Add this rule to each agent host's global instructions, rather than consumer
READMEs:

> Before repository commands, find the Git root and read `.runbox.yaml` when
> present. Run the commands its profiles describe through Runbox with the declared
> entrypoints, arguments, working directory and execution policy. Use an explicit
> profile when selection is ambiguous. Commands outside those profiles follow
> normal credential policy; an absent file does not require Runbox. Metadata-only
> bindings provide no runnable route. Missing authenticated access must stop
> without key retrieval, fallback or automatic approval. Delegated agents inherit
> this rule.

```sh
runbox --profile development run -- pnpm dev --port auto
```

That example requires a profile declaring that command. Some profiles expose a
logical command instead; read the actual configuration rather than guessing a
package-script translation. Generic profiles permit only service operations
consistent with their reviewed scope. Shell compounds must not bypass command
selection.

For child-process integrations, a domain tool may accept an explicit neutral
executor argv supplied by its caller. It must work with normal commands by
default, never auto-load a personal runner file, evaluate a shell string or
retrieve credentials. Only the external host configuration selects Runbox and
its reviewed profile. Preserve existing schedules and session lifetimes when
moving supervision outside an application; do not restart active work to migrate
it. Trusted renewal and provisioning remain separate authorized operations.

Instructions establish expected behavior. Full-access same-user agents are not
an enforced credential-isolation boundary; see [execution](execution.md).
