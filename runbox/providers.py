"""Built-in adapters. A provider change cannot replace the execution policy."""


class Infisical:
    @staticmethod
    def native_config(profile):
        provider = profile["provider"]
        value = {"version": 1, "general": {"domain": provider["instance"]}}
        if "source" in provider:
            value["secrets-management"] = provider["source"]
        return value

    @staticmethod
    def command(profile, runtime, child):
        provider, session = profile["provider"], profile["session"]
        return [
            runtime["infisical"],
            *(
                ["--profile=" + provider["login-profile"]]
                if "login-profile" in provider
                else []
            ),
            "agent-vault",
            "run",
            "--domain=" + provider["instance"],
            "--project-id=" + provider["project-id"],
            "--access-bundle=" + provider["access-bundle"],
            "--proxy=" + session["proxy"],
            "--ca-fingerprint=" + runtime["ca-fingerprint"],
            "--ttl=" + session["ttl"],
            "--no-ca-trust",
            "--silent",
            "--telemetry=false",
            "--no-skills",
            *(["--no-mcp-servers"] if provider.get("no-mcp-servers") else []),
            "--",
            *child,
        ]


PROVIDERS = {"infisical": Infisical}
