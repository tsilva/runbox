<p align="center">
  <img src="logo.png" alt="Runbox" width="320">
  <br>
<!-- repo-tagline:start -->
<strong>📦 One command for reviewed access and execution 🔐</strong>
<!-- repo-tagline:end -->
</p>

# Runbox

Runbox starts a command with the access and execution policy declared by its
repository. It finds `.runbox.yaml` from the Git root, including when you run it
from a subdirectory. Local approvals and machine paths stay outside Git.

For a configured and approved checkout:

```sh
runbox check
runbox run -- your-command --your-options
```

`check` verifies the local approval and runtime. With Infisical Agent Vault,
`run` starts the scoped native proxy session, passes public placeholders to
the command, and revokes the session on exit.

## Install from source

Requires Python 3.11+, `uv`, Git and a separately installed, checksum-verified
Infisical CLI. Use an authenticated repository URL when access requires it.

```sh
git clone https://github.com/tsilva/runbox.git
cd runbox
uv --no-config sync --locked --exclude-newer '7 days'
uv --no-config run --locked --exclude-newer '7 days' python scripts/build.py
uv --no-config run --locked --exclude-newer '7 days' python scripts/install.py --python /absolute/persistent/python3
runbox --version
```

Choose a persistent Python executable rather than a disposable build environment.
The installer adds an owner-only release and a `runbox` link in `~/.local/bin`;
that directory must already be on your PATH. It refuses to replace an unrelated
command and leaves existing launchers installed. This project is installed from
its repository; the unrelated PyPI package named `runbox` is not this tool.

## Configure and approve a repository

- [Configuration](docs/configuration.md) covers profiles, approvals, and public
  browser settings.
- [Execution policies](docs/execution.md) covers supported command and
  sandbox boundaries.
- [Migration](docs/migration.md) and [development](docs/development.md)
  cover existing consumers and reproducible builds.

## License

[MIT License](LICENSE).
