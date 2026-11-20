"""Read approved GitHub Actions receipts through a scoped Runbox session."""

import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
from urllib.parse import unquote, urlencode, urlsplit


API_HOST = "api.github.com"
PLACEHOLDER = "runbox_github_actions_public_placeholder"
RUN_FIELDS = (
    "databaseId,headSha,displayTitle,createdAt,updatedAt,status,conclusion,url,event"
)
MAX_JSON = 2 * 1024 * 1024
MAX_ARCHIVE = 4 * 1024 * 1024
TIMEOUT = 15


class ReaderError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ReaderError(message)


def identifier(value):
    return type(value) is int and 0 < value < 10**20


def certificate_context(path):
    require(os.path.isabs(path), "Missing approved CA file")
    return ssl.create_default_context(cafile=path)


class Reader:
    def __init__(self, environment):
        policy = json.loads(environment["RUNBOX_GITHUB_ACTIONS_POLICY"])
        self.repository = policy["repository"]
        self.repository_id = policy["repository_id"]
        self.workflows = policy["workflows"]
        self.storage_hosts = policy["storage_hosts"]
        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository)
            and all(part not in (".", "..") for part in self.repository.split("/"))
            and identifier(self.repository_id)
            and type(self.workflows) is dict
            and 0 < len(self.workflows) <= 8
            and all(
                identifier(workflow["id"])
                and type(workflow["artifacts"]) is list
                and 0 < len(workflow["artifacts"]) <= 8
                and all(
                    re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                    for name in workflow["artifacts"]
                )
                for workflow in self.workflows.values()
            )
            and type(self.storage_hosts) is list
            and 0 < len(self.storage_hosts) <= 8
            and all(
                re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host)
                for host in self.storage_hosts
            )
            and API_HOST not in self.storage_hosts,
            "Invalid Actions reader policy",
        )
        proxy = urlsplit(environment["HTTPS_PROXY"])
        require(
            environment.get("GH_TOKEN") == PLACEHOLDER
            and proxy.scheme == "http"
            and proxy.hostname in ("127.0.0.1", "localhost")
            and proxy.port is not None
            and proxy.username
            and proxy.password
            and not proxy.path
            and not proxy.query
            and not proxy.fragment,
            "Expected the scoped proxy and public placeholder",
        )
        self.proxy = proxy
        self.api_context = certificate_context(environment["SSL_CERT_FILE"])
        self.storage_context = certificate_context(
            environment["GITHUB_ACTIONS_ARCHIVE_CA"]
        )
        self.prefix = f"/repos/{self.repository}/actions"

    def api(self, path, *, archive=False):
        proxy_auth = f"{unquote(self.proxy.username)}:{unquote(self.proxy.password)}"
        connection = http.client.HTTPSConnection(
            self.proxy.hostname,
            self.proxy.port,
            timeout=TIMEOUT,
            context=self.api_context,
        )
        connection.set_tunnel(
            API_HOST,
            443,
            headers={
                "Proxy-Authorization": "Basic "
                + base64.b64encode(proxy_auth.encode()).decode()
            },
        )
        try:
            connection.request(
                "GET",
                self.prefix + path,
                headers={
                    "Authorization": "Bearer " + PLACEHOLDER,
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "Runbox-Actions-Reader",
                },
            )
            with connection.getresponse() as response:
                if archive:
                    locations = [
                        value
                        for key, value in response.getheaders()
                        if key.lower() == "location"
                    ]
                    require(
                        response.status == 302 and len(locations) == 1,
                        "Expected an Actions archive redirect",
                    )
                    return locations[0]
                require(response.status == 200, "Actions metadata request failed")
                payload = response.read(MAX_JSON + 1)
                require(len(payload) <= MAX_JSON, "Actions metadata exceeds size limit")
                return json.loads(payload)
        finally:
            connection.close()

    def run_list(self, name, branch, limit):
        workflow = self.workflows.get(name)
        require(workflow is not None, "Workflow is outside the approved scope")
        query = {"per_page": limit}
        if branch:
            require(re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", branch), "Invalid branch")
            query["branch"] = branch
        runs = self.api(f"/workflows/{workflow['id']}/runs?{urlencode(query)}")[
            "workflow_runs"
        ]
        require(type(runs) is list, "Invalid Actions run listing")
        fields = dict(
            zip(
                RUN_FIELDS.split(","),
                (
                    "id",
                    "head_sha",
                    "display_title",
                    "created_at",
                    "updated_at",
                    "status",
                    "conclusion",
                    "html_url",
                    "event",
                ),
            )
        )
        return [
            {output: run.get(source) for output, source in fields.items()}
            for run in runs
            if run["workflow_id"] == workflow["id"]
        ]

    def repository_run(self, run_id):
        run = self.api(f"/runs/{run_id}")
        require(
            run["id"] == run_id
            and run["repository"]["id"]
            == run["head_repository"]["id"]
            == self.repository_id
            and run.get("event") in ("push", "workflow_dispatch"),
            "Run is outside the approved repository or events",
        )
        for workflow in self.workflows.values():
            if workflow["id"] == run["workflow_id"]:
                return run, workflow
        raise ReaderError("Run is outside the approved workflows")

    def artifact_list(self, run_id):
        _, workflow = self.repository_run(run_id)
        artifacts = self.api(f"/runs/{run_id}/artifacts?per_page=100")["artifacts"]
        require(type(artifacts) is list, "Invalid Actions artifact listing")
        return {
            "artifacts": [
                {"id": row["id"], "name": row["name"], "expired": False}
                for row in artifacts
                if identifier(row["id"])
                and row["name"] in workflow["artifacts"]
                and row["expired"] is False
            ]
        }

    def read_archive(self, artifact_id):
        artifact = self.api(f"/artifacts/{artifact_id}")
        origin = artifact["workflow_run"]
        size = artifact["size_in_bytes"]
        digest = artifact["digest"]
        require(
            artifact["id"] == artifact_id
            and identifier(origin["id"])
            and origin["repository_id"]
            == origin["head_repository_id"]
            == self.repository_id
            and artifact["expired"] is False
            and type(size) is int
            and 0 < size <= MAX_ARCHIVE
            and re.fullmatch(r"sha256:[a-f0-9]{64}", digest),
            "Artifact did not match the approved repository, size or digest contract",
        )
        run, workflow = self.repository_run(origin["id"])
        require(
            artifact["name"] in workflow["artifacts"]
            and origin["head_sha"] == run["head_sha"],
            "Artifact is outside the approved receipt scope",
        )
        location = self.api(f"/artifacts/{artifact_id}/zip", archive=True)
        content = self.download(location, size)
        require(
            "sha256:" + hashlib.sha256(content).hexdigest() == digest,
            "Actions archive digest mismatch",
        )
        return content

    def download(self, location, size):
        require(
            len(location) <= 8192
            and all(33 <= ord(character) <= 126 for character in location)
            and "\\" not in location,
            "Invalid Actions archive redirect",
        )
        target = urlsplit(location)
        require(
            target.scheme == "https"
            and target.netloc in self.storage_hosts
            and not target.fragment
            and target.path.startswith("/")
            and not target.path.startswith("//")
            and target.query,
            "Unreviewed Actions archive redirect",
        )
        # The signed storage request uses a fresh direct connection, with no proxy or auth headers.
        connection = http.client.HTTPSConnection(
            target.netloc, timeout=TIMEOUT, context=self.storage_context
        )
        try:
            connection.request("GET", target.path + "?" + target.query)
            with connection.getresponse() as response:
                require(
                    response.status == 200, "Actions archive storage request failed"
                )
                content = response.read(size + 1)
                require(len(content) == size, "Actions archive size mismatch")
                return content
        finally:
            connection.close()


def read_command(reader, arguments):
    if arguments == ["repo", "view", "--json", "nameWithOwner"]:
        return {"nameWithOwner": reader.repository}
    if arguments[:3] == ["run", "list", "--workflow"]:
        options = arguments[4:]
        branch = None
        if options[:1] == ["--branch"] and len(options) >= 2:
            branch, options = options[1], options[2:]
        require(
            len(options) == 4
            and options[0] == "--limit"
            and re.fullmatch(r"[1-9][0-9]?", options[1])
            and options[2:] == ["--json", RUN_FIELDS],
            "Unsupported Actions run list arguments",
        )
        return reader.run_list(arguments[3], branch, int(options[1]))
    if len(arguments) == 2 and arguments[0] == "api":
        base = re.escape(reader.prefix.removeprefix("/"))
        listing = re.fullmatch(
            base + r"/runs/([1-9][0-9]{0,19})/artifacts\?per_page=100", arguments[1]
        )
        if listing:
            return reader.artifact_list(int(listing[1]))
        archive = re.fullmatch(
            base + r"/artifacts/([1-9][0-9]{0,19})/zip", arguments[1]
        )
        if archive:
            return reader.read_archive(int(archive[1]))
    raise ReaderError("Command is outside the Actions reader scope")


def main(arguments):
    reader = Reader(os.environ)
    if (
        len(arguments) == 2
        and arguments[0] == "check"
        and re.fullmatch(r"[1-9][0-9]{0,19}", arguments[1])
    ):
        reader.read_archive(int(arguments[1]))
        result = {
            "ok": True,
            "read_only": True,
            "credential_mode": "public-placeholder",
            "item_count": 1,
        }
    else:
        result = read_command(reader, arguments)
    if isinstance(result, bytes):
        sys.stdout.buffer.write(result)
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except ReaderError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print("Actions reader failed; upstream details withheld", file=sys.stderr)
        raise SystemExit(1) from None
