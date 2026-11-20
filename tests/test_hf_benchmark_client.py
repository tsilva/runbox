import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


RESOURCE = (
    Path(__file__).resolve().parents[1] / "runbox/resources/hf-benchmark-publish.py"
)
SPEC = importlib.util.spec_from_file_location("benchmark_client", RESOURCE)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)

REPO = "owner/env-benchmarks"
PROJECT = "env-example"
VERSION = "1.2.3"
BUNDLE = "b" * 64
PARENT = "c" * 40
COMMIT = "d" * 40
PAYLOAD = f"bundles/v{VERSION}/vs-baseline-1.0.0/{BUNDLE}/report.md"


class Missing(Exception):
    def __init__(self, provider_code):
        self.response = SimpleNamespace(
            status_code=404, headers={"x-error-code": provider_code}
        )


class BenchmarkClientTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        (self.root / PAYLOAD).parent.mkdir(parents=True)
        (self.root / PAYLOAD).write_bytes(b"verified benchmark evidence")
        (self.root / "README.md").write_bytes(b"# Benchmark evidence")
        (self.root / "benchmark-index.json").write_text(
            json.dumps(
                {
                    "schema": PROJECT + ".benchmark-index/v1",
                    "repo_id": REPO,
                    "latest_version": VERSION,
                    "latest_bundle_id": BUNDLE,
                    "entries": [
                        {
                            "path": str(Path(PAYLOAD).parent),
                            "package_version": VERSION,
                            "bundle_id": BUNDLE,
                        }
                    ],
                }
            )
        )
        self.plan = client.stage_plan(self.root, REPO, PROJECT, VERSION, PARENT)
        self.receipt = {
            "repo_id": REPO,
            "version": VERSION,
            "bundle_id": BUNDLE,
            "tag": "v" + VERSION,
            "commit": COMMIT,
        }

    def test_stage_inventory_and_changed_file_stop_before_the_sdk(self):
        self.assertEqual(
            set(self.plan["files"]), {"README.md", "benchmark-index.json", PAYLOAD}
        )
        (self.root / PAYLOAD).write_bytes(b"unreviewed payload")
        api = Mock()
        with self.assertRaisesRegex(client.PublicationError, "bytes differ"):
            client.publish(
                self.root, self.plan, REPO, PROJECT, api, tuple, Missing, Missing
            )
        self.assertEqual(api.mock_calls, [])

    def test_stage_rejects_unrelated_files_and_symlinks(self):
        outside = self.root / ".env.local"
        outside.write_bytes(b"synthetic extra file")
        with self.assertRaisesRegex(client.PublicationError, "Unreviewed file"):
            client.stage_plan(self.root, REPO, PROJECT, VERSION, PARENT)
        outside.unlink()
        (self.root / "alias").symlink_to(self.root / PAYLOAD)
        with self.assertRaisesRegex(client.PublicationError, "symlink"):
            client.stage_plan(self.root, REPO, PROJECT, VERSION, PARENT)

    def test_commit_and_tag_use_the_reviewed_parent_and_receipt(self):
        api = Mock()
        api.dataset_info.side_effect = [
            SimpleNamespace(id=REPO, private=False, sha=PARENT),
            Missing("RevisionNotFound"),
            SimpleNamespace(sha=COMMIT),
        ]
        api.create_commit.return_value = SimpleNamespace(oid=COMMIT)
        result = client.publish(
            self.root,
            self.plan,
            REPO,
            PROJECT,
            api,
            lambda a, b: (a, b),
            Missing,
            Missing,
        )
        self.assertEqual(result, self.receipt)
        api.create_repo.assert_not_called()
        self.assertEqual(api.create_commit.call_args.kwargs["parent_commit"], PARENT)
        self.assertEqual(api.create_tag.call_args.kwargs["revision"], COMMIT)

    def test_repository_absence_requires_the_exact_provider_error(self):
        api = Mock()
        api.dataset_info.side_effect = Missing("unrecognized")
        plan = client.stage_plan(self.root, REPO, PROJECT, VERSION, None)
        with self.assertRaisesRegex(
            client.PublicationError, "absence was not verified"
        ):
            client.publish(
                self.root, plan, REPO, PROJECT, api, Mock(), Missing, Missing
            )
        api.create_repo.assert_not_called()

    def test_public_download_pins_the_commit_disables_authentication_and_verifies_bytes(
        self,
    ):
        destination = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        api = Mock()
        api.dataset_info.return_value = SimpleNamespace(sha=COMMIT)

        def copy_download(repository, **options):
            self.assertEqual(repository, REPO)
            self.assertIs(options["token"], False)
            self.assertEqual(options["revision"], COMMIT)
            self.assertEqual(options["endpoint"], "https://huggingface.co")
            name = options["filename"]
            path = options["local_dir"] / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.root / name).read_bytes())

        proof = client.download_back(
            self.plan, self.receipt, REPO, destination, api, copy_download
        )
        self.assertTrue(proof["transport_verified"])
        self.assertEqual(proof["downloaded_file_count"], 3)
        self.assertEqual(api.dataset_info.call_count, 2)
        for call in api.dataset_info.call_args_list:
            self.assertIs(call.kwargs["token"], False)

    def test_foreign_tag_and_receipt_extras_cannot_authorize_public_download(self):
        destination = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        api, download = Mock(), Mock()
        api.dataset_info.return_value = SimpleNamespace(sha=PARENT)
        with self.assertRaisesRegex(
            client.PublicationError, "Public benchmark tag differs"
        ):
            client.download_back(
                self.plan, self.receipt, REPO, destination, api, download
            )
        with self.assertRaisesRegex(
            client.PublicationError, "acknowledged benchmark receipt"
        ):
            client.download_back(
                self.plan,
                dict(self.receipt, private="synthetic"),
                REPO,
                destination,
                api,
                download,
            )
        download.assert_not_called()
