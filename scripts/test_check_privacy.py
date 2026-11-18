import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_privacy as privacy


class PrivacyTests(unittest.TestCase):
    def test_private_paths_are_rejected_even_with_benign_content(self):
        for path in ["env/dev/access.json", "planning/accounts.md", ".env.local", "client_secret_local.json"]:
            with self.subTest(path=path):
                self.assertIn("private operational file", privacy.violations(path, b"{}"))
        self.assertEqual([], privacy.violations(".env.example", b"RELEASE_TOKEN="))

    def test_personal_identifiers_are_case_insensitive_and_not_disclosed(self):
        with patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(b"private.example").hexdigest()]}):
            self.assertEqual(["personal or deployment identifier"], privacy.violations("README.md", b"https://nested.PRIVATE.EXAMPLE"))
            self.assertEqual([], privacy.violations("README.md", b"owner@example.com"))

    def test_private_catalog_paths_and_metadata_are_rejected(self):
        locator = b"aws/example/operator/catalog"
        name = b"Private Operator"
        with patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(v.lower()).hexdigest() for v in [locator, name]]}):
            self.assertEqual(["personal or deployment identifier"], privacy.violations("operator.py", locator))
            self.assertEqual(["personal or deployment identifier"], privacy.metadata_violations(b"tagger Private Operator <operator@example.com>"))
            self.assertEqual([], privacy.metadata_violations(b"Public Operator <operator@example.com>"))

    def test_history_scans_annotated_tagger_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])
            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.com")
            git("commit", "--allow-empty", "-qm", "safe")
            environment = dict(os.environ, GIT_COMMITTER_NAME="Private Operator")
            subprocess.run(["git", "-C", str(root), "tag", "-a", "v-test", "-m", "safe tag"], env=environment, check=True)
            with patch.object(privacy, "git", git), patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(b"private operator").hexdigest()]}):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    self.assertEqual(1, privacy.scan_history("--all"))
                self.assertNotIn("Private Operator", output.getvalue())

    def test_git_identity_override_is_rejected(self):
        def git(*args):
            return b"Private Operator <operator@example.com>" if args[0] == "var" else b""
        with patch.object(privacy, "git", git), patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(b"private operator").hexdigest()]}):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(1, privacy.scan(True))
            self.assertNotIn("Private Operator", output.getvalue())

    def test_private_owner_label_does_not_match_namespace_prefix(self):
        label = b"owner"
        with patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(label).hexdigest()]}):
            self.assertEqual(["personal or deployment identifier"], privacy.violations("operator.py", b'owner="owner"'))
            self.assertEqual([], privacy.violations("README.md", b"https://github.com/ownerinc/project"))

    def test_hyphenated_credential_locator_is_rejected(self):
        locator = b"example-vault-service-api-key"
        with patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(locator).hexdigest()]}):
            self.assertEqual(["personal or deployment identifier"], privacy.violations("operator.py", b'credential="' + locator + b'"'))

    def test_private_home_prefix_respects_username_boundary(self):
        prefix = b"/home/private-user"
        with patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(prefix).hexdigest()]}):
            self.assertEqual(["personal or deployment identifier"], privacy.violations("README.md", prefix + b"/project"))
            self.assertEqual([], privacy.violations("README.md", prefix + b"-other/project"))

    def test_staged_scan_reads_index_and_ignores_deleted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])
            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.com")
            target = root / "file with spaces.md"
            target.write_text("safe")
            git("add", ".")
            git("commit", "-qm", "initial")
            target.write_text("owner@private.example")
            git("add", ".")
            target.write_text("safe")
            with patch.object(privacy, "git", git), patch.dict(privacy.POLICY, {"identifier_sha256": [hashlib.sha256(b"private.example").hexdigest()]}):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    self.assertEqual(1, privacy.scan(True))
                self.assertIn("file with spaces.md", output.getvalue())
                self.assertNotIn("owner@", output.getvalue())
                git("add", ".")
                target.write_text("owner@private.example")
                self.assertEqual(0, privacy.scan(True))
                target.unlink()
                git("add", "-u")
                self.assertEqual(0, privacy.scan(True))
                target.write_text("owner@private.example")
                git("add", ".")
                git("commit", "-qm", "add private content")
                target.unlink()
                git("add", "-u")
                git("commit", "-qm", "remove private content")
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    self.assertEqual(1, privacy.scan_history("HEAD"))
                self.assertNotIn("owner@", output.getvalue())


if __name__ == "__main__":
    unittest.main()
