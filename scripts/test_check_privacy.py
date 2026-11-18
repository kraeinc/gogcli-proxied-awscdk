import contextlib
import hashlib
import io
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
