#!/usr/bin/env python3
"""Exercise the workflow's Clippy command without building the workspace."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def clippy_command():
    text = WORKFLOW.read_text()
    match = re.search(r"^      - name: Clippy[^\n]*\n(?:        [^\n]*\n)*?        run: ([^\n]+)$", text, re.MULTILINE)
    if not match:
        raise AssertionError("expected an explicit one-line Clippy command")
    return match.group(1)


class CiGateTest(unittest.TestCase):
    def run_clippy(self, status):
        with tempfile.TemporaryDirectory(prefix="adb-ci-gate-") as directory:
            cargo = Path(directory) / "cargo"
            cargo.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'EARLY_DIAGNOSTIC' >&2\n"
                "i=0\n"
                "while [ \"$i\" -lt 50 ]; do printf '%s\\n' 'warning: fixture'; i=$((i + 1)); done\n"
                f"exit {status}\n"
            )
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            # GitHub's implicit bash shell uses -e, not pipefail. The command
            # itself must preserve failure; do not let the test supply a fix.
            return subprocess.run(
                ["bash", "-e", "-c", clippy_command()],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=10,
            )

    def test_clippy_failure_is_not_reported_as_success(self):
        result = self.run_clippy(42)
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)

    def test_warnings_do_not_fail_successful_clippy(self):
        result = self.run_clippy(0)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_early_diagnostic_is_preserved(self):
        result = self.run_clippy(42)
        self.assertIn("EARLY_DIAGNOSTIC", result.stdout + result.stderr)

    def test_pull_request_ci_also_runs_for_stacked_bases(self):
        text = WORKFLOW.read_text()
        event = re.search(r"^  pull_request:\s*\n((?:    [^\n]*\n)*)", text, re.MULTILINE)
        self.assertIsNotNone(event)
        self.assertNotIn("branches:", event.group(1), "stacked PR bases must not be excluded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
