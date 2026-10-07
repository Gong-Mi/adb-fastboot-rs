#!/usr/bin/env python3
"""Test the test gate using an executable fake cargo, not product Rust tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("run_rust_tests.py")
spec = importlib.util.spec_from_file_location("rust_test_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hosttools-test-gate-")
        self.root = Path(self.temp.name)
        self.cargo = self.root / "cargo-fixture"
        self.cargo.write_text("#!" + sys.executable + "\n" + """
import json, os, sys, time
from pathlib import Path
with Path(os.environ['RUNNER_FIXTURE_TRACE']).open('a') as f:
    f.write(json.dumps(sys.argv[1:]) + '\\n')
mode = os.environ['RUNNER_FIXTURE_MODE']
print('EARLY_DIAGNOSTIC', flush=True)
if mode == 'timeout':
    time.sleep(60)
if mode == 'escape_stdout':
    pid = os.fork()
    if pid == 0:
        os.setsid()
        Path(os.environ['RUNNER_FIXTURE_TRACE'] + '.escaped').write_text(str(os.getpid()))
        time.sleep(4)
        os._exit(0)
    time.sleep(60)
if mode == 'invalid_bytes_failed':
    os.write(1, b'\\xffbinary diagnostic\\n')
    sys.exit(42)
if mode == 'failed_check' or mode == 'failed_test':
    sys.exit(42)
if sys.argv[3] == 'test':
    if mode == 'no_summary':
        print('command ended without running any harness')
    else:
        passed = 0 if mode == 'zero_tests' else 1
        ignored = 1 if mode == 'ignored' else 0
        failed = 1 if mode == 'false_green' else 0
        print(f'running {passed + ignored + failed} tests')
        state = 'FAILED' if mode == 'failed_label' else 'ok'
        prefix = 'diagnostic contains ' if mode == 'prefixed_label' else ''
        print(f'{prefix}test result: {state}. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; 0 filtered out')
""")
        self.cargo.chmod(0o755)
        self.env = mock.patch.dict(os.environ, RUNNER_FIXTURE_MODE="success",
                                   RUNNER_FIXTURE_TRACE=str(self.root / "trace"))
        self.env.start()
        self.common = ["--cargo", str(self.cargo), "--target-dir", str(self.root / "target"),
                       "--output-dir", str(self.root / "evidence")]

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_gate(self, *args, mode="success"):
        with mock.patch.dict(os.environ, RUNNER_FIXTURE_MODE=mode):
            return subprocess.run([sys.executable, str(SCRIPT), *self.common, *args],
                                  capture_output=True, text=True, timeout=20)

    def focused(self, mode="success", *extra):
        return self.run_gate("--package", "fastboot-protocol", "--lib", "--filter", "regression", *extra, mode=mode)

    def evidence(self):
        return json.loads((self.root / "evidence/result.json").read_text())

    def test_original_failure_and_early_diagnostic_are_preserved(self):
        result = self.focused("failed_test")
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("EARLY_DIAGNOSTIC", result.stdout)
        report = self.evidence()
        self.assertEqual(report["steps"][0]["exit_code"], 42)
        self.assertIn("EARLY_DIAGNOSTIC", Path(report["steps"][0]["log"]).read_text())

    def test_zero_executed_tests_do_not_pass(self):
        self.assertEqual(self.focused("zero_tests").returncode, 2)
        self.assertEqual(self.evidence()["status"], "INVALID_TEST_EVIDENCE")

    def test_missing_test_summary_is_not_a_pass(self):
        self.assertEqual(self.focused("no_summary").returncode, 2)

    def test_failed_summary_with_zero_process_status_is_not_a_pass(self):
        self.assertEqual(self.focused("false_green").returncode, 2)

    def test_ignored_tests_are_reported_not_counted_as_passed(self):
        self.assertEqual(self.focused("ignored").returncode, 0)
        report = self.evidence()
        self.assertEqual(report["status"], "PASS_WITH_IGNORED")
        self.assertEqual(report["steps"][0]["rust"]["passed"], 1)
        self.assertEqual(report["steps"][0]["rust"]["ignored"], 1)

    def test_local_is_locked_offline_and_target_is_explicit(self):
        self.assertEqual(self.focused().returncode, 0)
        report = self.evidence()
        self.assertIn("--locked", report["steps"][0]["command"])
        self.assertIn("--offline", report["steps"][0]["command"])
        self.assertEqual(report["target_dir"], str(self.root / "target"))

    def test_ci_uses_same_gate_but_online_is_explicit(self):
        result = self.run_gate("--scope", "matrix", "--features", "all", "--online")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        steps = self.evidence()["steps"]
        self.assertEqual([step["command"][3] for step in steps], ["check", "test"])
        self.assertTrue(all("--all-features" in step["command"] for step in steps))
        self.assertTrue(all("--locked" in step["command"] for step in steps))
        self.assertTrue(all("--offline" not in step["command"] for step in steps))

    def test_failed_check_does_not_run_next_step(self):
        result = self.run_gate("--scope", "matrix", mode="failed_check")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(len(self.evidence()["steps"]), 1)
        self.assertEqual(len((self.root / "trace").read_text().splitlines()), 1)

    def test_matrix_cannot_be_silently_filtered(self):
        result = self.run_gate("--scope", "matrix", "--filter", "small")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "trace").exists())

    def test_oracle_requires_explicit_ignored_execution(self):
        result = self.run_gate("--scope", "oracle", "--package", "fastboot-protocol", "--lib", "--filter", "simg2img_oracle")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        command = self.evidence()["steps"][0]["command"]
        self.assertEqual(command[command.index("--") + 1:], ["simg2img_oracle", "--ignored"])

    def test_timeout_is_not_a_pass(self):
        result = self.focused("timeout", "--timeout", "1")
        self.assertEqual(result.returncode, 124)
        self.assertEqual(self.evidence()["status"], "TIMEOUT")

    def test_source_change_invalidates_an_otherwise_green_run(self):
        identity = {"head": "fixed", "tree": "fixed", "overlay_sha256": "before", "worktree": str(runner.ROOT)}
        changed = dict(identity, overlay_sha256="after")
        argv = [*self.common, "--package", "fastboot-protocol", "--lib", "--filter", "regression"]
        with mock.patch.object(runner, "source_identity", side_effect=[identity, changed]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(argv), 2)
        self.assertEqual(self.evidence()["status"], "SOURCE_CHANGED_DURING_RUN")

    def test_existing_evidence_is_not_overwritten_by_a_retry(self):
        self.assertEqual(self.focused().returncode, 0)
        report = self.root / "evidence/result.json"
        saved = report.read_bytes()
        second = self.focused("failed_test")
        self.assertEqual(second.returncode, 2, second.stdout + second.stderr)
        self.assertEqual(report.read_bytes(), saved)
        self.assertEqual(len((self.root / "trace").read_text().splitlines()), 1)

    def test_interrupt_stops_owned_process_group_and_reports_cancelled(self):
        import signal
        identity = {"head": "fixed", "tree": "fixed", "overlay_sha256": "fixed", "worktree": str(runner.ROOT)}
        proc = mock.Mock(pid=424242)
        proc.poll.return_value = None
        proc.wait.side_effect = [KeyboardInterrupt(), 0]
        argv = [*self.common, "--package", "fastboot-protocol", "--lib", "--filter", "regression"]
        with mock.patch.object(runner, "source_identity", return_value=identity), mock.patch.object(runner.subprocess, "Popen", return_value=proc), mock.patch.object(runner.os, "killpg") as kill, contextlib.redirect_stdout(io.StringIO()):
            try:
                rc = runner.main(argv)
            except KeyboardInterrupt:
                self.fail("interrupt escaped without bounded process-group cancellation")
        self.assertEqual(rc, 130)
        kill.assert_called_once_with(424242, signal.SIGKILL)
        self.assertEqual(self.evidence()["status"], "CANCELLED")

    def test_filter_cannot_inject_cargo_options(self):
        for value in ["--manifest-path=/other/Cargo.toml", "--target-dir=/shared", "--all-features"]:
            with self.subTest(value=value):
                args = runner.arguments(["--package", "fastboot-protocol", "--lib", "--filter=" + value])
                with self.assertRaises(ValueError):
                    runner.make_commands(args)

    def test_filter_and_all_cases_are_mutually_exclusive(self):
        self.assertEqual(self.focused("success", "--all-cases").returncode, 2)
        self.assertFalse((self.root / "trace").exists())

    def test_failed_summary_label_is_not_accepted(self):
        self.assertEqual(self.focused("failed_label").returncode, 2)
        self.assertEqual(self.evidence()["status"], "INVALID_TEST_EVIDENCE")

    def test_summary_inside_a_diagnostic_is_not_counted(self):
        self.assertEqual(self.focused("prefixed_label").returncode, 2)

    def test_binary_failure_output_is_preserved_and_never_passes(self):
        result = self.focused("invalid_bytes_failed")
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        report = self.evidence()
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["exit_code"], 42)
        self.assertIn(b"\xffbinary diagnostic", Path(report["steps"][0]["log"]).read_bytes())

    def test_timeout_does_not_wait_for_detached_stdout_eof(self):
        import time
        try:
            result = self.focused("escape_stdout", "--timeout", "1")
            self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
            self.assertLess(self.evidence()["steps"][0]["seconds"], 2.5)
            self.assertEqual(self.evidence()["status"], "TIMEOUT")
        finally:
            # The escaped fixture is finite. A PID read from a file after it
            # may have exited is not a process-identity capability; do not open
            # a fresh pidfd or signal that possibly reused number.
            time.sleep(4)

    def test_second_cleanup_interrupt_cannot_publish_pass(self):
        identity = {"head": "fixed", "tree": "fixed", "overlay_sha256": "fixed", "worktree": str(runner.ROOT)}
        proc = mock.Mock(pid=424242)
        proc.poll.return_value = None
        proc.wait.side_effect = [KeyboardInterrupt(), KeyboardInterrupt(), 0]
        argv = [*self.common, "--package", "fastboot-protocol", "--lib", "--filter", "regression"]
        with mock.patch.object(runner, "source_identity", return_value=identity), mock.patch.object(runner.subprocess, "Popen", return_value=proc), mock.patch.object(runner.os, "killpg"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(argv), 130)
        report = self.evidence()
        self.assertEqual(report["status"], "CANCELLED")
        self.assertEqual(report["steps"][0]["exit_code"], 130)

    def test_real_sigint_after_spawn_before_handle_assignment_is_reaped(self):
        import signal
        identity = {"head": "fixed", "tree": "fixed", "overlay_sha256": "fixed", "worktree": str(runner.ROOT)}
        real_popen = subprocess.Popen
        owned = []
        def spawn_then_cancel(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            owned.append(process)
            # Real child exists, but execute() has not yet received the handle.
            os.kill(os.getpid(), signal.SIGINT)
            return process
        argv = [*self.common, "--package", "fastboot-protocol", "--lib", "--filter", "regression"]
        try:
            with mock.patch.dict(os.environ, RUNNER_FIXTURE_MODE="timeout"), mock.patch.object(runner, "source_identity", return_value=identity), mock.patch.object(runner.subprocess, "Popen", side_effect=spawn_then_cancel), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(argv), 130)
            self.assertEqual(len(owned), 1)
            self.assertIsNotNone(owned[0].poll(), "cancelled runner leaked its own spawned leader")
            self.assertEqual(self.evidence()["status"], "CANCELLED")
            self.assertEqual(self.evidence()["steps"][0]["exit_code"], 130)
        finally:
            for process in owned:
                # Keep the actual still-owned Popen object; never reopen a
                # process-identity handle from a stale number after reaping.
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
