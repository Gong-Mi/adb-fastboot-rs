#!/usr/bin/env python3
"""Run a local Rust target or one CI leg; retain bounded, fail-closed evidence.

Local commands are locked/offline. Source snapshots are endpoint observations,
not continuous mutation detection. This gate never certifies physical hardware.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FEATURES = {"default": [], "all": ["--all-features"], "none": ["--no-default-features"]}


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def source_identity():
    digest = hashlib.sha256(git("diff", "--binary", "HEAD"))
    for item in sorted(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
        if item:
            digest.update(item)
            path = ROOT / os.fsdecode(item)
            digest.update(path.read_bytes() if path.is_file() else b"<non-file>")
    return {"head": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "overlay_sha256": digest.hexdigest(), "worktree": str(ROOT)}


def rust_results(text):
    # Only complete libtest summary lines count. Retain status independently of
    # counters so a contradictory FAILED/zero-fail summary cannot certify green.
    pattern = (r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
               r"(\d+) measured; (\d+) filtered out(?:; finished in [^\r\n]*)?$" )
    rows = []
    for match in re.finditer(pattern, text, re.MULTILINE):
        rows.append({"status": match.group(1), **dict(zip(
            ["passed", "failed", "ignored", "measured", "filtered"], map(int, match.groups()[1:])) )})
    return {"summary_rows": len(rows), "statuses": [row["status"] for row in rows],
            **{key: sum(row[key] for row in rows)
               for key in ["passed", "failed", "ignored", "measured", "filtered"]}}


def make_commands(args):
    common = [args.cargo, "--color", "never"]
    flags = ["--locked"] + ([] if args.online else ["--offline"]) + FEATURES[args.features]
    if args.filter and args.filter.startswith("-"):
        raise ValueError("--filter is a test-name substring, not a Cargo/libtest option")
    if args.filter and args.all_cases:
        raise ValueError("--filter and --all-cases are mutually exclusive")
    if args.scope == "matrix":
        if args.package or args.bin or args.test or args.lib or args.filter or args.all_cases:
            raise ValueError("matrix scope must not silently filter workspace targets")
        return [common + ["check", "--workspace"] + flags,
                common + ["test", "--workspace"] + flags]
    if not args.package:
        raise ValueError("focused/oracle scope requires --package")
    if int(args.lib) + int(bool(args.bin)) + int(bool(args.test)) != 1:
        raise ValueError("select exactly one target with --lib, --bin NAME or --test NAME")
    if not args.filter and not args.all_cases:
        raise ValueError("provide --filter or explicitly request --all-cases")
    target = ["--lib"] if args.lib else (["--bin", args.bin] if args.bin else ["--test", args.test])
    cmd = common + ["test", "-p", args.package] + target + flags
    harness_args = ([args.filter] if args.filter else []) + (["--ignored"] if args.scope == "oracle" else [])
    if harness_args:
        cmd += ["--", *harness_args]
    return [cmd]


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=["focused", "matrix", "oracle"], default="focused")
    parser.add_argument("--features", choices=FEATURES, default="default")
    parser.add_argument("--package")
    parser.add_argument("--lib", action="store_true")
    parser.add_argument("--bin")
    parser.add_argument("--test")
    parser.add_argument("--filter")
    parser.add_argument("--all-cases", action="store_true")
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=900, help="budget for the entire Cargo command, including compilation")
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--cargo", default="cargo", help="explicit tool override, including gate fixtures")
    return parser.parse_args(argv)


@contextlib.contextmanager
def signal_policy(cleanup=False):
    saved = {}
    if threading.current_thread() is threading.main_thread():
        for number in [signal.SIGINT, signal.SIGTERM]:
            saved[number] = signal.getsignal(number)
            def cancelled(_number, _frame):
                raise KeyboardInterrupt
            signal.signal(number, signal.SIG_IGN if cleanup else cancelled)
    try:
        yield
    finally:
        for number, handler in saved.items():
            signal.signal(number, handler)


@contextlib.contextmanager
def defer_spawn_cancellation():
    """Record cancellation until the returned Popen handle has been adopted.

    Python signal handlers may run inside Popen after fork but before its
    constructor returns. Delaying the exception closes that ownership gap.
    """
    pending = []
    saved = {}
    if threading.current_thread() is threading.main_thread():
        def record(number, _frame):
            pending.append(number)
        for number in [signal.SIGINT, signal.SIGTERM]:
            saved[number] = signal.getsignal(number)
            signal.signal(number, record)
    try:
        yield pending
    finally:
        for number, handler in saved.items():
            signal.signal(number, handler)


def stop_owned(proc):
    """Bound cleanup of the still-owned leader/group, without stdout EOF waits.

    Escaped sessions are outside this group contract. Do not signal a possibly
    reused raw PID after Popen has already reaped the leader.
    """
    with signal_policy(cleanup=True):
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for _attempt in range(2):
            try:
                proc.wait(timeout=2)
                return None
            except KeyboardInterrupt:
                continue
            except subprocess.TimeoutExpired:
                return "leader did not reap within bounded cleanup; group kill requested"
        return "cleanup interrupted repeatedly; leader reaping unconfirmed"


def execute(cmd, args, env, output, index, evidence):
    logfile = output / f"{index:02d}-{cmd[3]}.log"
    streamfile = output / f"{index:02d}-{cmd[3]}.stream"
    row = {"command": cmd, "exit_code": None, "log": str(logfile), "producer_log": str(streamfile)}
    evidence["steps"].append(row)
    start = time.monotonic()
    proc = None
    try:
        # File-backed binary output avoids pipe-EOF dependence on descendants.
        with streamfile.open("wb") as stream:
            with defer_spawn_cancellation() as pending:
                proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, start_new_session=True)
            if pending:
                raise KeyboardInterrupt
            try:
                rc = proc.wait(timeout=args.timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                rc = 130 if isinstance(error, KeyboardInterrupt) else 124
                row["cleanup_issue"] = stop_owned(proc)
            row["exit_code"] = rc
    except KeyboardInterrupt:
        row["exit_code"] = 130
        if proc is not None:
            row["cleanup_issue"] = stop_owned(proc)
        raise
    except Exception:
        if proc is not None:
            row["cleanup_issue"] = stop_owned(proc)
        raise
    finally:
        row["seconds"] = time.monotonic() - start
        # Snapshot observed bytes. A detached producer may retain .stream, but
        # cannot later alter the immutable final .log snapshot.
        if streamfile.exists():
            raw = streamfile.read_bytes()
            logfile.write_bytes(raw)
            row["log_sha256"] = hashlib.sha256(raw).hexdigest()
    raw = logfile.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    print(text, end="" if text.endswith("\n") else "\n", flush=True)
    if cmd[3] == "test":
        row["rust"] = rust_results(text)
    return row


def main(argv=None):
    args = arguments(argv)
    try:
        if args.jobs < 1 or args.timeout < 1:
            raise ValueError("jobs and timeout must be positive")
        commands = make_commands(args)
        before = source_identity()
        cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "adb-fastboot-rs-tests"
        key = hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]
        target = (args.target_dir or cache / ("target-" + key)).resolve()
        output = (args.output_dir or cache / ("evidence-" + key) / f"{time.time_ns()}-{os.getpid()}").resolve()
        if output == ROOT or ROOT in output.parents:
            raise ValueError("--output-dir must be outside the source checkout")
        target.mkdir(parents=True, exist_ok=True)
        output.mkdir(parents=True, exist_ok=False)
        lock = (target / ".hosttools-runner.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            raise ValueError("target directory already has an active test runner")
    except (Exception, KeyboardInterrupt) as error:
        print(f"SETUP_FAILURE: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS=str(args.jobs),
               CMAKE_BUILD_PARALLEL_LEVEL=str(args.jobs))
    evidence = {"source": before, "scope": args.scope, "features": args.features,
                "offline": not args.online, "target_dir": str(target), "steps": [],
                "source_observation": "before/after snapshots only; freeze source externally",
                "timeout_scope": "whole Cargo command including compilation; bounded leader/group cleanup, not detached sessions"}
    result, status = 2, "INCOMPLETE"
    try:
        with signal_policy():
            saw_ignored = False
            for index, cmd in enumerate(commands):
                print("RUN " + json.dumps(cmd), flush=True)
                row = execute(cmd, args, env, output, index, evidence)
                rc = row["exit_code"]
                if rc != 0:
                    result = rc if rc > 0 else 128 - rc
                    status = {124: "TIMEOUT", 130: "CANCELLED"}.get(rc, "FAILED")
                    break
                if "rust" in row:
                    stats = row["rust"]
                    if (not stats["summary_rows"] or not stats["passed"] or stats["failed"]
                            or any(value != "ok" for value in stats["statuses"])):
                        result, status = 2, "INVALID_TEST_EVIDENCE"
                        break
                    saw_ignored |= bool(stats["ignored"])
            else:
                result, status = 0, "PASS_WITH_IGNORED" if saw_ignored else "PASS"
            after = source_identity()
            evidence["source_after"] = after
            if after != before:
                result, status = 2, "SOURCE_CHANGED_DURING_RUN"
    except KeyboardInterrupt as error:
        evidence["error"] = type(error).__name__
        result, status = 130, "CANCELLED"
    except Exception as error:
        evidence["error"] = f"{type(error).__name__}: {error}"
        result, status = 2, "EXECUTION_ERROR"
    finally:
        with signal_policy(cleanup=True):
            evidence.update(status=status, exit_code=result,
                            boundary="selected host tests only; no physical device/USB acceptance")
            report = output / "result.json"
            try:
                report.write_text(json.dumps(evidence, indent=2, ensure_ascii=False))
            except Exception as error:
                print(f"EVIDENCE_WRITE_FAILED: {error}", file=sys.stderr)
                result, status = 2, "EVIDENCE_WRITE_FAILED"
            finally:
                lock.close()
    print(f"{status}: evidence={report} exit_code={result}")
    return result


if __name__ == "__main__":
    sys.exit(main())
