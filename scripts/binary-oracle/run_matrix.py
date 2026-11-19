#!/usr/bin/env python3
"""Differential runner: drive a client binary through a fixed scenario matrix
against the fake ADB server, capture (exit code, stdout, stderr, server wire log)
as one JSON record per case.

usage: run_matrix.py <client-binary> <out.json> [case ...]
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.environ.get("BINARY_ORACLE_WORK", os.path.join(HERE, "work"))

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


CASES = [
    # name, argv, stdin, needs_server
    ("version", ["version"], None, False),
    ("help", ["--help"], None, False),
    ("noddaemon-badflag", ["--not-a-flag"], None, False),
    ("unknown-command", ["frobnicate"], None, False),
    ("devices", ["devices"], None, True),
    ("devices-l", ["devices", "-l"], None, True),
    ("get-state", ["get-state"], None, True),
    ("get-serialno", ["get-serialno"], None, True),
    ("get-devpath", ["get-devpath"], None, True),
    ("features", ["features"], None, True),
    ("forward-list", ["forward", "--list"], None, True),
    ("mdns-check", ["mdns", "check"], None, True),
    ("mdns-services", ["mdns", "services"], None, True),
    ("reconnect-offline", ["reconnect", "offline"], None, True),
    ("wait-for-device", ["wait-for-device"], None, True),
    ("kill-server", ["kill-server"], None, True),
    ("shell", ["shell", "echo", "hi"], None, True),
    ("shell-T", ["shell", "-T", "echo", "hi"], None, True),
    ("exec-out", ["exec-out", "echo", "hi"], None, True),
    ("reboot", ["reboot"], None, True),
    ("root", ["root"], None, True),
    ("unroot", ["unroot"], None, True),
    ("tcpip", ["tcpip", "5555"], None, True),
    ("remount", ["remount"], None, True),
    ("jdwp", ["jdwp"], None, True),
    ("push", ["push", "SRC", "/data/local/tmp/x"], None, True),
    ("pull", ["pull", "/data/local/tmp/x", "DST"], None, True),
    ("logcat-d", ["logcat", "-d"], None, True),
    ("install", ["install", "APK"], None, True),
    ("keygen", ["keygen", "KEYFILE"], None, False),
    ("version-server-missing", ["-s", "nosuchserial", "shell", "id"], None, False),
    # --- extended matrix ---
    ("s-serial-devices", ["-s", "emulator-5554", "devices"], None, True),
    ("s-serial-shell", ["-s", "emulator-5554", "shell", "echo", "hi"], None, True),
    ("connect", ["connect", "127.0.0.1:5555"], None, True),
    ("disconnect", ["disconnect", "127.0.0.1:5555"], None, True),
    ("forward-add", ["forward", "tcp:12345", "tcp:6789"], None, True),
    ("forward-remove-all", ["forward", "--remove-all"], None, True),
    ("reverse-list", ["reverse", "--list"], None, True),
    ("abb", ["abb", "echo", "hi"], None, True),
    ("exec-in", ["exec-in", "cat"], b"stdin-payload\n", True),
    ("wait-for-disconnect", ["wait-for-disconnect"], None, True),
    ("usb", ["usb"], None, True),
    ("uninstall", ["uninstall", "com.example.app"], None, True),
    ("shell-tty", ["shell", "-t", "echo", "hi"], None, True),
    ("shell-x", ["shell", "-x", "echo", "hi"], None, True),
    ("start-server", ["start-server"], None, True),
    ("devices-flag-l-after", ["devices", "--long"], None, True),
]


def run_case(binary, name, argv, stdin, needs_server):
    tag = os.path.basename(binary).replace("/", "_")
    case_dir = os.path.join(WORK, f"run-tmp-{tag}")
    shutil.rmtree(case_dir, ignore_errors=True)
    os.makedirs(case_dir, exist_ok=True)
    home = os.path.join(case_dir, "home")
    os.makedirs(home, exist_ok=True)
    rec = {"case": name, "argv": argv, "binary": binary}

    # fixtures
    src = os.path.join(case_dir, "payload.bin")
    with open(src, "wb") as f:
        f.write(b"0123456789" * 10)
    apk = os.path.join(case_dir, "fake.apk")
    with open(apk, "wb") as f:
        f.write(b"PK\x03\x04" + b"0" * 100)
    keyfile = os.path.join(case_dir, "adbkey-probe")
    dst = os.path.join(case_dir, "pulled.bin")
    real_argv = [a.replace("SRC", src).replace("APK", apk).replace("KEYFILE", keyfile).replace("DST", dst)
                 for a in argv]

    port = free_port()
    env = dict(os.environ)
    env.update({
        "ANDROID_ADB_SERVER_PORT": str(port),
        "HOME": home,
        "ADB_MDNS": "0",
        "ADB_TRACE": "",
        "ADB_VENDOR_KEYS": "",
    })
    env.pop("ADB_SERVER_SOCKET", None)

    srv = None
    if needs_server:
        srv = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py"), str(port), case_dir],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = os.path.join(case_dir, "ready")
        for _ in range(60):
            if os.path.exists(ready):
                break
            time.sleep(0.05)

    try:
        p = subprocess.run([binary] + real_argv, input=stdin, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        rec["rc"] = p.returncode
        rec["stdout"] = p.stdout.decode("utf-8", "replace")
        rec["stderr"] = p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        rec["rc"] = "TIMEOUT"
        rec["stdout"] = (e.stdout or b"").decode("utf-8", "replace")
        rec["stderr"] = (e.stderr or b"").decode("utf-8", "replace")
    finally:
        time.sleep(0.15)
        if srv:
            srv.terminate()
            try:
                srv.wait(2)
            except subprocess.TimeoutExpired:
                srv.kill()
        log = os.path.join(case_dir, "server.jsonl")
        wire = []
        if os.path.exists(log):
            with open(log) as f:
                for line in f:
                    try:
                        wire.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        rec["wire"] = wire
        # local artifacts
        rec["keyfile_exists"] = os.path.exists(keyfile)
        rec["pulled_exists"] = os.path.exists(dst)
        if rec["pulled_exists"]:
            rec["pulled_bytes"] = open(dst, "rb").read().decode("utf-8", "replace")[:80]
    return rec


def main():
    binary = sys.argv[1]
    out = sys.argv[2]
    wanted = sys.argv[3:]
    os.makedirs(WORK, exist_ok=True)
    results = []
    for name, argv, stdin, needs in CASES:
        if wanted and name not in wanted:
            continue
        print(f"--- {name}", flush=True)
        results.append(run_case(binary, name, argv, stdin, needs))
    with open(out, "w") as f:
        json.dump(results, f, indent=1)
    print(f"wrote {out} ({len(results)} cases)")


if __name__ == "__main__":
    main()
