#!/usr/bin/env python3
"""Minimal, dependency-free fastboot case against fakefastbootd.py.

This exists to prove the harness runs end to end *without* the C reference
binary: the fixture is one side, this script is a stand-in client, and the
pass criterion is the bytes that landed on the fake partition -- not the
OKAY on the wire.

  default            spawn fakefastbootd.py, run the case, verify readback
  --client-only      only act as the client, talk to --port (e.g. a
                     record_proxy.py listener fronting a device)

usage:
  python3 scripts/binary-oracle/examples/fastboot_one_case.py
  python3 scripts/binary-oracle/examples/fastboot_one_case.py --client-only --port 7100
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from framing import FastbootTcp, Transcript  # noqa: E402

PAYLOAD = bytes(range(256)) * 4          # 1024 bytes, fits fake boot_a (4096)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_case(port, workdir):
    """getvar:version -> download -> flash:boot, asserting each device reply."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=5)
    codec = FastbootTcp(conn, Transcript(os.path.join(workdir, "client.jsonl")))
    assert codec.handshake(), "FB01 handshake rejected by device"

    codec.write_msg(b"getvar:version")
    reply = codec.read_msg()
    print(f"getvar:version -> {reply!r}")
    assert reply.startswith(b"OKAY"), reply

    codec.write_msg(b"download:%08x" % len(PAYLOAD))
    reply = codec.read_msg()
    print(f"download:{len(PAYLOAD):08x} -> {reply!r}")
    assert reply.startswith(b"DATA0000"), reply
    advertised = int(reply[4:12], 16)
    codec.write_msg(PAYLOAD[:advertised])
    reply = codec.read_msg()
    print(f"  payload  -> {reply!r}")
    assert reply == b"OKAY", reply

    codec.write_msg(b"flash:boot")
    reply = codec.read_msg()
    print(f"flash:boot -> {reply!r}")
    assert reply == b"OKAY", reply
    conn.close()


def _load_json(path, needle, tries=60):
    """Device state is dumped when the session closes: poll until it parses."""
    for _ in range(tries):
        try:
            with open(path) as f:
                data = json.load(f)
            if needle in data:
                return data
        except (OSError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise AssertionError(f"{path} never became readable")


def verify(workdir):
    """The real assertion: device-side bytes, not the client's OKAY.

    `flash:` writes into a 4096-byte boot_a buffer, so the partition hash is
    not the payload hash; the flashed span is attested by the device's own
    `flash` event and the partition head shows it landed at offset 0.
    """
    parts = _load_json(os.path.join(workdir, "partitions.json"), "boot_a")
    events = [json.loads(l) for l in open(os.path.join(workdir, "device.jsonl"))
              if l.strip()]
    flashed = [e for e in events if e.get("actor") == "flash"]
    assert flashed, "device never recorded a flash"
    rec = flashed[-1]
    want = hashlib.sha256(PAYLOAD).hexdigest()
    print(f"device flash event: resolved={rec['resolved']} bytes={rec['bytes']} "
          f"sha256={rec['sha256'][:16]}…")
    assert rec["resolved"] == "boot_a", rec
    assert rec["bytes"] == len(PAYLOAD), rec
    assert rec["sha256"] == want, (rec["sha256"], want)
    assert parts["boot_a"]["head"] == PAYLOAD[:16].hex(), parts["boot_a"]["head"]
    assert parts["boot_a"]["sha256"] != hashlib.sha256(b"B" * 4096).hexdigest()
    print(f"boot_a head: {parts['boot_a']['head']} (offset 0 matches payload)")
    print("PASS: split-flash landed byte-for-byte in boot_a")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-only", action="store_true")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()

    workdir = os.environ.get("BINARY_ORACLE_WORK") or os.path.join(
        tempfile.mkdtemp(prefix="fastboot-one-case-"), "work")
    os.makedirs(workdir, exist_ok=True)
    for stale in ("ready", "device.jsonl", "transcript.jsonl", "client.jsonl",
                  "partitions.json"):
        try:
            os.unlink(os.path.join(workdir, stale))
        except OSError:
            pass

    if args.client_only:
        run_case(args.port, workdir)
        print("client-only run finished (verify readback where the device wrote)")
        return

    port = args.port or free_port()
    dev = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fakefastbootd.py"), str(port), workdir, "{}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if os.path.exists(os.path.join(workdir, "ready")):
                break
            if dev.poll() is not None:
                sys.exit(f"fakefastbootd died: {dev.stderr.read().decode()}")
            time.sleep(0.05)
        else:
            sys.exit("fakefastbootd never became ready")
        run_case(port, workdir)
        # the device dumps its final state when the session closes; wait for
        # that before killing it, or the state file never lands
        _load_json(os.path.join(workdir, "partitions.json"), "boot_a")
    finally:
        dev.terminate()
        try:
            dev.wait(3)
        except subprocess.TimeoutExpired:
            dev.kill()
    verify(workdir)


if __name__ == "__main__":
    main()
