#!/usr/bin/env python3
"""Differential runner for fastboot: drive a client binary against
fakefastbootd.py over the AOSP TCP transport (`-s tcp:127.0.0.1:PORT`),
capture the CLI result *and* the device-side command log / final partition
state.

usage: run_fb_matrix.py <client-binary> <out.json> [case ...]
"""
import hashlib
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


# name, argv template, scenario
CASES = [
    ("help", ["--help"], {}),
    ("bad-flag", ["--not-a-flag"], {}),
    ("devices", ["devices"], {}),
    ("getvar-version", ["getvar", "version"], {}),
    ("getvar-product", ["getvar", "product"], {}),
    ("getvar-all", ["getvar", "all"], {}),
    ("getvar-unknown", ["getvar", "no-such-var"], {}),
    ("getvar-partition-size", ["getvar", "partition-size:boot"], {}),
    ("flash-boot", ["flash", "boot", "BOOTIMG"], {}),
    ("flash-boot-slot-b", ["flash", "boot_b", "BOOTIMG"], {}),
    ("flash-raw", ["flash:raw", "boot", "MAGICIMG"], {}),
    ("flash-avb", ["flash", "boot", "AVBIMG"], {}),
    ("flash-boot-strict", ["flash", "boot", "BOOTIMG"], {"strict_slots": True}),
    ("erase-boot-strict", ["erase", "boot"], {"strict_slots": True}),
    ("flash-too-big", ["flash", "init_boot", "BIGIMG"], {}),
    ("flash-fail", ["flash", "boot", "BOOTIMG"], {"fail_flash": True}),
    ("flash-short-data", ["flash", "boot", "BOOTIMG"], {"short_data": True}),
    ("flash-download-fail", ["flash", "boot", "BOOTIMG"], {"fail_after_download": True}),
    ("erase-boot", ["erase", "boot"], {}),
    ("erase-unknown", ["erase", "nosuchpart"], {}),
    ("fetch-boot", ["fetch", "boot"], {}),
    ("fetch-boot-out", ["fetch", "boot", "FETCHOUT"], {}),
    ("set-active-b", ["--set-active=b"], {}),
    ("reboot-bootloader", ["reboot-bootloader"], {}),
    ("reboot", ["reboot"], {}),
    ("oem-device-info", ["oem", "device-info"], {}),
    ("s-serial-getvar", ["-s", "tcp:127.0.0.1:PORT", "getvar", "product"], {}),
]


def run_case(binary, name, argv, scenario):
    tag = os.path.basename(binary)
    case_dir = os.path.join(WORK, f"fb-{tag}-{name}")
    shutil.rmtree(case_dir, ignore_errors=True)
    os.makedirs(case_dir, exist_ok=True)

    bootimg = os.path.join(case_dir, "boot.img")
    with open(bootimg, "wb") as f:
        f.write(bytes(range(256)) * 4)          # 1024 bytes
    magicimg = os.path.join(case_dir, "magic.img")
    with open(magicimg, "wb") as f:
        f.write(b"K" * 4096)                   # plain kernel >= sizeof(boot_img_hdr_v3)
    avbimg = os.path.join(case_dir, "avb.img")
    _avb = bytearray(b"Z" * 1024)
    _avb[960:964] = b"AVBf"
    _avb[964:1024] = b"\xa5" * 60
    with open(avbimg, "wb") as f:
        f.write(bytes(_avb))
    bigimg = os.path.join(case_dir, "big.img")
    with open(bigimg, "wb") as f:
        f.write(b"X" * 9000)                    # larger than init_boot (1024)
    fetchout = os.path.join(case_dir, "fetched.bin")

    fixed = os.environ.get("FB_FIXED_PORT")
    port = int(fixed) if fixed else free_port()
    real_argv = []
    for a in argv:
        a = a.replace("BOOTIMG", bootimg).replace("BIGIMG", bigimg)
        a = a.replace("MAGICIMG", magicimg).replace("AVBIMG", avbimg)
        a = a.replace("FETCHOUT", fetchout)
        a = a.replace("PORT", str(port))
        real_argv.append(a)
    if not fixed and not any(a.startswith("tcp:") for a in real_argv):
        real_argv = ["-s", f"tcp:127.0.0.1:{port}"] + real_argv

    env = dict(os.environ)
    env.pop("ANDROID_SERIAL", None)
    env["HOME"] = os.path.join(case_dir, "home")
    os.makedirs(env["HOME"], exist_ok=True)

    needs_device = name not in ("help", "bad-flag", "devices")
    dev = None
    if needs_device:
        dev = subprocess.Popen([sys.executable, os.path.join(HERE, "fakefastbootd.py"),
                                str(port), case_dir, json.dumps(scenario)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if os.path.exists(os.path.join(case_dir, "ready")):
                break
            time.sleep(0.05)

    rec = {"case": name, "argv": real_argv, "scenario": scenario, "binary": binary}
    try:
        p = subprocess.run([binary] + real_argv, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=20)
        rec["rc"] = p.returncode
        rec["stdout"] = p.stdout.decode("utf-8", "replace")
        rec["stderr"] = p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        rec["rc"] = "TIMEOUT"
        rec["stdout"] = (e.stdout or b"").decode("utf-8", "replace")
        rec["stderr"] = (e.stderr or b"").decode("utf-8", "replace")
    finally:
        time.sleep(0.2)
        if dev:
            dev.terminate()
            try:
                dev.wait(2)
            except subprocess.TimeoutExpired:
                dev.kill()
        cmds, events = [], []
        log = os.path.join(case_dir, "device.jsonl")
        if os.path.exists(log):
            for line in open(log):
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("actor") == "cmd":
                    cmds.append(e["text"])
                elif e.get("actor") != "send":
                    events.append(e)
        rec["device_cmds"] = cmds
        rec["device_events"] = events
        parts = os.path.join(case_dir, "partitions.json")
        rec["partitions"] = json.load(open(parts)) if os.path.exists(parts) else {}
        if os.path.exists(fetchout):
            data = open(fetchout, "rb").read()
            rec["fetched"] = {"len": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        else:
            rec["fetched"] = None
    return rec


def main():
    binary = sys.argv[1]
    out = sys.argv[2]
    wanted = sys.argv[3:]
    os.makedirs(WORK, exist_ok=True)
    results = []
    for name, argv, scenario in CASES:
        if wanted and name not in wanted:
            continue
        print(f"--- {name}", flush=True)
        results.append(run_case(binary, name, argv, scenario))
    with open(out, "w") as f:
        json.dump(results, f, indent=1)
    print(f"wrote {out} ({len(results)} cases)")


if __name__ == "__main__":
    main()
