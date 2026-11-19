#!/usr/bin/env python3
"""Fake fastboot device (TCP transport) used as a differential oracle for
C fastboot vs Rust fastboot-rs.

Wire format (AOSP `system/core/fastboot/tcp.cpp`):
  * handshake: client sends 4 bytes "FB01", device answers 4 bytes "FB0x";
  * every message after that is framed: 8-byte big-endian payload length,
    then the payload. That applies to commands *and* to download payloads and
    to device responses.

The device keeps a partition table in memory so a run can be verified by
reading back bytes, not by trusting the client's own "OKAY".

usage: fakefastbootd.py <port> <logdir> [scenario_json]
"""
import hashlib
import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framing import FastbootTcp, Transcript  # noqa: E402

PARTITIONS = {
    "boot": (4096, b"B" * 4096),
    "init_boot": (1024, b"I" * 1024),
    "system": (8192, b"S" * 8192),
    "super": (16384, b"U" * 16384),
    "dtbo": (512, b"D" * 512),
}

VARS = {
    "version": "0.4",
    "version-bootloader": "fake-bootloader-1.0",
    "version-baseband": "fake-baseband",
    "product": "fake_product",
    "serialno": "FAKEFB0001",
    "secure": "yes",
    "unlocked": "yes",
    "max-download-size": "0x10000000",
    "max-fetch-size": "0x1000",
    "slot-count": "2",
    "current-slot": "a",
    "slot-successful:a": "yes",
    "slot-unbootable:a": "no",
    "slot-retry-count:a": "3",
    "slot-successful:b": "yes",
    "slot-unbootable:b": "yes",
    "slot-retry-count:b": "0",
    "super-partition-name": "super",
    "is-userspace": "no",
    "battery-voltage": "4200",
    "off-mode-charge": "1",
}


def slots_of(name):
    base = name[:-2] if name.endswith(("_a", "_b")) else name
    return base in ("boot", "init_boot", "dtbo", "system")


class Device:
    def __init__(self, conn, logdir, scenario):
        self.c = conn
        self.logdir = logdir
        self.scenario = scenario or {}
        self.log = open(os.path.join(logdir, "device.jsonl"), "a", buffering=1)
        # shared, protocol-agnostic wire layer: framing + byte-exact transcript
        self.codec = FastbootTcp(conn, Transcript(os.path.join(logdir, "transcript.jsonl")))
        # Slotted partitions are modelled as two independent buffers so a
        # `--slot a/b` mistake in the client is visible in the readback.
        self.parts = {}
        self.sizes = {}
        self.vars = dict(VARS)
        for name, (size, initial) in PARTITIONS.items():
            names = [f"{name}_a", f"{name}_b"] if slots_of(name) else [name]
            for full in names:
                self.parts[full] = bytearray(initial)
                self.sizes[full] = size
                self.vars[f"partition-size:{full}"] = "0x%x" % size
                self.vars[f"partition-type:{full}"] = "raw"
                self.vars[f"is-logical:{full}"] = "no"
            self.vars[f"has-slot:{name}"] = "yes" if slots_of(name) else "no"
        self.downloaded = b""
        self.commands = []

    # ---------- framing (delegated to the shared codec) ----------
    def read_msg(self):
        return self.codec.read_msg()

    def send_msg(self, payload):
        self.codec.write_msg(payload)

    def record(self, obj):
        self.log.write(json.dumps(obj) + "\n")

    # ---------- main ----------
    def run(self):
        if not self.codec.handshake():
            return
        while True:
            msg = self.read_msg()
            if msg is None:
                return
            if self.scenario.get("download_first", False):
                pass
            text = msg.decode("utf-8", "replace")
            if text.startswith(("INFO", "TEXT", "OKAY", "FAIL", "DATA")):
                # a download payload, not a command
                self.record({"actor": "download-data", "len": len(msg),
                             "sha256": hashlib.sha256(msg).hexdigest()})
                self.downloaded = msg
                continue
            cmd = text.rstrip("\x00")
            self.commands.append(cmd)
            self.record({"actor": "cmd", "text": cmd.replace("\x00", "\\0"), "len": len(msg),
                         "hex": msg[:48].hex()})
            self.handle(cmd)

    def resolve(self, part):
        if part in self.parts:
            return part
        if self.scenario.get("strict_slots"):
            # real bootloaders have no unsuffixed slot partition: `flash boot`
            # must be resolved by the client via has-slot + current-slot.
            return part
        base = part[:-2] if part.endswith(("_a", "_b")) else part
        if slots_of(base):
            cand = base + "_" + self.vars.get("current-slot", "a")
            if cand in self.parts:
                return cand
        return part

    def handle(self, cmd):
        if cmd.startswith("getvar:"):
            name = cmd[len("getvar:"):].rstrip("\x00")
            if name == "all":
                for k, v in sorted(self.vars.items()):
                    self.send_msg("INFO" + k + ": " + v)
                self.send_msg("OKAY")
                return
            if name in self.vars:
                self.send_msg("OKAY" + self.vars[name])
                return
            self.send_msg("FAILFailed to getvar " + name)
            return
        if cmd.startswith("download:"):
            size = int(cmd[len("download:"):].rstrip("\x00"), 16)
            if self.scenario.get("fail_download"):
                self.send_msg("FAILdownload rejected by scenario")
                return
            advertised = size
            if self.scenario.get("short_data"):
                advertised = max(1, size - 8)
            self.send_msg("DATA" + ("%08x" % advertised))
            payload = self.read_msg()
            self.record({"actor": "download", "requested": size, "advertised": advertised,
                         "got": len(payload or b""),
                         "sha256": hashlib.sha256(payload or b"").hexdigest()})
            if payload is None:
                return
            self.downloaded = payload
            if self.scenario.get("fail_after_download"):
                self.send_msg("FAILdownload failed mid-way")
                return
            self.send_msg("OKAY")
            return
        if cmd.startswith("flash:"):
            part = cmd[len("flash:"):].rstrip("\x00")
            if self.scenario.get("fail_flash"):
                self.send_msg("FAILpartition " + part + " rejected by scenario")
                return
            key = self.resolve(part)
            if key not in self.parts:
                self.send_msg("FAILpartition '" + part + "' not found")
                return
            data = self.downloaded
            if len(data) > self.sizes[key]:
                self.send_msg("FAILimage too large for '" + part + "'")
                return
            slot = bytearray(self.parts[key])
            slot[:len(data)] = data
            self.parts[key] = slot
            self.record({"actor": "flash", "partition": part, "resolved": key, "bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()})
            self.send_msg("OKAY")
            return
        if cmd.startswith("erase:"):
            part = cmd[len("erase:"):].rstrip("\x00")
            key = self.resolve(part)
            if key not in self.parts:
                self.send_msg("FAILpartition '" + part + "' not found")
                return
            self.parts[key] = bytearray(self.sizes[key])
            self.record({"actor": "erase", "partition": part, "resolved": key})
            self.send_msg("OKAY")
            return
        if cmd.startswith("fetch:"):
            spec = cmd[len("fetch:"):].rstrip("\x00")
            fields = spec.split(":")
            part, off, size = fields[0], None, None
            if len(fields) >= 2 and fields[1]:
                off = int(fields[1], 16)
            if len(fields) >= 3 and fields[2]:
                size = int(fields[2], 16)
            key = self.resolve(part)
            if key not in self.parts:
                self.send_msg("FAILpartition '" + part + "' not found")
                return
            data = bytes(self.parts[key])
            if off is not None:
                data = data[off:]
            if size is not None:
                data = data[:size]
            self.record({"actor": "fetch", "spec": spec, "bytes": len(data)})
            self.send_msg("DATA" + ("%08x" % len(data)))
            self.send_msg(data)
            self.send_msg("OKAY")
            return
        if cmd.startswith("set_active:"):
            self.vars["current-slot"] = cmd[len("set_active:"):].rstrip("\x00")
            self.record({"actor": "set_active", "slot": self.vars["current-slot"]})
            self.send_msg("OKAY")
            return
        if cmd.startswith("reboot"):
            self.record({"actor": "reboot", "cmd": cmd})
            self.send_msg("OKAY")
            return
        if cmd.startswith("oem"):
            self.send_msg("OKAY")
            return
        self.send_msg("FAILunknown command " + cmd)

    def dump(self):
        # atomic: a reader must never see a half-written (or 0-byte) state file,
        # which would read as "the flash did nothing".
        parts = os.path.join(self.logdir, "partitions.json")
        with open(parts + ".tmp", "w") as f:
            json.dump({k: {"len": len(v), "sha256": hashlib.sha256(bytes(v)).hexdigest(),
                           "head": bytes(v[:16]).hex()} for k, v in self.parts.items()}, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(parts + ".tmp", parts)
        vars_after = os.path.join(self.logdir, "vars-after.json")
        with open(vars_after + ".tmp", "w") as f:
            json.dump(self.vars, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(vars_after + ".tmp", vars_after)


def main():
    port = int(sys.argv[1])
    logdir = sys.argv[2]
    scenario = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    os.makedirs(logdir, exist_ok=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    with open(os.path.join(logdir, "ready"), "w") as f:
        f.write(str(port))
    while True:
        conn, _ = s.accept()
        dev = Device(conn, logdir, scenario)
        try:
            dev.run()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            dev.dump()
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
