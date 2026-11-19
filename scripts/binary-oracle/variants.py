#!/usr/bin/env python3
"""Protocol variant registry.

A *variant* binds three things so the same runners/diff work for AOSP adb,
AOSP fastboot and vendor forks (Huawei `hadb`, HarmonyOS `hdc`, MTK/KSU
bootloader shells, ...):

  codec      - message framing (see framing.py)
  transport  - how the client is pointed at the fixture (serial/env form)
  vocabulary - behaviour table: services/commands the fixture understands

Anything a variant does *not* declare must surface as a recorded FAIL, never
as a silent success: unknown traffic is evidence, not noise.

Deliberate non-goal: do not "normalize" vendor framing into the AOSP codec to
make a diff look clean. The framing difference is usually the finding.
"""
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framing import AdbSmartSocket, FastbootTcp  # noqa: E402


@dataclass
class Variant:
    name: str
    # None = framing not yet established from a capture. A variant with no
    # codec cannot be driven by the runners, and that is the correct state:
    # it stops a guessed framing from becoming "evidence".
    codec: Optional[type]
    # how the runner must address the fixture
    transport: str                 # "adb-server" | "fastboot-tcp" | "raw-tcp"
    serial_form: Optional[str] = None   # e.g. "-s tcp:127.0.0.1:{port}"
    env: Dict[str, str] = field(default_factory=dict)
    # behaviour table: command/service prefix -> handler name
    vocabulary: Dict[str, str] = field(default_factory=dict)
    # what is known / unknown before we have a real transcript
    known: str = ""
    unknown: str = ""
    # how to obtain a real transcript for an unknown implementation
    capture_hint: str = ""


AOSP_ADB = Variant(
    name="aosp-adb-35",
    codec=AdbSmartSocket,
    transport="adb-server",
    env={"ANDROID_ADB_SERVER_PORT": "{port}"},
    vocabulary={
        "host:version": "reply", "host:devices": "reply", "host:devices-l": "reply",
        "host:features": "reply", "host:get-state": "reply", "host:get-serialno": "reply",
        "host:get-devpath": "reply", "host:list-forward": "reply",
        "host:kill": "reply", "host:mdns:*": "reply", "host:tport:*": "ack+id",
        "host:transport*": "ack", "host:wait-for-*": "okay-okay-eof",
        "host-serial:*:features": "reply", "host-serial:*:transport*": "ack",
        "sync:": "device-sync", "shell*": "device-shellv2", "abb:*": "device-shellv2",
        "exec:*": "device-raw", "root:": "device-raw", "unroot:": "device-raw",
    },
    known="AOSP 35.0.2 host adb compiled locally with symbols; wire verified against AOSP sources.",
    unknown="26Q2-only services (server-status protobuf fields, track-app, dev-raw).",
)

AOSP_FASTBOOT = Variant(
    name="aosp-fastboot-35",
    codec=FastbootTcp,
    transport="fastboot-tcp",
    serial_form="-s tcp:127.0.0.1:{port}",
    vocabulary={
        "getvar:": "reply-okay-value", "getvar:all": "info-then-okay",
        "download:": "data-then-raw", "flash:": "write-partition",
        "erase:": "zero-partition", "fetch:": "data-then-raw",
        "set_active:": "mutate-slot", "reboot": "okay", "oem": "okay",
    },
    known="AOSP 35.0.2 fastboot (system/core/fastboot) with the Termux uid gate removed; "
          "framing confirmed from tcp.cpp (FB01 + 8-byte big-endian length).",
    unknown="26Q2 additions (fetch range semantics, super/super_empty handling, "
            "logical-partition checks, --slot variants).",
    capture_hint="record_proxy.py --listen 7200 --upstream <device>:<port> while a real "
                 "fastboot/flash tool talks to a device.",
)

HADB_PLACEHOLDER = Variant(
    name="huawei-hadb",
    codec=None,                # unconfirmed: must come from a capture, not from analogy
    transport="raw-tcp",
    serial_form="-s {serial}",
    vocabulary={},             # intentionally empty: unknown until captured
    known="Nothing verified. Name only: Huawei's adb-derived implementation.",
    unknown=("framing (hex-length vs binary), handshake/auth flow, service "
             "vocabulary, capability/feature names, whether it reuses adb "
             "A_* packet types or a different envelope, USB-only vs TCP."),
    capture_hint=("1) record_proxy.py between the vendor client and the vendor "
                  "daemon to get framing + service strings; 2) replay the "
                  "captured bytes into a fixture codec; 3) only then diff "
                  "against the Rust implementation."),
)

REGISTRY = {v.name: v for v in (AOSP_ADB, AOSP_FASTBOOT, HADB_PLACEHOLDER)}


def get(name):
    return REGISTRY[name]


if __name__ == "__main__":
    for v in REGISTRY.values():
        codec = v.codec.__name__ if v.codec else "<unconfirmed>"
        print(f"{v.name}: codec={codec} transport={v.transport}")
        print(f"  known  : {v.known}")
        print(f"  unknown: {v.unknown}")
