#!/usr/bin/env python3
"""A *fake* fastboot client: enough of the CLI surface for run_fb_matrix.py.

Purpose: exercise the runner + diff machinery without the C reference binary
(no compiler, no Termux uid gate). It speaks the same TCP transport as the real
client (`-s tcp:host:port`) and the same FB01 framing, so a matrix run against
fakefastbootd.py is a real wire test of the harness -- not of any product.

It is NOT an oracle: it only proves the fixtures and runners agree with
themselves. For an actual differential you point run_fb_matrix.py at the C
binary and at the Rust binary.

usage:
  fake_fastboot_client.py -s tcp:127.0.0.1:7000 getvar product
  fake_fastboot_client.py -s tcp:127.0.0.1:7000 flash boot boot.img
  fake_fastboot_client.py -s tcp:127.0.0.1:7000 erase boot
exit: 0 on OKAY, 1 on FAIL, 2 on usage/IO error
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framing import FastbootTcp  # noqa: E402


class NullTranscript:
    def note(self, **kw):
        pass

    def rx(self, *a, **kw):
        pass

    def tx(self, *a, **kw):
        pass


def connect(serial):
    if not serial.startswith("tcp:"):
        sys.exit(f"fake client only supports -s tcp:host:port (got {serial})")
    host, port = serial[4:].rsplit(":", 1)
    conn = socket.create_connection((host, int(port)), timeout=10)
    codec = FastbootTcp(conn, NullTranscript())
    if not codec.handshake():
        sys.exit("FB01 handshake rejected")
    return codec


def expect_okay(codec, what):
    reply = codec.read_msg() or b""
    if reply.startswith(b"OKAY"):
        return reply[4:]
    print(f"FAILED ({what}): {reply.decode('utf-8', 'replace')}", file=sys.stderr)
    sys.exit(1)


def main():
    argv = sys.argv[1:]
    serial = None
    if argv[:1] == ["-s"]:
        serial, argv = argv[1], argv[2:]
    if not serial or not argv:
        sys.exit(__doc__)

    codec = connect(serial)
    cmd, rest = argv[0], argv[1:]

    if cmd == "getvar":
        codec.write_msg(("getvar:" + rest[0]).encode())
        payload = expect_okay(codec, cmd)
        if rest[0] == "all":
            while True:
                reply = codec.read_msg() or b""
                if reply.startswith(b"INFO"):
                    print(reply[4:].decode("utf-8", "replace"))
                    continue
                break
        else:
            print(payload.decode("utf-8", "replace"))
    elif cmd in ("flash", "erase", "fetch", "reboot", "reboot-bootloader", "oem"):
        if cmd == "flash":
            part, path = rest[0], rest[1]
            data = open(path, "rb").read()
            codec.write_msg(b"download:%08x" % len(data))
            reply = codec.read_msg() or b""
            if not reply.startswith(b"DATA"):
                print(f"FAILED (download): {reply!r}", file=sys.stderr)
                sys.exit(1)
            codec.write_msg(data[:int(reply[4:12], 16)])
            expect_okay(codec, "download")
            codec.write_msg(("flash:" + part).encode())
            expect_okay(codec, cmd)
        elif cmd == "erase":
            codec.write_msg(("erase:" + rest[0]).encode())
            expect_okay(codec, cmd)
        elif cmd == "fetch":
            codec.write_msg(("fetch:" + ":".join(rest)).encode())
            expect_okay(codec, cmd)
        else:
            codec.write_msg(cmd.encode())
            expect_okay(codec, cmd)
        print("OKAY")
    else:
        sys.exit(f"fake client: unsupported command {cmd}")


if __name__ == "__main__":
    main()
