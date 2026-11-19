#!/usr/bin/env python3
"""Fake ADB server: accepts hex-length host services, logs exact bytes,
answers from a scripted table so that both C adb and Rust adb-rs clients can
be driven through identical scenarios.

Key protocol facts modelled here (AOSP client behaviour):
  * one-shot host services are answered then the server must CLOSE the
    connection -- the client calls ReadOrderlyShutdown() and blocks until EOF;
  * transport selection answers bare OKAY (plus an 8-byte transport id for
    host:tport:*) and KEEPS the connection open, because the same socket then
    carries the device service request.
"""
import json
import os
import socket
import struct
import sys
import threading
import time

FEATURES = "cmd,shell_v2,abb,abb_exec,apex,deviceside,remount_shell"
DEVICES = "emulator-5554\tdevice\n"
DEVICES_L = "emulator-5554\tdevice product:sdk model:emu device:emu transport_id:1\n"
VERSION = "0029"
SERIAL = "emulator-5554"

KEEP = "keep"
CLOSE = "close"


class FakeServer:
    def __init__(self, port, logdir):
        self.port = port
        self.logdir = logdir
        self.sock = None
        self.stop = threading.Event()
        self.conn_id = 0
        self.log = open(os.path.join(logdir, "server.jsonl"), "a", buffering=1)
        self.lock = threading.Lock()

    def record(self, conn, actor, data):
        if isinstance(data, (bytes, bytearray)):
            text = data.decode("utf-8", "replace")
            hexed = data.hex()
        else:
            # keep byte-level evidence for requests too (they arrive as str
            # after the length prefix is consumed)
            text = str(data)
            hexed = text.encode("utf-8", "replace").hex()
        rec = {"conn": conn, "actor": actor, "hex": hexed, "text": text.replace("\x00", "\\0")}
        with self.lock:
            self.log.write(json.dumps(rec) + "\n")

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port))
        s.listen(16)
        s.settimeout(0.2)
        self.sock = s

        def loop():
            while not self.stop.is_set():
                try:
                    c, _ = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with self.lock:
                    self.conn_id += 1
                    cid = self.conn_id
                threading.Thread(target=self.handle, args=(c, cid), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()

    def shutdown(self):
        self.stop.set()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    @staticmethod
    def okay(payload=None):
        if payload is None:
            return b"OKAY"
        return b"OKAY" + ("%04x" % len(payload)).encode() + payload

    @staticmethod
    def fail(msg=""):
        m = msg.encode()
        return b"FAIL" + ("%04x" % len(m)).encode() + m

    def handle(self, c, cid):
        c.settimeout(8.0)
        try:
            while True:
                req = self.read_hex_command(c, cid)
                if req is None:
                    return
                self.record(cid, "host", req)
                if not req.startswith(("host:", "host-")):
                    self.device_service(c, cid, req)
                    return
                verdict = self.host_service(c, cid, req)
                if verdict == CLOSE:
                    return
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            return
        finally:
            try:
                c.close()
            except OSError:
                pass

    def read_hex_command(self, c, cid):
        buf = b""
        while len(buf) < 4:
            chunk = c.recv(4 - len(buf))
            if not chunk:
                return None
            buf += chunk
        try:
            n = int(buf.decode("ascii"), 16)
        except ValueError:
            self.record(cid, "badprefix", buf)
            return None
        data = b""
        while len(data) < n:
            chunk = c.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data.decode("utf-8", "replace")

    def send(self, c, cid, data):
        self.record(cid, "send", data)
        c.sendall(data)

    def ack(self, c, cid):
        """Bare OKAY -> the socket must stay open for the next host command."""
        self.send(c, cid, b"OKAY")
        return KEEP

    def reply(self, c, cid, payload=b""):
        """OKAY + length-prefixed payload -> client will ReadOrderlyShutdown."""
        self.send(c, cid, self.okay(payload))
        return CLOSE

    def host_service(self, c, cid, req):
        # ---- transport selection: keep the connection for the device service
        if req.startswith("host:tport"):
            self.send(c, cid, b"OKAY" + struct.pack("<Q", 1))
            return KEEP
        if req.startswith("host:transport"):
            return self.ack(c, cid)
        if req.startswith(("host-serial:", "host-transport-id:", "host-usb:", "host-local:")):
            inner = req.split(":", 2)[2] if req.count(":") >= 2 else ""
            if inner.startswith("transport"):
                return self.ack(c, cid)
            if inner.startswith("wait-for"):
                self.send(c, cid, b"OKAYOKAY")
                time.sleep(0.05)
                return CLOSE
            if inner.startswith("features"):
                return self.reply(c, cid, FEATURES.encode())
            if inner.startswith("get-state"):
                return self.reply(c, cid, b"device")
            if inner.startswith("get-serialno"):
                return self.reply(c, cid, SERIAL.encode())
            if inner.startswith("connect"):
                return self.reply(c, cid, b"connected to 127.0.0.1:5555")
            self.send(c, cid, self.fail("unsupported host-serial service " + inner))
            return CLOSE

        # ---- one-shot host services: answer then close
        if req == "host:version":
            return self.reply(c, cid, VERSION.encode())
        if req == "host:devices":
            return self.reply(c, cid, DEVICES.encode())
        if req == "host:devices-l":
            return self.reply(c, cid, DEVICES_L.encode())
        if req == "host:features":
            return self.reply(c, cid, FEATURES.encode())
        if req == "host:get-state":
            return self.reply(c, cid, b"device")
        if req == "host:get-serialno":
            return self.reply(c, cid, SERIAL.encode())
        if req == "host:get-devpath":
            return self.reply(c, cid, b"usb:1-1")
        if req.startswith("host:wait-for"):
            # AOSP implements wait-for-* as a host socket service: the smart
            # socket sends the connect OKAY (_adb_connect consumes it), the
            # service thread sends a second OKAY (adb_command's adb_status),
            # then the service socket is torn down -> ReadOrderlyShutdown.
            self.send(c, cid, b"OKAYOKAY")
            time.sleep(0.05)
            return CLOSE
        if req == "host:list-forward":
            return self.reply(c, cid, b"")
        if req.startswith("host:forward:"):
            return self.reply(c, cid, b"")
        if req.startswith("host:killforward"):
            return self.ack(c, cid)
        if req == "host:kill":
            self.send(c, cid, b"OKAY")
            return CLOSE
        if req.startswith("host:mdns:check"):
            return self.reply(c, cid, b"mdns daemon version [fake]")
        if req.startswith("host:mdns:services"):
            return self.reply(c, cid, b"")
        if req.startswith("host:mdns:"):
            return self.ack(c, cid)
        if req in ("host:track-devices", "host:track-devices-l"):
            self.send(c, cid, self.okay(DEVICES.encode()))
            return KEEP
        if req == "host:reconnect-offline":
            return self.reply(c, cid, b"reconnected")
        if req.startswith("host:reconnect"):
            return self.ack(c, cid)
        if req.startswith("host:connect:"):
            return self.reply(c, cid, b"connected to " + req.split(":", 2)[2].encode())
        if req.startswith("host:disconnect:"):
            return self.reply(c, cid, b"disconnected")
        self.send(c, cid, self.fail("unknown host service " + req))
        return CLOSE

    # ---- device services (after transport selection, same socket) ----
    def device_service(self, c, cid, req):
        self.record(cid, "device", req)
        if req.startswith(("shell,v2", "shell", "abb:", "exec:")):
            self.send(c, cid, b"OKAY")
            self.shellv2(c, cid)
            return
        if req.startswith("sync:"):
            self.send(c, cid, b"OKAY")
            self.sync(cid, c)
            return
        if req.startswith(("root:", "unroot:")):
            # device services answer a BARE OKAY; the payload is the raw
            # service stream (AOSP server relays device bytes verbatim).
            self.send(c, cid, b"OKAY" + b"restarting adbd as root\n")
            return
        self.send(c, cid, b"OKAY")

    def shellv2(self, c, cid):
        time.sleep(0.05)
        out = b"hello\n"
        self.send(c, cid, struct.pack("<BI", 1, len(out)) + out)
        self.send(c, cid, struct.pack("<BI", 3, 1) + b"\x00")
        try:
            c.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        c.settimeout(0.5)
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                self.record(cid, "shellv2-client", d)
        except (socket.timeout, OSError):
            pass

    def sync(self, cid, c):
        c.settimeout(3.0)
        try:
            while True:
                hdr = recvn(c, 8)
                if not hdr:
                    return
                self.record(cid, "sync", hdr)
                name = hdr[:4]
                length = struct.unpack("<I", hdr[4:])[0]
                # only request frames carry a path payload; DATA/DONE/OKAY/FAIL
                # reuse the second u32 for length/mtime
                path = recvn(c, length) if (length and name in (b"STAT", b"LIST", b"SEND", b"RECV")) else b""
                if path:
                    self.record(cid, "sync-path", path)
                if name == b"STAT":
                    self.send(c, cid, struct.pack("<4sIII", b"STAT", 0o100644, 12, 1700000000))
                elif name == b"LIST":
                    self.send(c, cid, struct.pack("<4sIII", b"DENT", 0o100644, 12, 1700000000) + b"file.txt")
                    self.send(c, cid, struct.pack("<4sIII", b"DENT", 0, 0, 0))
                    self.send(c, cid, b"DONE" + struct.pack("<I", 0))
                elif name == b"SEND":
                    while True:
                        h = recvn(c, 8)
                        if not h:
                            return
                        self.record(cid, "sync", h)
                        n = struct.unpack("<I", h[4:])[0]
                        if h[:4] == b"DONE":
                            break
                        payload = recvn(c, n)
                        if payload is None:
                            return
                        self.record(cid, "sync-data", payload)
                    self.send(c, cid, b"OKAY")
                    continue
                elif name == b"RECV":
                    self.send(c, cid, b"DATA" + struct.pack("<I", 4) + b"data")
                    self.send(c, cid, b"DONE" + struct.pack("<I", 0))
                elif name == b"QUIT":
                    return
                else:
                    self.send(c, cid, b"FAIL" + struct.pack("<I", 1) + b"x")
        except (socket.timeout, OSError):
            return


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf


def main():
    port = int(sys.argv[1])
    logdir = sys.argv[2]
    os.makedirs(logdir, exist_ok=True)
    srv = FakeServer(port, logdir)
    srv.start()
    with open(os.path.join(logdir, "ready"), "w") as f:
        f.write(str(port))
    while True:
        time.sleep(0.2)


if __name__ == "__main__":
    main()
