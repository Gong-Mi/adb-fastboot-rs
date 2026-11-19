#!/usr/bin/env python3
"""Pluggable wire codecs + byte-exact transcript recorder.

Rationale (why this is not optional):
The differential oracle must outlive AOSP. Huawei `hadb` and other vendor ADB
variants reuse the same *idea* (length-framed service strings) but not
necessarily the same framing, service vocabulary, auth or capability set.
Hard-coding one framing into a fixture would silently cap every later reverse
effort at "AOSP-shaped protocols only".

So every device fixture talks through a Codec, and every run keeps a raw
two-direction transcript. A new protocol only needs:
  1. a Codec subclass (framing/handshake),
  2. a behaviour table (service/command vocabulary),
  3. the same runner + diff, which then works unchanged.

Codecs implemented here:
  * AdbSmartSocket  - 4 ASCII hex chars length prefix + command string (AOSP
                      `sockets.cpp` smart socket), raw bytes afterwards.
  * FastbootTcp     - 4-byte "FB01" handshake, then 8-byte big-endian length
                      prefix per message (AOSP `fastboot/tcp.cpp`).
The codecs are deliberately stateless about *meaning*: they only delimit
messages and record bytes, so unknown vendor commands still land in the
transcript instead of breaking the fixture.
"""
import hashlib
import json


class Transcript:
    """Byte-exact record of one fixture session (both directions)."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "a", buffering=1)

    def note(self, **kw):
        self.f.write(json.dumps(kw) + "\n")

    def rx(self, who, payload, note=None):
        self.note(actor=f"{who}-rx", len=len(payload), hex=payload.hex(),
                  sha256=hashlib.sha256(payload).hexdigest(), note=note)

    def tx(self, who, payload, note=None):
        self.note(actor=f"{who}-tx", len=len(payload), hex=payload.hex(),
                  sha256=hashlib.sha256(payload).hexdigest(), note=note)


class Codec:
    name = "abstract"
    handshake_rx = None   # bytes the peer must send first, if any
    handshake_tx = None   # bytes the fixture must answer with

    def __init__(self, conn, transcript):
        self.c = conn
        self.t = transcript

    # ---- primitive IO ----
    def recv_exact(self, n, timeout=None):
        if timeout is not None:
            self.c.settimeout(timeout)
        buf = b""
        while len(buf) < n:
            d = self.c.recv(n - len(buf))
            if not d:
                return None
            buf += d
        return buf

    def send(self, payload):
        if isinstance(payload, str):
            payload = payload.encode()
        self.t.tx(self.name, payload)
        self.c.sendall(payload)

    # Which side talks first is part of the protocol, not a detail: AOSP
    # fastboot has the *client* send "FB01" and the device answer "FB0x".
    # Getting this backwards yields a deadlock that looks like a broken
    # fixture, so the role is explicit per direction.
    client_speaks_first = False

    def handshake(self):
        if self.handshake_rx is None:
            return True
        if self.client_speaks_first:
            self.send(self.handshake_tx)
            got = self.recv_exact(len(self.handshake_rx))
            self.t.rx(self.name, got or b"", note="handshake")
            # AOSP tcp.cpp only requires the answer to start with "FB";
            # keep the version byte visible instead of normalising it away.
            ok = got is not None and got[:2] == b"FB" and len(got) == len(self.handshake_rx)
        else:
            got = self.recv_exact(len(self.handshake_rx))
            self.t.rx(self.name, got or b"", note="handshake")
            ok = got == self.handshake_rx
        if not ok:
            self.t.note(actor="protocol-error", reason="handshake mismatch",
                        want=self.handshake_rx.decode("latin1"),
                        got=(got or b"").decode("latin1"))
            return False
        if not self.client_speaks_first:
            self.send(self.handshake_tx)
        return True

    # ---- message IO ----
    def read_msg(self):
        raise NotImplementedError

    def write_msg(self, payload):
        raise NotImplementedError


class AdbSmartSocket(Codec):
    """AOSP smart socket: `%04x` ASCII length + payload, no handshake."""

    name = "adb"
    MAX_CMD_LEN = 4096

    def read_msg(self):
        hdr = self.recv_exact(4)
        if hdr is None:
            return None
        try:
            n = int(hdr.decode("ascii"), 16)
        except ValueError:
            self.t.rx(self.name, hdr, note="bad length prefix")
            return None
        if n > 1024 * 1024:
            self.t.note(actor="protocol-error", reason="oversized command", len=n)
            return None
        payload = self.recv_exact(n) if n else b""
        if payload is None:
            return None
        self.t.rx(self.name, payload)
        return payload

    def write_msg(self, payload):
        if isinstance(payload, str):
            payload = payload.encode()
        self.send(("%04x" % len(payload)).encode() + payload)

    def write_raw(self, payload):
        """Device-service / sync responses carry no length prefix."""
        self.send(payload)


class FastbootTcp(Codec):
    """AOSP fastboot over TCP: "FB01" handshake, 8-byte BE length framing."""

    name = "fastboot"
    handshake_rx = b"FB01"
    handshake_tx = b"FB01"
    client_speaks_first = True

    def read_msg(self):
        hdr = self.recv_exact(8)
        if hdr is None:
            return None
        n = int.from_bytes(hdr, "big")
        if n > 256 * 1024 * 1024:
            self.t.note(actor="protocol-error", reason="huge frame", len=n)
            return None
        payload = self.recv_exact(n) if n else b""
        if payload is None:
            return None
        self.t.rx(self.name, payload)
        return payload

    def write_msg(self, payload):
        if isinstance(payload, str):
            payload = payload.encode()
        self.send(len(payload).to_bytes(8, "big") + payload)


def _selftest():
    """Byte-exactness check for each codec over a socketpair (no network).

    Run: python3 scripts/binary-oracle/framing.py
    """
    import os
    import socket
    import tempfile

    cases = (
        # codec, messages, expected sender bytes (length prefix included),
        # expected receiver bytes (framing consumed by the codec, so payload only)
        (AdbSmartSocket, [b"host:version", b"shell:id"],
         # "%04x" ASCII prefix, not binary: '0','0','0','c' == 30303063
         ["30303063" + "686f73743a76657273696f6e",
          "30303038" + "7368656c6c3a6964"],
         ["686f73743a76657273696f6e", "7368656c6c3a6964"]),
        (FastbootTcp, [b"getvar:version", b"OKAY0.4"],
         ["000000000000000e6765747661723a76657273696f6e",
          "00000000000000074f4b4159302e34"],
         ["6765747661723a76657273696f6e", "4f4b4159302e34"]),
    )
    for codec_cls, messages, want_tx, want_rx in cases:
        a, b = socket.socketpair()
        with tempfile.NamedTemporaryFile("r", suffix=".jsonl", delete=False) as tf:
            tx_path = tf.name
        with tempfile.NamedTemporaryFile("r", suffix=".jsonl", delete=False) as tf:
            rx_path = tf.name
        try:
            tx = codec_cls(a, Transcript(tx_path))
            rx = codec_cls(b, Transcript(rx_path))
            if codec_cls.handshake_rx:
                # single thread: speak the client half raw, then let the
                # device half answer, otherwise both sides would block.
                a.sendall(codec_cls.handshake_rx)
                assert rx.handshake(), "device handshake failed"
                # the answer travels back towards the client socket (a)
                assert a.recv(len(codec_cls.handshake_tx)) == codec_cls.handshake_tx
            for m in messages:
                tx.write_msg(m)
            assert [rx.read_msg() for _ in messages] == messages
            sent = [r["hex"] for r in map(json.loads, open(tx_path))
                    if r["actor"].endswith("-tx")]
            recv = [r["hex"] for r in map(json.loads, open(rx_path))
                    if r["actor"].endswith("-rx") and r.get("note") != "handshake"]
            if codec_cls.handshake_rx:
                hs = [r["hex"] for r in map(json.loads, open(rx_path))
                      if r.get("note") == "handshake"]
                assert hs == [codec_cls.handshake_rx.hex()], (codec_cls.name, hs)
            assert sent == want_tx, (codec_cls.name, "tx", sent, want_tx)
            assert recv == want_rx, (codec_cls.name, "rx", recv, want_rx)
            print(f"{codec_cls.name}: {len(messages)} msgs round-tripped, "
                  f"framing bytes match on the wire")
        finally:
            a.close()
            b.close()
            os.unlink(tx_path)
            os.unlink(rx_path)
    print("framing selftest OK")


if __name__ == "__main__":
    _selftest()
