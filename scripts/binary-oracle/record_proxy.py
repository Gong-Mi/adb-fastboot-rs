#!/usr/bin/env python3
"""Protocol-agnostic recording proxy.

Use this *before* writing any fixture for an unknown implementation (Huawei
hadb, vendor hdc variants, a new fastbootd): it forwards raw bytes in both
directions and records every chunk with timestamps, so framing, handshake and
command vocabulary can be derived from evidence instead of guessed.

usage:
  record_proxy.py --listen 7100 --upstream 127.0.0.1:5555 --out cap.jsonl
(point the client at 127.0.0.1:7100 yourself; this proxy does not spawn it)

Notes:
  * operates on raw byte chunks; it does NOT assume any framing;
  * each record: {dir, t, len, hex, sha256};
  * safe to run against a *fixture* too, to validate that the fixture really
    reproduces the captured transcript.
"""
import argparse
import hashlib
import json
import socket
import sys
import threading
import time

LOG_LOCK = threading.Lock()


def log(f, direction, data):
    rec = {"dir": direction, "t": round(time.time(), 6), "len": len(data),
           "hex": data.hex(), "sha256": hashlib.sha256(data).hexdigest()}
    with LOG_LOCK:
        f.write(json.dumps(rec) + "\n")


def pump(src, dst, f, direction, tag):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            log(f, direction, data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        print(f"[{tag}] {direction} closed", file=sys.stderr, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--upstream", required=True, help="host:port of the real daemon/device")
    ap.add_argument("--out", default="capture.jsonl")
    args = ap.parse_args()

    host, port = args.upstream.rsplit(":", 1)
    port = int(port)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.listen))
    srv.listen(8)
    print(f"listening on 127.0.0.1:{args.listen} -> {args.upstream}; log={args.out}",
          file=sys.stderr, flush=True)

    f = open(args.out, "a", buffering=1)
    n = 0
    while True:
        c, _ = srv.accept()
        n += 1
        u = socket.create_connection((host, port))
        threading.Thread(target=pump, args=(c, u, f, "c2s", f"conn{n}"), daemon=True).start()
        threading.Thread(target=pump, args=(u, c, f, "s2c", f"conn{n}"), daemon=True).start()


if __name__ == "__main__":
    main()
