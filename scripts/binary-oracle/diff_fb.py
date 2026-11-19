#!/usr/bin/env python3
"""Compare two run_fb_matrix.py outputs (C fastboot oracle vs Rust fastboot-rs).

Differences are classified so a fixture artefact is never reported as a product
defect:
  wire    - device command sequence differs
  side    - what actually landed on the (fake) partitions differs
  result  - rc / stdout / stderr differ
usage: diff_fb.py c.json r.json [out.md]
"""
import json
import re
import sys


def cmds(r):
    return r["device_cmds"]


def trimmed(r):
    out = []
    for c in cmds(r):
        out.append(re.sub(r"0x[0-9a-fA-F]+", "0x<HEX>", c))
    return out


def side(r):
    kinds = []
    for e in r["device_events"]:
        if e.get("actor") in ("flash", "erase", "fetch", "set_active", "download"):
            k = {kk: vv for kk, vv in e.items() if kk in ("actor", "partition", "resolved", "sha256", "bytes", "requested", "advertised", "got", "spec")}
            kinds.append(k)
    return kinds


def parts(r):
    return {k: v.get("sha256", "")[:16] for k, v in sorted(r.get("partitions", {}).items())}


def main():
    c = {r["case"]: r for r in json.load(open(sys.argv[1]))}
    r = {r["case"]: r for r in json.load(open(sys.argv[2]))}
    rows = []
    for case in c:
        if case not in r:
            continue
        a, b = c[case], r[case]
        d = []
        if trimmed(a) != trimmed(b):
            d.append("wire")
        if side(a) != side(b):
            d.append("side")
        if parts(a) != parts(b):
            d.append("state")
        if a["rc"] != b["rc"]:
            d.append("rc")
        if a["stdout"].strip() != b["stdout"].strip():
            d.append("stdout")
        if a["stderr"].strip() != b["stderr"].strip():
            d.append("stderr")
        rows.append((case, d, a, b))

    out = ["| case | diff | C fastboot | fastboot-rs |", "|---|---|---|---|"]
    for case, d, a, b in rows:
        if not d:
            continue
        out.append(f"| `{case}` | {', '.join(d)} | {' / '.join(trimmed(a)) or '—'} | {' / '.join(trimmed(b)) or '—'} |")
    print("\n".join(out))
    same = sum(1 for _, d, _, _ in rows if not d)
    print(f"\n# cases={len(rows)} identical={same} divergent={len(rows)-same}", file=sys.stderr)
    if len(sys.argv) > 3:
        with open(sys.argv[3], "w") as f:
            f.write("\n".join(out) + "\n")
            f.write("\n## detail\n\n")
            for case, d, a, b in rows:
                if not d:
                    continue
                f.write(f"### {case} [{', '.join(d)}]\n")
                f.write(f"- C  rc={a['rc']} out={a['stdout'][:300]!r} err={a['stderr'][:300]!r}\n")
                f.write(f"- R  rc={b['rc']} out={b['stdout'][:300]!r} err={b['stderr'][:300]!r}\n")
                f.write(f"- C cmds={trimmed(a)}\n- R cmds={trimmed(b)}\n")
                f.write(f"- C side={side(a)}\n- R side={side(b)}\n")
                f.write(f"- C parts={parts(a)}\n- R parts={parts(b)}\n\n")


if __name__ == "__main__":
    main()
