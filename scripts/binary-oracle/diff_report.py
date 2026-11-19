#!/usr/bin/env python3
"""Compare two run_matrix.py outputs (C adb oracle vs Rust adb-rs) and emit a
divergence table.

usage: diff_report.py c.json r.json [out.md]
"""
import json
import re
import sys


def wire(r):
    return [w["text"] for w in r["wire"] if w["actor"] in ("host", "device")]


def norm_text(s):
    s = re.sub(r"[0-9a-f]{8,}", "<HEX>", s)
    s = re.sub(r"/\S*run-tmp\S*", "<TMP>", s)
    return s.strip()


def norm_wire(items):
    out = []
    for t in items:
        t = re.sub(r"/\S*run-tmp\S*", "<TMP>", t)
        t = re.sub(r",\d+(?=,|$)", ",<MODE>", t)
        out.append(t)
    return out


def main():
    c = {r["case"]: r for r in json.load(open(sys.argv[1]))}
    r = {r["case"]: r for r in json.load(open(sys.argv[2]))}
    cases = [k for k in c if k in r]
    rows = []
    for case in cases:
        a, b = c[case], r[case]
        aw, bw = norm_wire(wire(a)), norm_wire(wire(b))
        diffs = []
        if a["rc"] != b["rc"]:
            diffs.append(f"rc {a['rc']} -> {b['rc']}")
        if aw != bw:
            diffs.append("wire")
        if norm_text(a["stdout"]) != norm_text(b["stdout"]):
            diffs.append("stdout")
        if norm_text(a["stderr"]) != norm_text(b["stderr"]):
            diffs.append("stderr")
        rows.append({
            "case": case,
            "diffs": diffs,
            "c_rc": a["rc"], "r_rc": b["rc"],
            "c_wire": aw, "r_wire": bw,
            "c_stdout": a["stdout"][:400], "r_stdout": b["stdout"][:400],
            "c_stderr": a["stderr"][:400], "r_stderr": b["stderr"][:400],
            "c_argv": a["argv"], "r_argv": b["argv"],
        })

    md = ["| case | diff | C adb (oracle) | adb-rs |", "|---|---|---|---|"]
    lines = []
    for row in rows:
        if not row["diffs"]:
            continue
        md.append(f"| `{row['case']}` | {', '.join(row['diffs'])} | "
                  f"{' / '.join(row['c_wire']) or '—'} | {' / '.join(row['r_wire']) or '—'} |")
        lines.append(json.dumps(row, ensure_ascii=False))
    out = "\n".join(md)
    print(out)
    if len(sys.argv) > 3:
        with open(sys.argv[3], "w") as f:
            f.write(out + "\n\n## raw divergences\n\n```jsonl\n" + "\n".join(lines) + "\n```\n")
    same = sum(1 for x in rows if not x["diffs"])
    print(f"\n# cases={len(rows)} identical={same} divergent={len(rows)-same}", file=sys.stderr)


if __name__ == "__main__":
    main()
