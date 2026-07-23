#!/system/bin/sh
# Build a reproducible, systemless Magisk module from Android arm64 release ELF files.
# Usage:
#   scripts/magisk-package.sh [WORKSPACE] [OUTPUT_ZIP]
#   scripts/magisk-package.sh --check OUTPUT_ZIP

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MODULE_ID=adb-fastboot-rs
TMP_BASE=${TMPDIR:-}
if [ -z "$TMP_BASE" ] || [ ! -d "$TMP_BASE" ] || [ ! -w "$TMP_BASE" ]; then
    TMP_BASE=${PREFIX:-$REPO_DIR/.tmp}
fi
mkdir -p "$TMP_BASE"
export TMPDIR="$TMP_BASE"

usage() {
    printf '%s\n' \
        "Usage: $0 [WORKSPACE] [OUTPUT_ZIP]" \
        "       $0 --check OUTPUT_ZIP" \
        "Defaults: WORKSPACE=$REPO_DIR, OUTPUT_ZIP=$REPO_DIR/dist/$MODULE_ID-magisk.zip" >&2
    exit 2
}

check_zip() {
    [ "$#" -eq 1 ] || usage
    ZIP=$1 python3 - <<'PY'
import os
import stat
import subprocess
import sys
import tempfile
import zipfile

zip_path = os.environ["ZIP"]
required = {
    "module.prop": 0o644,
    "system/bin/adb": 0o755,
    "system/bin/fastboot": 0o755,
    "common/adb-rs": 0o755,
    "common/fastboot-rs": 0o755,
}
with zipfile.ZipFile(zip_path) as zf:
    names = zf.namelist()
    actual = set(names)
    missing = set(required) - actual
    extras = actual - set(required)
    if missing:
        raise SystemExit("ZIP content check failed: missing " + ", ".join(sorted(missing)))
    if extras:
        raise SystemExit("ZIP content check failed: unexpected entries " + ", ".join(sorted(extras)))
    if len(names) != len(actual):
        raise SystemExit("ZIP content check failed: duplicate entries")
    for name, mode in required.items():
        info = zf.getinfo(name)
        if info.is_dir():
            raise SystemExit(f"ZIP content check failed: {name} is a directory")
        stored_mode = (info.external_attr >> 16) & 0o777
        if stored_mode != mode:
            raise SystemExit(f"ZIP content check failed: {name} mode {stored_mode:o}, expected {mode:o}")
        if not zf.read(name):
            raise SystemExit(f"ZIP content check failed: {name} is empty")
    prop = zf.read("module.prop").decode("utf-8")
    for line in ("id=adb-fastboot-rs", "name=adb-fastboot-rs", "version=0.1.0", "versionCode=1"):
        if line not in prop.splitlines():
            raise SystemExit(f"ZIP content check failed: module.prop lacks {line!r}")
    expected_home = {
        "system/bin/adb": b"HOME=/sdcard",
        "system/bin/fastboot": b"HOME=/data/adb/adb-fastboot-rs/fastboot-home",
    }
    for name in ("system/bin/adb", "system/bin/fastboot"):
        wrapper = zf.read(name)
        if expected_home[name] not in wrapper or b"TMPDIR=/data/local/tmp" not in wrapper:
            raise SystemExit(f"ZIP content check failed: {name} lacks Android HOME/TMPDIR settings")
        if b"MODDIR=/data/adb/modules/adb-fastboot-rs" not in wrapper:
            raise SystemExit(f"ZIP content check failed: {name} lacks absolute MODDIR")
    with tempfile.TemporaryDirectory() as td:
        for name in ("system/bin/adb", "system/bin/fastboot"):
            path = os.path.join(td, name.replace("/", "_"))
            with open(path, "wb") as fh:
                fh.write(zf.read(name))
            os.chmod(path, 0o755)
            result = subprocess.run(["sh", "-n", path], text=True, capture_output=True)
            if result.returncode:
                raise SystemExit(f"wrapper shell syntax check failed: {name}\n{result.stderr}")
print(f"ZIP content check passed: {zip_path}")
PY
}

if [ "${1:-}" = "--check" ]; then
    shift
    check_zip "${1:-}"
    exit 0
fi

WORKSPACE=${1:-$REPO_DIR}
OUTPUT=${2:-$REPO_DIR/dist/$MODULE_ID-magisk.zip}
ADB="$WORKSPACE/target/release/adb-rs"
FASTBOOT="$WORKSPACE/target/release/fastboot-rs"
READELF=${READELF:-llvm-readelf}

[ -d "$WORKSPACE" ] || { printf 'error: workspace does not exist: %s\n' "$WORKSPACE" >&2; exit 1; }
for binary in "$ADB" "$FASTBOOT"; do
    [ -f "$binary" ] || { printf 'error: missing release binary: %s\nBuild target/release first.\n' "$binary" >&2; exit 1; }
    [ -x "$binary" ] || { printf 'error: release binary is not executable: %s\n' "$binary" >&2; exit 1; }
    command -v "$READELF" >/dev/null 2>&1 || { printf 'error: %s is required to verify ELF architecture\n' "$READELF" >&2; exit 1; }
    header=$($READELF -h "$binary") || { printf 'error: cannot read ELF header: %s\n' "$binary" >&2; exit 1; }
    printf '%s\n' "$header" | grep -q 'Class:[[:space:]]*ELF64' || { printf 'error: wrong architecture (not ELF64): %s\n' "$binary" >&2; exit 1; }
    printf '%s\n' "$header" | grep -q 'Machine:[[:space:]]*AArch64' || { printf 'error: wrong architecture (expected AArch64 arm64): %s\n' "$binary" >&2; exit 1; }
done

TMPROOT=$(mktemp -d "$TMP_BASE/$MODULE_ID.XXXXXX")
trap 'rm -rf "$TMPROOT"' EXIT
mkdir -p "$TMPROOT/system/bin" "$TMPROOT/common"

cat > "$TMPROOT/module.prop" <<'EOF'
id=adb-fastboot-rs
name=adb-fastboot-rs
version=0.1.0
versionCode=1
author=local
description=Pure Rust adb and fastboot arm64 Android tools (systemless, no native .so deps)
EOF

make_wrapper() {
    name=$1
    elf=$2
    if [ "$name" = adb ]; then
        tool_home=/sdcard
    else
        tool_home=/data/adb/adb-fastboot-rs/fastboot-home
    fi
    cat > "$TMPROOT/system/bin/$name" <<EOF
#!/system/bin/sh
# Systemless Magisk wrapper; do not modify or delete the real system binary.
MODDIR=/data/adb/modules/$MODULE_ID
export HOME=$tool_home
export TMPDIR=/data/local/tmp
mkdir -p "\$HOME" 2>/dev/null || true
exec "\$MODDIR/common/$elf" "\$@"
EOF
    chmod 755 "$TMPROOT/system/bin/$name"
    sh -n "$TMPROOT/system/bin/$name"
}

cp "$ADB" "$TMPROOT/common/adb-rs"
cp "$FASTBOOT" "$TMPROOT/common/fastboot-rs"
chmod 755 "$TMPROOT/common/adb-rs" "$TMPROOT/common/fastboot-rs"
make_wrapper adb adb-rs
make_wrapper fastboot fastboot-rs

mkdir -p "$(dirname -- "$OUTPUT")"
python3 - "$TMPROOT" "$OUTPUT" <<'PY'
import os
import sys
import zipfile
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
files = sorted(p for p in root.rglob("*") if p.is_file())
epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
import time
stamp = time.gmtime(max(epoch, 315532800))[:6]
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for path in files:
        name = path.relative_to(root).as_posix()
        data = path.read_bytes()
        info = zipfile.ZipInfo(name, date_time=stamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = 0o755 if name.startswith("system/bin/") or name.startswith("common/") else 0o644
        info.external_attr = (0o100000 | mode) << 16
        info.create_system = 3
        zf.writestr(info, data)
PY

"$0" --check "$OUTPUT"
printf 'Created reproducible Magisk module: %s\n' "$OUTPUT"
