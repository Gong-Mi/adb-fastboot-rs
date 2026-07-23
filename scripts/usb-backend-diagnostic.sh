#!/data/data/com.termux/files/usr/bin/bash
# Read-only USB backend evidence ladder for Termux/Android.
# This script never opens, resets, claims, detaches, or writes USB devices.
set +e

say() { printf '\n=== %s ===\n' "$*"; }
run() {
  printf '+ %s\n' "$*"
  "$@" 2>&1
  printf '[exit=%s]\n' "$?"
}

say 'scope'
printf '%s\n' 'READ-ONLY: no USB open/reset/claim/detach, no flashing, no persistent permission changes.'
printf 'time: '; date 2>/dev/null || true

say '1. ordinary UID / SELinux context'
run id
run id -a
printf 'SELinux: '; cat /proc/self/attr/current 2>/dev/null || true
printf 'groups: '; id -Gn 2>/dev/null || true

say '2. command availability'
for c in sudo su pkg-config lsusb usb-devices termux-usb termux-usb-list termux-api dumpsys cmd; do
  if command -v "$c" >/dev/null 2>&1; then printf '%-18s %s\n' "$c" "$(command -v "$c")"; else printf '%-18s ABSENT\n' "$c"; fi
done

say '3. sudo layer (does not imply root)'
if command -v sudo >/dev/null 2>&1; then
  run sudo -n id
  run sudo -n sh -c 'id; printf "usb-dir="; test -d /dev/bus/usb && printf present || printf absent; printf "\\n"'
else
  printf 'sudo: absent\n'
fi

say '4. su root layer'
if command -v su >/dev/null 2>&1; then
  run su -c id
  run su -c 'id; printf "context="; cat /proc/self/attr/current 2>/dev/null; printf "\\n"'
else
  printf 'su: absent\n'
fi

say '5. pkg-config / libusb'
if command -v pkg-config >/dev/null 2>&1; then
  run pkg-config --modversion libusb-1.0
  run pkg-config --cflags --libs libusb-1.0
  run pkg-config --variable pc_path pkg-config
else
  printf 'pkg-config: absent\n'
fi

say '6. usbfs device nodes (ordinary UID)'
for p in /dev/bus/usb /sys/bus/usb/devices /sys/class/android_usb; do
  if [ -e "$p" ]; then
    printf '%s: present\n' "$p"
    find "$p" -maxdepth 2 -mindepth 1 -print 2>/dev/null
  else
    printf '%s: ABSENT\n' "$p"
  fi
done
for f in /dev/bus/usb/*/*; do
  [ -e "$f" ] || continue
  stat -c '%n mode=%A uid=%u gid=%g type=%F' "$f" 2>&1
 done

say '7. usbfs device nodes (su root)'
if command -v su >/dev/null 2>&1; then
  su -c 'for p in /dev/bus/usb /sys/bus/usb/devices; do if [ -e "$p" ]; then printf "%s: present\\n" "$p"; find "$p" -maxdepth 2 -mindepth 1 -print 2>/dev/null; else printf "%s: ABSENT\\n" "$p"; fi; done; for f in /dev/bus/usb/*/*; do [ -e "$f" ] || continue; stat -c "%n mode=%A uid=%u gid=%g type=%F" "$f" 2>&1; done' 2>&1
else
  printf 'su: absent\n'
fi

say '8. USB enumeration tools (read-only)'
if command -v lsusb >/dev/null 2>&1; then
  run lsusb
else
  printf 'lsusb: absent\n'
fi
if command -v usb-devices >/dev/null 2>&1; then
  run usb-devices
else
  printf 'usb-devices: absent\n'
fi

say '9. sysfs USB enumeration (read-only)'
found=0
for d in /sys/bus/usb/devices/*; do
  [ -e "$d" ] || continue
  found=1
  printf '%s: ' "$d"
  for x in idVendor idProduct manufacturer product busnum devnum; do
    if [ -r "$d/$x" ]; then printf '%s=%s ' "$x" "$(tr -d '\n' < "$d/$x" 2>/dev/null)"; fi
  done
  printf '\n'
done
[ "$found" -eq 0 ] && printf 'no USB device/interface entries visible to this shell\n'

say '10. Android UsbManager service / termux-usb bridge'
if command -v termux-usb >/dev/null 2>&1; then
  run termux-usb -l
  printf '%s\n' 'termux-usb is present: its list is the Android UsbManager-mediated device view; opening a device would require explicit user action and is intentionally not done.'
else
  printf '%s\n' 'termux-usb: ABSENT (no Termux UsbManager bridge executable found).'
fi
if [ -x /system/bin/dumpsys ]; then
  printf '+ /system/bin/dumpsys usb (ordinary UID, first 20 lines)\n'
  /system/bin/dumpsys usb 2>&1 | sed -n '1,20p'
  printf '[exit=%s]\n' "${PIPESTATUS[0]}"
  if command -v su >/dev/null 2>&1; then
    printf '+ su -c /system/bin/dumpsys usb (root, selected state)\n'
    su -c '/system/bin/dumpsys usb' 2>&1 | grep -E 'connected=|host_connected=|source_power=|sink_power=|num_connects=|current_mode=|data_role=|power_role=' || true
  fi
else
  printf '/system/bin/dumpsys: absent\n'
fi

say '10. interpretation'
printf '%s\n' \
  'UID层：证明当前进程身份、组和SELinux域；不能证明能访问USB。' \
  'sudo层：只有 sudo -n id 成功且uid=0才证明sudo可用；sudo存在或报错不能证明权限。' \
  'su层：su -c id uid=0证明本次子进程获得root；不证明Termux原进程、libusb或Android API自动获得权限。' \
  'libusb层：pkg-config只证明开发元数据/链接参数存在；不证明运行时能枚举、打开或传输。' \
  'usbfs层：/dev/bus/usb节点和可读权限证明Linux usbfs入口可见；无节点可能是未连接/未进入host模式/命名空间或策略隐藏。' \
  'sysfs层：/sys/bus/usb/devices条目证明内核枚举；不等于用户态可打开节点。' \
  'UsbManager层：dumpsys是系统服务状态探针；普通UID被DUMP拒绝不等于UsbManager API不可用。termux-usb -l才是Termux桥接可用性的直接证据。' \
  '最终USB backend可用性必须另行证明：实际设备出现、权限授予/FD交接成功、描述符读取和无破坏性bulk读写；本脚本刻意不做后两项。'
