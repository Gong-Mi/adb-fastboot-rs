//! Offline tests for the injectable USB hotplug scan (`client/usb_scan.rs`).
//!
//! Every test builds a throwaway `/dev/bus/usb` + `/sys/bus/usb/devices` tree
//! under the process temp directory; no real USB device, no thread, and no
//! system path is touched.  The module is included by path because
//! `adb-fastboot-cli` is a bin-only package (no lib target to link against),
//! and the slice is deliberately dependency-free so it can be compiled into
//! this test crate unchanged.
//!
//! The behaviours asserted here are the AOSP `client/usb_linux.cpp` scan
//! semantics: `scan_usb_devices()` walks only all-digit entries (:622-651,
//! `contains_non_digit` :115-120), `process_usb_device()` skips known nodes and
//! matches the ADB triple with exactly two endpoints (:158-161, :221-223),
//! `register_device()` reads `serial` from sysfs and tolerates it being absent
//! (:546-557), and `device_poll_thread()`'s add/remove handling (:700-716)
//! becomes a diff over successive scans.

#[path = "../src/client/usb_scan.rs"]
mod usb_scan;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use usb_scan::{
    classify_interface, scan_usb_devices, HotplugEvent, HotplugTracker, ProcessOutcome, ScanRoots,
    SkipReason, UsbInterfaceKind, ADB_CLASS, ADB_DBC_CLASS, ADB_DBC_SUBCLASS, ADB_PROTOCOL,
    ADB_SUBCLASS, FASTBOOT_CLASS, FASTBOOT_PROTOCOL, FASTBOOT_SUBCLASS,
};

static TREE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Fake sysfs / usbfs tree
// ---------------------------------------------------------------------------

struct FakeUsb {
    root: PathBuf,
}

impl FakeUsb {
    fn new() -> Self {
        let n = TREE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "adb-usb-hotplug-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("dev/bus/usb")).unwrap();
        fs::create_dir_all(root.join("sys/bus/usb/devices")).unwrap();
        Self { root }
    }

    fn roots(&self) -> ScanRoots {
        ScanRoots::new(
            self.root.join("dev/bus/usb"),
            self.root.join("sys/bus/usb/devices"),
        )
    }

    fn node(&self, bus: &str, addr: &str) -> PathBuf {
        let bus_dir = self.root.join("dev/bus/usb").join(bus);
        fs::create_dir_all(&bus_dir).unwrap();
        let node = bus_dir.join(addr);
        fs::write(&node, b"").unwrap();
        node
    }

    fn remove_node(&self, bus: &str, addr: &str) {
        fs::remove_file(self.root.join("dev/bus/usb").join(bus).join(addr)).unwrap();
    }

    fn sysfs_dir(&self, name: &str) -> PathBuf {
        let dir = self.root.join("sys/bus/usb/devices").join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}

impl Drop for FakeUsb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn attr(dir: &Path, name: &str, value: &str) {
    fs::write(dir.join(name), value.as_bytes()).unwrap();
}

/// Replace an attribute file with a directory so reads fail with `EISDIR`
/// regardless of the uid the tests run as.
fn break_attr(dir: &Path, name: &str) {
    let path = dir.join(name);
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
}

#[derive(Clone, Copy)]
struct Iface {
    dir: &'static str,
    class: u8,
    subclass: u8,
    protocol: u8,
    endpoints: u8,
}

impl Iface {
    fn adb(dir: &'static str) -> Self {
        Self {
            dir,
            class: ADB_CLASS,
            subclass: ADB_SUBCLASS,
            protocol: ADB_PROTOCOL,
            endpoints: 2,
        }
    }

    fn fastboot(dir: &'static str) -> Self {
        Self {
            dir,
            class: FASTBOOT_CLASS,
            subclass: FASTBOOT_SUBCLASS,
            protocol: FASTBOOT_PROTOCOL,
            endpoints: 2,
        }
    }

    fn plain(dir: &'static str, class: u8, subclass: u8, protocol: u8, endpoints: u8) -> Self {
        Self {
            dir,
            class,
            subclass,
            protocol,
            endpoints,
        }
    }
}

struct Dev {
    bus: &'static str,
    addr: &'static str,
    sysfs: &'static str,
    vendor: u16,
    product: u16,
    serial: Option<&'static str>,
    ifaces: Vec<Iface>,
}

fn adb_device() -> Dev {
    Dev {
        bus: "001",
        addr: "002",
        sysfs: "1-2",
        vendor: 0x18d1,
        product: 0x4ee7,
        serial: Some("ABC123\n"),
        ifaces: vec![Iface::adb("1-2:1.0")],
    }
}

/// Materialise a device: usbfs placeholder node, sysfs device attributes and
/// one directory per interface.
fn install(tree: &FakeUsb, dev: &Dev) -> PathBuf {
    tree.node(dev.bus, dev.addr);
    let sys = tree.sysfs_dir(dev.sysfs);
    attr(&sys, "busnum", &dev.bus.parse::<u8>().unwrap().to_string());
    attr(&sys, "devnum", &dev.addr.parse::<u8>().unwrap().to_string());
    attr(&sys, "idVendor", &format!("{:04x}", dev.vendor));
    attr(&sys, "idProduct", &format!("{:04x}", dev.product));
    if let Some(serial) = dev.serial {
        attr(&sys, "serial", serial);
    }
    for iface in &dev.ifaces {
        let dir = sys.join(iface.dir);
        fs::create_dir_all(&dir).unwrap();
        attr(&dir, "bInterfaceClass", &format!("{:02x}", iface.class));
        attr(&dir, "bInterfaceSubClass", &format!("{:02x}", iface.subclass));
        attr(&dir, "bInterfaceProtocol", &format!("{:02x}", iface.protocol));
        attr(&dir, "bNumEndpoints", &format!("{:02x}", iface.endpoints));
        attr(
            &dir,
            "bInterfaceNumber",
            &format!("{:02x}", interface_number(iface.dir)),
        );
    }
    sys
}

fn interface_number(dir: &str) -> u8 {
    dir.rsplit('.')
        .next()
        .and_then(|n| n.parse::<u8>().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Triples
// ---------------------------------------------------------------------------

#[test]
fn interface_triples_match_aosp_is_adb_interface() {
    assert_eq!(
        classify_interface(0xff, 0x42, 0x01),
        Some(UsbInterfaceKind::Adb)
    );
    // DbC fallback: client/transport_usb.cpp:170-179.
    assert_eq!(
        classify_interface(ADB_DBC_CLASS, ADB_DBC_SUBCLASS, ADB_PROTOCOL),
        Some(UsbInterfaceKind::Adb)
    );
    assert_eq!(
        classify_interface(0xff, 0x42, 0x03),
        Some(UsbInterfaceKind::Fastboot)
    );
    // Right class/subclass with the wrong protocol is neither.
    assert_eq!(classify_interface(0xff, 0x42, 0x02), None);
    // Wrong subclass with protocol 1 is neither.
    assert_eq!(classify_interface(0xff, 0x43, 0x01), None);
    // Mass storage.
    assert_eq!(classify_interface(0x08, 0x06, 0x50), None);
}

// ---------------------------------------------------------------------------
// scan_usb_devices
// ---------------------------------------------------------------------------

#[test]
fn first_scan_finds_adb_device_from_fake_tree() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());

    let report = scan_usb_devices(&tree.roots());

    assert!(report.complete, "root_error: {:?}", report.root_error);
    assert_eq!(report.devices.len(), 1, "skipped: {:?}", report.skipped);
    let dev = &report.devices[0];
    assert!(dev.dev_name.ends_with("/001/002"), "{}", dev.dev_name);
    assert_eq!(dev.sysfs_name, "1-2");
    // register_device() builds /sys/bus/usb/devices/<dev_path + 4>/serial
    // (usb_linux.cpp:546-548); the "usb:" prefix is part of the contract.
    assert_eq!(dev.dev_path, "usb:1-2");
    assert_eq!(dev.bus_number, 1);
    assert_eq!(dev.address, 2);
    assert_eq!(dev.vendor_id, Some(0x18d1));
    assert_eq!(dev.product_id, Some(0x4ee7));
    assert_eq!(dev.serial.as_deref(), Some("ABC123"));
    assert_eq!(dev.kind, UsbInterfaceKind::Adb);
    let iface = dev.adb_interface().expect("adb interface");
    assert_eq!((iface.class, iface.subclass, iface.protocol), (0xff, 0x42, 0x01));
    assert_eq!(iface.num_endpoints, 2);
    assert_eq!(iface.number, 0);
}

#[test]
fn non_digit_entries_and_non_adb_devices_are_filtered() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());

    // Stray entries the walk must ignore: usb_linux.cpp:634-647 only accepts
    // all-digit bus and device names.
    fs::create_dir_all(tree.root.join("dev/bus/usb/not-a-bus")).unwrap();
    fs::write(tree.root.join("dev/bus/usb/README"), b"").unwrap();
    fs::write(tree.root.join("dev/bus/usb/001/not-an-addr"), b"").unwrap();

    // A mass-storage device on another bus/address.
    let mut msd = adb_device();
    msd.addr = "003";
    msd.sysfs = "1-3";
    msd.ifaces = vec![Iface::plain("1-3:1.0", 0x08, 0x06, 0x50, 2)];
    install(&tree, &msd);

    let report = scan_usb_devices(&tree.roots());

    assert_eq!(report.devices.len(), 1);
    assert!(report.devices[0].dev_name.ends_with("/001/002"));
    assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
    assert!(report.skipped[0].dev_name.ends_with("/001/003"));
    assert_eq!(report.skipped[0].reason, SkipReason::NoMatchingInterface);
    assert_eq!(report.present_dev_nodes.len(), 2);
    assert!(report.complete);
}

#[test]
fn fastboot_interface_is_recognised() {
    let tree = FakeUsb::new();
    let mut dev = adb_device();
    dev.serial = None;
    dev.ifaces = vec![Iface::fastboot("1-2:1.0")];
    install(&tree, &dev);

    let report = scan_usb_devices(&tree.roots());

    assert_eq!(report.devices.len(), 1, "skipped: {:?}", report.skipped);
    assert_eq!(report.devices[0].kind, UsbInterfaceKind::Fastboot);
    assert!(report.devices[0].adb_interface().is_none());
    assert!(report.devices[0].fastboot_interface().is_some());
    // No serial attribute at all is not an error (usb_linux.cpp:551-556).
    assert_eq!(report.devices[0].serial, None);
}

#[test]
fn dbc_interface_is_treated_as_adb() {
    let tree = FakeUsb::new();
    let mut dev = adb_device();
    dev.ifaces = vec![Iface::plain(
        "1-2:1.0",
        ADB_DBC_CLASS,
        ADB_DBC_SUBCLASS,
        ADB_PROTOCOL,
        2,
    )];
    install(&tree, &dev);

    let report = scan_usb_devices(&tree.roots());

    assert_eq!(report.devices.len(), 1, "skipped: {:?}", report.skipped);
    assert_eq!(report.devices[0].kind, UsbInterfaceKind::Adb);
}

#[test]
fn adb_interface_without_two_endpoints_is_rejected() {
    let tree = FakeUsb::new();
    let mut dev = adb_device();
    dev.ifaces = vec![Iface::plain("1-2:1.0", 0xff, 0x42, 0x01, 1)];
    install(&tree, &dev);

    let report = scan_usb_devices(&tree.roots());

    assert!(report.devices.is_empty());
    assert_eq!(report.skipped.len(), 1);
    match &report.skipped[0].reason {
        SkipReason::AdbInterfaceWithoutTwoEndpoints { interface } => {
            assert_eq!(interface, "1-2:1.0")
        }
        other => panic!("unexpected reason: {other:?}"),
    }
    // The node still exists, so nothing may be unregistered on its behalf.
    assert_eq!(report.present_dev_nodes.len(), 1);
}

#[test]
fn broken_sysfs_attributes_skip_instead_of_panicking() {
    let tree = FakeUsb::new();
    let dev = adb_device();
    let sys = install(&tree, &dev);
    break_attr(&sys.join("1-2:1.0"), "bInterfaceClass");

    let report = scan_usb_devices(&tree.roots());

    assert!(report.devices.is_empty());
    assert_eq!(report.skipped.len(), 1);
    match &report.skipped[0].reason {
        SkipReason::SysfsAttributeUnreadable { attribute } => {
            assert_eq!(attribute, "bInterfaceClass")
        }
        other => panic!("unexpected reason: {other:?}"),
    }
    assert!(report.complete);
}

#[test]
fn unreadable_serial_keeps_the_device() {
    let tree = FakeUsb::new();
    let dev = adb_device();
    let sys = install(&tree, &dev);
    break_attr(&sys, "serial");

    let report = scan_usb_devices(&tree.roots());

    assert_eq!(report.devices.len(), 1, "skipped: {:?}", report.skipped);
    assert_eq!(report.devices[0].serial, None);
    assert_eq!(report.devices[0].vendor_id, Some(0x18d1));
}

#[test]
fn missing_id_vendor_or_id_product_is_not_fatal() {
    let tree = FakeUsb::new();
    let dev = adb_device();
    let sys = install(&tree, &dev);
    fs::remove_file(sys.join("idVendor")).unwrap();
    fs::remove_file(sys.join("idProduct")).unwrap();

    let report = scan_usb_devices(&tree.roots());

    assert_eq!(report.devices.len(), 1, "skipped: {:?}", report.skipped);
    assert_eq!(report.devices[0].vendor_id, None);
    assert_eq!(report.devices[0].product_id, None);
}

#[test]
fn device_without_sysfs_counterpart_is_skipped() {
    let tree = FakeUsb::new();
    tree.node("002", "007");

    let report = scan_usb_devices(&tree.roots());

    assert!(report.devices.is_empty());
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].reason, SkipReason::SysfsDeviceNotFound);
    // The node was seen, so an incomplete identification is not a removal.
    assert_eq!(report.present_dev_nodes.len(), 1);
}

#[test]
fn missing_bus_root_reports_the_error_without_panicking() {
    let tree = FakeUsb::new();
    let roots = ScanRoots::new(
        tree.root.join("does-not-exist/dev"),
        tree.root.join("does-not-exist/sys"),
    );

    let report = scan_usb_devices(&roots);

    assert!(report.devices.is_empty());
    assert!(!report.complete);
    let error = report.root_error.expect("root error");
    assert!(error.contains("does-not-exist/dev"), "{error}");

    // A poll tick over a broken root must not unregister anything.
    let mut tracker = HotplugTracker::new(roots);
    let tick = tracker.tick();
    assert!(tick.added.is_empty());
    assert!(tick.removed.is_empty());
    assert!(!tick.complete);
    assert!(tick.root_error.is_some());
}

// ---------------------------------------------------------------------------
// Known-device set / diffing
// ---------------------------------------------------------------------------

#[test]
fn second_tick_does_not_register_the_same_device_again() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());
    let mut tracker = HotplugTracker::new(tree.roots());

    let first = tracker.tick();
    assert_eq!(first.generation, 1);
    assert_eq!(first.added.len(), 1, "skipped: {:?}", first.skipped);
    assert!(first.removed.is_empty());
    assert_eq!(tracker.known_count(), 1);

    let second = tracker.tick();
    assert_eq!(second.generation, 2);
    assert!(second.added.is_empty(), "re-registered: {:?}", second.added);
    assert!(second.removed.is_empty());
    assert_eq!(second.kept.len(), 1);
    assert_eq!(tracker.known_count(), 1);
    assert_eq!(tracker.scans(), 2);
    // Added at generation 1, still the same registration after generation 2.
    let name = tracker.known_devices().next().unwrap().dev_name.clone();
    assert_eq!(tracker.added_at(&name), Some(1));
    assert!(tracker.is_known_device(&name));
}

#[test]
fn removing_the_device_node_unregisters_it() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());
    let mut tracker = HotplugTracker::new(tree.roots());

    assert_eq!(tracker.tick().added.len(), 1);
    let name = tracker.known_devices().next().unwrap().dev_name.clone();

    tree.remove_node("001", "002");
    fs::remove_dir_all(tree.root.join("sys/bus/usb/devices/1-2")).unwrap();

    let tick = tracker.tick();
    assert_eq!(tick.removed.len(), 1, "complete: {}", tick.complete);
    assert_eq!(tick.removed[0].dev_name, name);
    assert!(tick.kept.is_empty());
    assert_eq!(tracker.known_count(), 0);
    assert!(!tracker.is_known_device(&name));
}

#[test]
fn unreadable_interface_keeps_the_registration() {
    let tree = FakeUsb::new();
    let dev = adb_device();
    let sys = install(&tree, &dev);
    let mut tracker = HotplugTracker::new(tree.roots());
    assert_eq!(tracker.tick().added.len(), 1);

    // Node still exists, but its class attribute is unreadable (the
    // udev-chmod race from usb_linux.cpp:122-151).  AOSP never unregisters on
    // a scan failure, only on an explicit remove.
    let class_path = sys.join("1-2:1.0").join("bInterfaceClass");
    fs::set_permissions(&class_path, fs::Permissions::from_mode(0o000)).unwrap();

    let tick = tracker.tick();
    assert!(tick.added.is_empty());
    assert!(tick.removed.is_empty(), "removed: {:?}", tick.removed);
    assert_eq!(tick.kept.len(), 1);
    assert_eq!(tracker.known_count(), 1);

    fs::set_permissions(&class_path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn tick_with_dispatches_add_then_remove_events() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());
    let mut tracker = HotplugTracker::new(tree.roots());
    let mut seen = Vec::new();

    let first = tracker.tick_with(|event| seen.push(format!("{event:?}")));
    assert_eq!(first.added.len(), 1);
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("Added("));

    seen.clear();
    tree.remove_node("001", "002");
    let second = tracker.tick_with(|event| match event {
        HotplugEvent::Removed(dev) => seen.push(format!("removed:{}", dev.sysfs_name)),
        HotplugEvent::Added(dev) => seen.push(format!("added:{}", dev.sysfs_name)),
    });
    assert!(second.added.is_empty());
    assert_eq!(seen, vec!["removed:1-2".to_string()]);
}

#[test]
fn process_usb_device_registers_once_and_marks_known() {
    let tree = FakeUsb::new();
    let _sys = install(&tree, &adb_device());
    let node = tree.root.join("dev/bus/usb/001/002");
    let mut tracker = HotplugTracker::new(tree.roots());

    match tracker.process_usb_device(&node.to_string_lossy()) {
        ProcessOutcome::Added(dev) => assert_eq!(dev.serial.as_deref(), Some("ABC123")),
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(tracker.known_count(), 1);
    assert_eq!(
        tracker.process_usb_device(&node.to_string_lossy()),
        ProcessOutcome::AlreadyKnown
    );

    // A node that vanished before the event is handled: no phantom device.
    assert_eq!(
        tracker.process_usb_device("/definitely/not/there/001/009"),
        ProcessOutcome::NotPresent
    );
    assert_eq!(tracker.known_count(), 1);
}

#[test]
fn process_usb_device_accepts_bus_address_relative_to_the_root() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());
    let mut tracker = HotplugTracker::new(tree.roots());

    match tracker.process_usb_device("001/002") {
        ProcessOutcome::Added(dev) => assert!(dev.dev_name.ends_with("/001/002")),
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(
        tracker.process_usb_device("001/002"),
        ProcessOutcome::AlreadyKnown
    );
}

#[test]
fn fastboot_device_is_also_tracked() {
    let tree = FakeUsb::new();
    let mut dev = adb_device();
    dev.ifaces = vec![Iface::fastboot("1-2:1.0")];
    install(&tree, &dev);
    let mut tracker = HotplugTracker::new(tree.roots());

    let tick = tracker.tick();
    assert_eq!(tick.added.len(), 1);
    assert_eq!(tick.added[0].kind, UsbInterfaceKind::Fastboot);
}

#[test]
fn two_devices_are_independent() {
    let tree = FakeUsb::new();
    install(&tree, &adb_device());
    let mut second = adb_device();
    second.bus = "002";
    second.addr = "005";
    second.sysfs = "2-5";
    second.serial = Some("SECOND");
    second.ifaces = vec![Iface::adb("2-5:1.0")];
    install(&tree, &second);

    let mut tracker = HotplugTracker::new(tree.roots());
    assert_eq!(tracker.tick().added.len(), 2);

    tree.remove_node("001", "002");
    let tick = tracker.tick();
    assert_eq!(tick.removed.len(), 1);
    assert_eq!(tick.kept.len(), 1);
    let survivor = tracker.known_devices().next().unwrap();
    assert_eq!(survivor.serial.as_deref(), Some("SECOND"));
}
