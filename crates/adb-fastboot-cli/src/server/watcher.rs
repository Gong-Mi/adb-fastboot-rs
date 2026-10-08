//! ADB USB device watcher — inotify event-driven, fallback to polling.
//!
//! At device discovery time, the watcher opens the USB transport, performs the
//! full AUTH/CNXN handshake, and caches the authenticated transport in the
//! registry.  This allows the bridge to reuse the cached transport instead of
//! opening a new one and re-authenticating on each client connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(feature = "usb")]
use inotify::{Inotify, WatchMask};

use crate::server::models::{TransportRegistry, POLL_INTERVAL};

#[cfg(feature = "usb")]
use crate::server::models::AuthenticatedUsbTransport;

/// USB device watcher: monitors `/dev/bus/usb` via inotify for create/delete/move
/// events. Falls back to regular polling (`POLL_INTERVAL`) when inotify is
/// unavailable (e.g. Android restrictions, kernel without inotify, etc.).
///
/// When a new USB device is discovered, the watcher eagerly opens the USB
/// transport, performs the AUTH/CNXN handshake, and caches the authenticated
/// transport in the registry's `usb_auth` map for reuse by the bridge.
#[cfg(feature = "usb")]
pub(crate) fn usb_device_watcher(registry: Arc<Mutex<TransportRegistry>>, running: Arc<AtomicBool>) {
    // Strategy 1: inotify on /dev/bus/usb — event-driven, no CPU waste
    match Inotify::init() {
        Ok(mut inotify) => {
            let watch_result = inotify.watches().add(
                "/dev/bus/usb",
                WatchMask::CREATE
                    | WatchMask::DELETE
                    | WatchMask::MOVED_FROM
                    | WatchMask::MOVED_TO,
            );
            match watch_result {
                Ok(_) => {
                    eprintln!(
                        "[adb-server] USB watcher: using inotify on /dev/bus/usb"
                    );
                    let mut buffer = [0u8; 4096];
                    while running.load(Ordering::Relaxed) {
                        match inotify.read_events_blocking(&mut buffer) {
                            Ok(events) => {
                                // Any observable change → re-enumerate and re-auth
                                if events.count() > 0 {
                                    if let Ok(mut reg) = registry.lock() {
                                        reg.refresh_usb_devices();
                                    }
                                    // Eagerly authenticate newly discovered USB devices
                                    preauth_new_usb_devices(&registry);
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "[adb-server] USB watcher: inotify read error ({e}), retrying"
                                );
                                // Brief pause to avoid busy-loop on persistent errors
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                    return; // inotify path done
                }
                Err(e) => {
                    eprintln!(
                        "[adb-server] USB watcher: cannot watch /dev/bus/usb ({e})"
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("[adb-server] USB watcher: inotify init failed ({e})");
        }
    }

    // Strategy 2: fallback — periodic polling
    eprintln!(
        "[adb-server] USB watcher: falling back to polling every {:?}",
        POLL_INTERVAL
    );
    while running.load(Ordering::Relaxed) {
        thread::sleep(POLL_INTERVAL);
        if let Ok(mut reg) = registry.lock() {
            reg.refresh_usb_devices();
        }
        // Eagerly authenticate newly discovered USB devices
        preauth_new_usb_devices(&registry);
    }
}

/// Iterate USB devices in the registry, and for any that are not yet
/// authenticated, open the USB transport and perform the AUTH/CNXN handshake.
///
/// Authentication is done **outside** the registry lock to avoid holding the
/// lock during slow USB I/O.  The registry is locked only to read the list of
/// unauthenticated serials and to store the result.
#[cfg(feature = "usb")]
fn preauth_new_usb_devices(registry: &Arc<Mutex<TransportRegistry>>) {
    use crate::server::transport::connect_usb_device;

    // Collect serials of USB devices that need authentication
    let todo: Vec<String> = {
        let reg = match registry.lock() {
            Ok(r) => r,
            Err(_) => return,
        };
        reg.devices
            .iter()
            .filter(|d| {
                use crate::server::models::DeviceOrigin;
                matches!(d.origin, DeviceOrigin::Usb) && !reg.usb_auth.contains_key(&d.serial)
            })
            .map(|d| d.serial.clone())
            .collect()
    };

    for serial in &todo {
        eprintln!(
            "[adb-server] Pre-authenticating USB device '{serial}'..."
        );

        // Reserve before claim/auth: no duplicate owner during watcher work.
        {
            let Ok(mut reg) = registry.lock() else { return; };
            if reg.usb_auth.contains_key(serial) { continue; }
            reg.usb_auth.insert(serial.clone(), AuthenticatedUsbTransport {
                _serial: serial.clone(), transport: None,
            });
        }
        // Open USB transport and perform AUTH/CNXN (outside the lock)
        let transport = match connect_usb_device(serial, registry) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "[adb-server] Pre-auth of '{serial}' failed (will retry): {e}"
                );
                if let Ok(mut reg) = registry.lock() { reg.usb_auth.remove(serial); }
                continue;
            }
        };

        // Store the authenticated transport in the registry (brief lock)
        let mut reg = match registry.lock() {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "[adb-server] Registry lock failed while caching '{serial}': {e}"
                );
                continue;
            }
        };
        reg.usb_auth.insert(
            serial.clone(),
            AuthenticatedUsbTransport {
                _serial: serial.clone(),
                transport: Some(transport),
            },
        );

        eprintln!(
            "[adb-server] USB device '{serial}' pre-authenticated and cached."
        );
    }
}

/// No-op when USB feature is not compiled in.
#[cfg(not(feature = "usb"))]
pub(crate) fn usb_device_watcher(_registry: Arc<Mutex<TransportRegistry>>, _running: Arc<AtomicBool>) {}
