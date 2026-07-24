//! ADB USB device watcher — inotify event-driven, fallback to polling.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(feature = "usb")]
use inotify::{Inotify, WatchMask};

use crate::server::models::{TransportRegistry, POLL_INTERVAL};

/// USB device watcher: monitors `/dev/bus/usb` via inotify for create/delete/move
/// events. Falls back to regular polling (`POLL_INTERVAL`) when inotify is
/// unavailable (e.g. Android restrictions, kernel without inotify, etc.).
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
                                // Any observable change → re-enumerate
                                if events.count() > 0 {
                                    if let Ok(mut reg) = registry.lock() {
                                        reg.refresh_usb_devices();
                                    }
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
    }
}

/// No-op when USB feature is not compiled in.
#[cfg(not(feature = "usb"))]
pub(crate) fn usb_device_watcher(_registry: Arc<Mutex<TransportRegistry>>, _running: Arc<AtomicBool>) {}
