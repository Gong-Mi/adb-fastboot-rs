//! Discovered ADB services tracking and management.
//!
//! AOSP source: `vendor/adb/client/discovered_services.cpp`
//!
//! Tracks mDNS-discovered ADB services (devices found via network discovery).
//! Maintains a list of `AdbMdnsService` records that can be listed by the
//! user and used for connection.
//!
//! TODO: Implement the discovered services registry (in-memory store of
//!       mDNS-discovered ADB services).
//! TODO: Provide methods to list, filter, and resolve discovered services.
//! TODO: Integrate with mdns.rs for service discovery results.
