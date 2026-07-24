//! ADB over Wi-Fi service: pairing and connecting via mDNS + TLS.
//!
//! AOSP source: `vendor/adb/client/adb_wifi.cpp`
//!
//! Handles:
//! - `adb pair <host:port> <code>` — Wi-Fi pairing (TLS + QR code / pairing code)
//! - `adb connect <host:port>` over Wi-Fi (uses mDNS discovery + TLS handshake)
//! - Device authentication via pairing service
//!
//! TODO: Implement ADB Wi-Fi pairing protocol (mDNS + TLS + QR code).
//! TODO: Implement `adb pair` command with pairing code exchange.
//! TODO: Integrate with mdns.rs for service discovery.
