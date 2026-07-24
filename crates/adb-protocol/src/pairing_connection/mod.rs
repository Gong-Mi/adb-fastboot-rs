//! AOSP pairing connection, mirroring `vendor/adb/pairing_connection/`.
pub mod pairing_connection;
pub mod pairing_server;

// Re-exports for convenience
pub use pairing_connection::{save_adb_keystore, AdbKeystore, PairingClient};
pub use pairing_server::PairingServer;
