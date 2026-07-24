//! ADB bugreport generation and collection.
//!
//! AOSP source: `vendor/adb/client/bugreport.cpp`
//!
//! Handles:
//! - `adb bugreport [path]` — generate and pull a bugreport zip
//! - Coordinates `dumpstate` service on the device
//! - Manages bugreport progress and cancellation
//!
//! TODO: Implement bugreport command: sends `bugreportz` service request,
//!       monitors progress, pulls the resulting zip file via sync.
//! TODO: Support `bugreport` (legacy) and `bugreportz` (zipped) variants.
//! TODO: Handle CTRL+C cancellation gracefully.
