//! ADB application installation (adb install / adb install-multi-package).
//!
//! AOSP source: `vendor/adb/client/adb_install.cpp`
//!
//! Handles:
//! - `adb install <apk>` — push APK + run INSTALL command
//! - `adb install-multiple` — multiple APK split install
//! - `adb install-multi-package` — atomic multi-package install
//! - Progress reporting, verification, staging
//!
//! TODO: Implement APK push + install command cycle over ADB transport.
//! TODO: Handle split APKs (install-multiple) and multi-package transactions.
//! TODO: Support `-r` (reinstall), `-d` (downgrade), `-g` (grant all permissions) flags.
