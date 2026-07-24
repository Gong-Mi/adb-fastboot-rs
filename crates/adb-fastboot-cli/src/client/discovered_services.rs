//! Discovered ADB services tracking and management.
//!
//! AOSP source: `vendor/adb/client/discovered_services.cpp`
//!
//! Tracks mDNS-discovered ADB services (devices found via network discovery).
//! Maintains a list of `AdbMdnsService` records that can be listed by the
//! user and used for connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

use adb_protocol::mdns::{AdbMdnsService, AdbMdnsServiceType};

/// Thread-safe global registry of discovered ADB mDNS services.
fn global_registry() -> &'static Mutex<DiscoveredServiceRegistry> {
    static REGISTRY: OnceLock<Mutex<DiscoveredServiceRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(DiscoveredServiceRegistry::new()))
}

/// Filter options for listing discovered services.
#[derive(Debug, Clone, Default)]
pub struct ServiceFilter {
    /// Filter by service type (classic, TLS-connect, TLS-pairing).
    pub service_type: Option<AdbMdnsServiceType>,
    /// Filter by IP address family (4 for IPv4, 6 for IPv6).
    pub address_family: Option<u8>,
    /// Search string for instance name or serial.
    pub query: Option<String>,
}

/// A registry tracking discovered ADB mDNS services.
#[derive(Debug, Clone)]
pub struct DiscoveredServiceRegistry {
    services: HashMap<String, AdbMdnsService>,
}

impl DiscoveredServiceRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Add or update a discovered service.
    pub fn add_service(&mut self, service: AdbMdnsService) {
        let key = service.instance_name.clone();
        self.services.insert(key, service);
    }

    /// Remove a service by instance name.
    pub fn remove_service(&mut self, instance_name: &str) -> bool {
        self.services.remove(instance_name).is_some()
    }

    /// Get all discovered services.
    pub fn get_all(&self) -> Vec<&AdbMdnsService> {
        self.services.values().collect()
    }

    /// Get services matching a filter.
    pub fn get_filtered(&self, filter: &ServiceFilter) -> Vec<&AdbMdnsService> {
        self.services
            .values()
            .filter(|s| {
                if let Some(ref st) = filter.service_type {
                    if s.service_type != *st {
                        return false;
                    }
                }
                if let Some(family) = filter.address_family {
                    let has_matching = s.addresses.iter().any(|addr| match family {
                        4 => matches!(addr, IpAddr::V4(_)),
                        6 => matches!(addr, IpAddr::V6(_)),
                        _ => true,
                    });
                    if !has_matching {
                        return false;
                    }
                }
                if let Some(ref q) = filter.query {
                    let q_lower = q.to_lowercase();
                    let name_match = s.instance_name.to_lowercase().contains(&q_lower);
                    let serial_match = s
                        .device_serial()
                        .map(|ser| ser.to_lowercase().contains(&q_lower))
                        .unwrap_or(false);
                    let host_match = s
                        .host_name
                        .as_ref()
                        .map(|h| h.to_lowercase().contains(&q_lower))
                        .unwrap_or(false);
                    if !name_match && !serial_match && !host_match {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Get a service by instance name.
    pub fn get_by_instance_name(&self, name: &str) -> Option<&AdbMdnsService> {
        self.services.get(name)
    }

    /// Get a service by serial number (searches TXT records and instance name).
    pub fn get_by_serial(&self, serial: &str) -> Option<&AdbMdnsService> {
        self.services
            .values()
            .find(|s| s.device_serial().as_deref() == Some(serial))
    }

    /// Clear all services.
    pub fn clear(&mut self) {
        self.services.clear();
    }

    /// Number of services currently tracked.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

impl Default for DiscoveredServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// --- Global accessor functions ---

/// Add a discovered service to the global registry.
pub fn register_service(service: AdbMdnsService) {
    if let Ok(mut registry) = global_registry().lock() {
        registry.add_service(service);
    }
}

/// Remove a service from the global registry.
pub fn unregister_service(instance_name: &str) -> bool {
    if let Ok(mut registry) = global_registry().lock() {
        registry.remove_service(instance_name)
    } else {
        false
    }
}

/// List all discovered services.
pub fn list_services() -> Vec<AdbMdnsService> {
    if let Ok(registry) = global_registry().lock() {
        registry.get_all().into_iter().cloned().collect()
    } else {
        Vec::new()
    }
}

/// List discovered services matching a filter.
pub fn list_services_filtered(filter: &ServiceFilter) -> Vec<AdbMdnsService> {
    if let Ok(registry) = global_registry().lock() {
        registry
            .get_filtered(filter)
            .into_iter()
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

/// Find a service by serial number.
pub fn find_service_by_serial(serial: &str) -> Option<AdbMdnsService> {
    if let Ok(registry) = global_registry().lock() {
        registry.get_by_serial(serial).cloned()
    } else {
        None
    }
}

/// Find a service by instance name.
pub fn find_service_by_instance_name(name: &str) -> Option<AdbMdnsService> {
    if let Ok(registry) = global_registry().lock() {
        registry.get_by_instance_name(name).cloned()
    } else {
        None
    }
}

/// Get the count of discovered services.
pub fn service_count() -> usize {
    if let Ok(registry) = global_registry().lock() {
        registry.len()
    } else {
        0
    }
}

/// Clear all discovered services.
pub fn clear_services() {
    if let Ok(mut registry) = global_registry().lock() {
        registry.clear();
    }
}

/// Format a discovered service as a human-readable string.
pub fn format_service(service: &AdbMdnsService) -> String {
    let service_type = match service.service_type {
        AdbMdnsServiceType::Classic => "adb",
        AdbMdnsServiceType::TlsConnect => "adb-tls-connect",
        AdbMdnsServiceType::TlsPairing => "adb-tls-pairing",
    };

    let addresses: Vec<String> = service
        .addresses
        .iter()
        .map(|a| a.to_string())
        .collect();
    let addr_str = addresses.join(", ");

    let serial = service
        .device_serial()
        .unwrap_or_else(|| "N/A".to_string());

    format!(
        "{:<20} {:<15} {:<6} {:<10} {}",
        service.instance_name,
        serial,
        service.port,
        service_type,
        addr_str,
    )
}

/// Print all discovered services to stdout in a table format.
pub fn print_services() {
    let services = list_services();
    if services.is_empty() {
        println!("No services discovered.");
        return;
    }
    println!("{:<20} {:<15} {:<6} {:<10} Addresses", "Instance", "Serial", "Port", "Type");
    println!("{}", "-".repeat(65));
    for service in &services {
        println!("{}", format_service(service));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_registry_basics() {
        let mut registry = DiscoveredServiceRegistry::new();
        assert!(registry.is_empty());

        let service = AdbMdnsService::new(
            AdbMdnsServiceType::TlsConnect,
            "adb-DEVICE001-_adb-tls-connect._tcp.local.",
            5555,
        );
        registry.add_service(service.clone());
        assert_eq!(registry.len(), 1);

        let found = registry.get_by_serial("DEVICE001");
        assert!(found.is_some());

        registry.remove_service(&service.instance_name);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_filter_by_type() {
        let mut registry = DiscoveredServiceRegistry::new();

        let classic = AdbMdnsService::new(
            AdbMdnsServiceType::Classic,
            "adb-CLASSIC-_adb._tcp.local.",
            5555,
        );
        let tls = AdbMdnsService::new(
            AdbMdnsServiceType::TlsConnect,
            "adb-TLS-_adb-tls-connect._tcp.local.",
            5555,
        );

        registry.add_service(classic);
        registry.add_service(tls);

        let filter = ServiceFilter {
            service_type: Some(AdbMdnsServiceType::Classic),
            ..Default::default()
        };

        assert_eq!(registry.get_filtered(&filter).len(), 1);
    }
}
