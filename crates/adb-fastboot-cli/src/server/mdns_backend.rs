//! Adapter from the AOSP `adb-mdns` zero-config engine into the ADB server
//! transport registry. The pure state transition is separated from the
//! network worker so Create/Update/Delete behavior is testable without a
//! device, multicast access, or wall-clock waits.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;

use zeroconf::{AdbMdnsUpdate, DiscoveredService};
use adb_protocol::mdns::{AdbMdnsService, AdbMdnsServiceType};

use crate::server::models::{DeviceOrigin, DeviceState, TransportRegistry};

/// Start AOSP's Rust mDNS engine and feed its event stream into `registry`.
/// `ADB_MDNS=0` disables discovery, matching AOSP `mdns::is_enabled()`.
/// The worker is intentionally omitted from unit-test builds; tests exercise
/// `apply_discovery_event` directly with deterministic events instead.
#[cfg(not(test))]
pub(crate) fn start_discovery(registry: Arc<Mutex<TransportRegistry>>) {
    if std::env::var("ADB_MDNS").is_ok_and(|v| v == "0") {
        eprintln!("[adb-mdns] disabled by ADB_MDNS=0");
        return;
    }

    let _ = thread::Builder::new()
        .name("adb-mdns-aosp-startup".into())
        .spawn(move || {
            zeroconf::start_discovery(move |event, record| {
                match registry.lock() {
                    Ok(mut registry) => apply_discovery_event(&mut registry, event, record),
                    Err(error) => eprintln!("[adb-mdns] transport registry lock poisoned: {error}"),
                }
            });
        })
        .map_err(|error| eprintln!("[adb-mdns] failed to start AOSP discovery: {error}"));
}

#[cfg(test)]
pub(crate) fn start_discovery(_registry: Arc<Mutex<TransportRegistry>>) {}

/// Apply one AOSP mDNS state-machine event to the cached service records and
/// the device transport registry. Unknown service types are ignored; TLS
/// pairing records are not connectable transports and are ignored too.
pub(crate) fn apply_discovery_event(
    registry: &mut TransportRegistry,
    event: AdbMdnsUpdate,
    discovered: DiscoveredService,
) {
    let Some(service) = to_adb_service(discovered) else {
        return;
    };
    let key = service_key(&service);

    match event {
        AdbMdnsUpdate::Create | AdbMdnsUpdate::Update => {
            let previous = registry.mdns_services.insert(key, service.clone());
            if let Some(old) = previous {
                let old_serial = service_serial(&old);
                let new_serial = service_serial(&service);
                if old_serial != new_serial {
                    refresh_device_for_serial(registry, &old_serial);
                }
            }
            refresh_device_for_serial(registry, &service_serial(&service));
        }
        AdbMdnsUpdate::Delete => {
            if let Some(old) = registry.mdns_services.remove(&key) {
                refresh_device_for_serial(registry, &service_serial(&old));
            }
        }
    }
}

fn service_key(service: &AdbMdnsService) -> String {
    format!("{}\0{}", service.instance_name, service.service_type.service_name())
}

fn service_serial(service: &AdbMdnsService) -> String {
    service
        .device_serial()
        .unwrap_or_else(|| service.instance_name.clone())
}

fn to_adb_service(info: DiscoveredService) -> Option<AdbMdnsService> {
    let service_type = if info.service_type.contains("_adb-tls-connect._tcp") {
        AdbMdnsServiceType::TlsConnect
    } else if info.service_type.contains("_adb._tcp") {
        AdbMdnsServiceType::Classic
    } else {
        // _adb-tls-pairing is a pairing endpoint, not a transport. Do not
        // publish it in `host:mdns:services` or the device transport table.
        return None;
    };

    let mut service = AdbMdnsService::new(service_type, info.instance_name, info.port);
    if !info.host_name.is_empty() {
        service.host_name = Some(info.host_name);
    }
    service.addresses.extend(info.ipv4_addresses.into_iter().map(IpAddr::V4));
    service.addresses.extend(info.ipv6_addresses.into_iter().map(IpAddr::V6));
    service.txt_records = info.txt_records.into_iter().collect();
    Some(service)
}

/// Keep one TCP device per resolved serial while preserving USB transports
/// with the same serial. If several DNS-SD records resolve to that serial,
/// choose deterministically by service type then instance name.
fn refresh_device_for_serial(registry: &mut TransportRegistry, serial: &str) {
    let mut candidates: Vec<&AdbMdnsService> = registry
        .mdns_services
        .values()
        .filter(|service| service_serial(service) == serial && !service.addresses.is_empty())
        .collect();
    candidates.sort_by(|a, b| {
        a.service_type
            .service_name()
            .cmp(b.service_type.service_name())
            .then_with(|| a.instance_name.cmp(&b.instance_name))
    });

    if let Some(service) = candidates.first() {
        let address = SocketAddr::new(service.addresses[0], service.port);
        if let Some(existing) = registry.devices.iter_mut().find(|d| d.serial == serial) {
            // A physical USB transport takes precedence over a parallel
            // wireless advertisement with the same serial.
            if matches!(existing.origin, DeviceOrigin::Usb) {
                return;
            }
            existing.state = DeviceState::Device;
            existing.origin = DeviceOrigin::Tcp { addr: address };
            existing.product = service.txt_records.get("product").cloned();
            existing.model = service.txt_records.get("model").cloned();
            existing.device_name = service.txt_records.get("device").cloned();
        } else {
            let transport_id = registry.next_id;
            registry.next_id += 1;
            registry.devices.push(crate::server::models::DeviceEntry {
                serial: serial.to_owned(),
                transport_id,
                state: DeviceState::Device,
                origin: DeviceOrigin::Tcp { addr: address },
                product: service.txt_records.get("product").cloned(),
                model: service.txt_records.get("model").cloned(),
                device_name: service.txt_records.get("device").cloned(),
                transport_features: None,
            });
        }
    } else {
        // Remove only the wireless entry; do not remove a same-serial USB
        // device if another transport source owns that serial.
        registry.devices.retain(|device| {
            device.serial != serial || matches!(device.origin, DeviceOrigin::Usb)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn info(service_type: &str, name: &str, port: u16, serial: &str, v4: [u8; 4]) -> DiscoveredService {
        DiscoveredService {
            instance_name: name.to_owned(),
            service_type: service_type.to_owned(),
            host_name: "device.local".to_owned(),
            ipv4_addresses: vec![Ipv4Addr::from(v4)],
            ipv6_addresses: vec![Ipv6Addr::LOCALHOST],
            port,
            txt_records: BTreeMap::from([
                ("serial".to_owned(), serial.to_owned()),
                ("model".to_owned(), "test-model".to_owned()),
                ("product".to_owned(), "test-product".to_owned()),
                ("device".to_owned(), "test-device".to_owned()),
            ]),
        }
    }

    #[test]
    fn create_is_idempotent_and_maps_dns_sd_fields() {
        let mut registry = TransportRegistry::new();
        let record = info("_adb-tls-connect._tcp.local.", "adb-S1-_adb-tls-connect._tcp.local.", 5555, "S1", [10, 0, 0, 1]);
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Create, record.clone());
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Create, record);

        assert_eq!(registry.mdns_services.len(), 1);
        assert_eq!(registry.devices.len(), 1);
        let device = &registry.devices[0];
        assert_eq!(device.serial, "S1");
        assert_eq!(device.origin, DeviceOrigin::Tcp { addr: "10.0.0.1:5555".parse().unwrap() });
        assert_eq!(device.model.as_deref(), Some("test-model"));
        assert_eq!(device.product.as_deref(), Some("test-product"));
    }

    #[test]
    fn update_replaces_endpoint_and_txt_metadata_without_duplicate_device() {
        let mut registry = TransportRegistry::new();
        apply_discovery_event(
            &mut registry,
            AdbMdnsUpdate::Create,
            info("_adb._tcp.local.", "adb-S1-_adb._tcp.local.", 5555, "S1", [10, 0, 0, 1]),
        );
        let mut updated = info("_adb._tcp.local.", "adb-S1-_adb._tcp.local.", 6666, "S1", [10, 0, 0, 2]);
        updated.txt_records.insert("model".into(), "updated-model".into());
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Update, updated);

        assert_eq!(registry.mdns_services.len(), 1);
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0].origin, DeviceOrigin::Tcp { addr: "10.0.0.2:6666".parse().unwrap() });
        assert_eq!(registry.devices[0].model.as_deref(), Some("updated-model"));
    }

    #[test]
    fn delete_removes_last_service_and_device_but_unknown_delete_is_noop() {
        let mut registry = TransportRegistry::new();
        let record = info("_adb._tcp.local.", "adb-S1-_adb._tcp.local.", 5555, "S1", [10, 0, 0, 1]);
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Delete, record.clone());
        assert!(registry.mdns_services.is_empty());
        assert!(registry.devices.is_empty());

        apply_discovery_event(&mut registry, AdbMdnsUpdate::Create, record.clone());
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Delete, record);
        assert!(registry.mdns_services.is_empty());
        assert!(registry.devices.is_empty());
    }

    #[test]
    fn tls_pairing_advertisement_is_not_registered_as_a_device_transport() {
        let mut registry = TransportRegistry::new();
        apply_discovery_event(
            &mut registry,
            AdbMdnsUpdate::Create,
            info("_adb-tls-pairing._tcp.local.", "pairing", 37123, "", [10, 0, 0, 1]),
        );
        assert!(registry.mdns_services.is_empty());
        assert!(registry.devices.is_empty());
    }

    #[test]
    fn deleting_one_of_multiple_service_types_keeps_other_serial_transport() {
        let mut registry = TransportRegistry::new();
        let classic = info("_adb._tcp.local.", "adb-S1-_adb._tcp.local.", 5555, "S1", [10, 0, 0, 1]);
        let tls = info(
            "_adb-tls-connect._tcp.local.",
            "adb-S1-_adb-tls-connect._tcp.local.",
            5556,
            "S1",
            [10, 0, 0, 2],
        );
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Create, classic.clone());
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Create, tls.clone());
        assert_eq!(registry.mdns_services.len(), 2);
        assert_eq!(registry.devices.len(), 1);

        apply_discovery_event(&mut registry, AdbMdnsUpdate::Delete, tls);
        assert_eq!(registry.mdns_services.len(), 1);
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0].origin, DeviceOrigin::Tcp { addr: "10.0.0.1:5555".parse().unwrap() });

        apply_discovery_event(&mut registry, AdbMdnsUpdate::Delete, classic);
        assert!(registry.mdns_services.is_empty());
        assert!(registry.devices.is_empty());
    }

    #[test]
    fn update_that_changes_serial_cleans_old_device_and_adds_new_one() {
        let mut registry = TransportRegistry::new();
        apply_discovery_event(
            &mut registry,
            AdbMdnsUpdate::Create,
            info("_adb._tcp.local.", "instance-1", 5555, "OLD", [10, 0, 0, 1]),
        );
        apply_discovery_event(
            &mut registry,
            AdbMdnsUpdate::Update,
            info("_adb._tcp.local.", "instance-1", 6666, "NEW", [10, 0, 0, 2]),
        );

        assert_eq!(registry.mdns_services.len(), 1);
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0].serial, "NEW");
        assert_eq!(registry.devices[0].origin, DeviceOrigin::Tcp { addr: "10.0.0.2:6666".parse().unwrap() });
    }

    #[test]
    fn usb_transport_with_same_serial_is_not_replaced_or_removed() {
        let mut registry = TransportRegistry::new();
        registry.devices.push(crate::server::models::DeviceEntry {
            serial: "S1".into(),
            transport_id: 1,
            state: DeviceState::Device,
            origin: DeviceOrigin::Usb,
            product: None,
            model: None,
            device_name: None,
            transport_features: None,
        });
        let record = info("_adb._tcp.local.", "adb-S1-_adb._tcp.local.", 5555, "S1", [10, 0, 0, 1]);
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Create, record.clone());
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0].origin, DeviceOrigin::Usb);
        apply_discovery_event(&mut registry, AdbMdnsUpdate::Delete, record);
        assert_eq!(registry.devices.len(), 1);
        assert_eq!(registry.devices[0].origin, DeviceOrigin::Usb);
    }
}
