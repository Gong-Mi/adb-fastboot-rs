/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::rr::TxtAttributes;
use crate::zero_config::ZeroConfigCommand::{
    CreateService, DeleteService, DnsQueries, Restart, UpdateService,
};
use crate::zero_config::{ZeroConfig, ZeroConfigCommand};
use crate::zero_config_driver_channel::ZeroConfigDriverChannelReceiver;
use crate::{send_update, AdbMdnsUpdate};
use anyhow::Result;
use if_addrs::Interface;
use log::{debug, error, warn};
use mio::{net::UdpSocket, Events, Poll};
use simple_dns::{Name, Packet, Question};
use socket2::{Domain, Socket, Type};
use std::collections::HashSet;
use std::io::ErrorKind::WouldBlock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};
use std::{net, thread};

struct ZeroConfigIO {
    interface: Interface,
    socket: UdpSocket,
}

pub struct ZeroConfigDriver {
    zero_config: ZeroConfig,

    // The sockets/interfaces used to send and receive mDNS packets
    io: Vec<ZeroConfigIO>,

    // A channel allowing to received commands sent from outside zeroconfig driver.
    // Currently used to receive commands resulting from network_watch.
    command_channel: ZeroConfigDriverChannelReceiver,

    running: bool,

    poll: Poll,
}

const MDNS_PORT: u16 = 5353;
const COMMAND_CHANNEL_TOKEN: mio::Token = mio::Token(0);
const MDNS_ADDRESS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

impl ZeroConfigDriver {
    pub fn new(
        zero_config: ZeroConfig,
        mut command_channel: ZeroConfigDriverChannelReceiver,
    ) -> Result<ZeroConfigDriver> {
        let poll = Poll::new()?;
        poll.registry().register(
            &mut command_channel,
            COMMAND_CHANNEL_TOKEN,
            mio::Interest::READABLE,
        )?;
        Ok(ZeroConfigDriver { zero_config, io: Vec::new(), command_channel, running: true, poll })
    }

    fn send_query(&self, query: &[u8]) -> Result<()> {
        for zeroconfig_io in &self.io {
            let addr: SocketAddr = match zeroconfig_io.interface.addr {
                if_addrs::IfAddr::V4(_) => SocketAddrV4::new(MDNS_ADDRESS_V4, MDNS_PORT).into(),
                if_addrs::IfAddr::V6(_) => SocketAddrV6::new(
                    MDNS_ADDRESS_V6,
                    MDNS_PORT,
                    0,
                    zeroconfig_io.interface.index.unwrap_or(0),
                )
                .into(),
            };

            let res = zeroconfig_io.socket.send_to(query, addr);
            if res.is_err() {
                log::error!("Failed to send query to zero socket {res:?}");
                continue;
            }
        }
        Ok(())
    }

    fn new_socket(addr: SocketAddr) -> Result<Socket> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;

        // Play nice with other mDNS daemon that may be running on this machine.
        // Let's all share the same port.
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        // We are going to run a select() on these so let's make them non-blocking
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        Ok(socket)
    }

    fn create_socket(interface: &Interface) -> Result<UdpSocket> {
        let ip_address = &interface.ip();
        match ip_address {
            IpAddr::V4(ip) => {
                let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
                let sock = ZeroConfigDriver::new_socket(addr.into())?;
                sock.join_multicast_v4(&MDNS_ADDRESS_V4, ip)?;
                sock.set_multicast_if_v4(ip)?;
                Ok(UdpSocket::from_std(net::UdpSocket::from(sock)))
            }
            IpAddr::V6(_) => {
                let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
                let sock = ZeroConfigDriver::new_socket(addr.into())?;
                sock.join_multicast_v6(&MDNS_ADDRESS_V6, interface.index.unwrap_or(0))?;
                sock.set_multicast_if_v6(interface.index.unwrap_or(0))?;
                Ok(UdpSocket::from_std(net::UdpSocket::from(sock)))
            }
        }
    }

    fn create_sockets(&mut self) -> Result<()> {
        let all_interfaces: Vec<Interface> = if_addrs::get_if_addrs().unwrap_or_default();
        debug!("Create socket found interfaces:");
        for intf in &all_interfaces {
            debug!("{intf:?}");
        }

        let ifs: Vec<Interface> = all_interfaces
            .into_iter()
            .filter(|i| !i.is_loopback() && !i.is_link_local() && i.is_oper_up())
            .collect();

        self.io.clear();
        for interface in ifs {
            let Ok(socket) = ZeroConfigDriver::create_socket(&interface) else {
                warn!("Unable to create socket for interface {interface:?}");
                continue;
            };
            debug!("Created socket {socket:?} on interface {interface:?}");
            self.io.push(ZeroConfigIO { interface, socket });
        }
        Ok(())
    }

    fn process_packet(&mut self, packet: Packet) {
        self.zero_config.push_records(
            packet.questions,
            packet.answers,
            packet.additional_records,
            packet.name_servers,
        );
    }

    fn handle_socket_readable(&mut self, socket_id: usize) {
        let mut buf = [0u8; 65535];
        // Poll is ET (Edge-Triggered), we need to drain the socket buffer until it is empty.
        loop {
            match self.io[socket_id].socket.recv(&mut buf) {
                Ok(len) => match Packet::parse(&buf[..len]) {
                    Ok(packet) => {
                        self.process_packet(packet);
                    }
                    Err(e) => {
                        error!("Error parsing packet {e}");
                    }
                },
                Err(e) => {
                    if e.kind() != WouldBlock {
                        error!("Error in receiving on ZeroConfigDriverChannelReceiver: {e}");
                    }
                    break;
                }
            }
        }
    }

    fn process_events(&mut self, events: &Events) -> Duration {
        self.zero_config.set_time(Instant::now());

        for event in events.iter() {
            if !event.is_readable() {
                continue;
            }

            // This is the interrupt socket. We have command waiting to be processed in the
            // command_channel.
            if event.token() == COMMAND_CHANNEL_TOKEN {
                let commands = self.command_channel.recv();
                for command in &commands {
                    self.process_command(command);
                }
                continue;
            }

            self.handle_socket_readable(event.token().0 - 1);
        }

        let (commands, next_attention) = self.zero_config.tick();
        for command in commands {
            self.process_command(&command);
        }

        next_attention
    }

    fn run(&mut self) -> Result<()> {
        debug!("ZeroConfigDriver starting...");
        self.running = true;
        self.create_sockets()?;

        self.zero_config.set_time(Instant::now());
        self.zero_config.on_start();

        // Register all network interfaces
        for (index, interface) in self.io.iter_mut().enumerate() {
            self.poll.registry().register(
                &mut interface.socket,
                mio::Token(index + 1),
                mio::Interest::READABLE,
            )?;
        }

        let mut events = Events::with_capacity(self.io.len() + 1);
        let mut timeout: Duration = Duration::from_millis(0);
        while self.running {
            timeout = timeout.clamp(Duration::from_millis(300), Duration::from_secs(120));
            debug!("ZeroConfigDriver polling with timeout={}ms", timeout.as_millis());
            self.poll.poll(&mut events, Some(timeout))?;
            timeout = self.process_events(&events);
        }

        self.zero_config.set_time(Instant::now());
        for command in self.zero_config.on_stop() {
            self.process_command(&command);
        }

        debug!("ZeroConfigDriver stopping...");
        Ok(())
    }

    pub fn run_forever(mut self) {
        loop {
            match self.run() {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn process_command(&mut self, command: &ZeroConfigCommand) {
        log::debug!("Processing command {command:?}");
        match command {
            DnsQueries { questions } => {
                let mut packet = Packet::new_query(0);
                for question in questions {
                    let Ok(name) = Name::new(question.name.as_str()) else {
                        warn!("Query {question:?} cannot be made into a name");
                        return;
                    };

                    let question = Question::new(name, question.qtype, question.qclass, false);
                    packet.questions.push(question.clone());
                }
                let Ok(query) = packet.build_bytes_vec() else {
                    warn!("Unable to build query for {questions:?}");
                    return;
                };

                let res = self.send_query(&query);
                if res.is_err() {
                    warn!("Error sending query {questions:?} {res:?}");
                }
            }
            CreateService { instance_name, service_type, hostname, ipv4s, ipv6s, port, txt } => {
                send_update(
                    AdbMdnsUpdate::Create,
                    instance_name,
                    service_type,
                    hostname,
                    ipv4s,
                    ipv6s,
                    *port,
                    txt,
                )
            }
            UpdateService { instance_name, service_type, hostname, ipv4s, ipv6s, port, txt } => {
                send_update(
                    AdbMdnsUpdate::Update,
                    instance_name,
                    service_type,
                    hostname,
                    ipv4s,
                    ipv6s,
                    *port,
                    txt,
                )
            }
            DeleteService { instance_name, service_type } => send_update(
                AdbMdnsUpdate::Delete,
                instance_name,
                service_type,
                "",
                &HashSet::new(),
                &HashSet::new(),
                0,
                &TxtAttributes::new(),
            ),
            Restart {} => {
                self.running = false;
            }
        }
    }
}

#[cfg(test)]
mod packet_fixture_tests {
    use super::*;
    use simple_dns::rdata::{A, AAAA, PTR, RData, SRV, TXT};
    use simple_dns::{CLASS, Name, Packet, ResourceRecord};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    #[test]
    fn dns_packet_fixture_ptr_srv_a_aaaa_txt_reaches_service_create_event() {
        let service_type = "_adb-tls-connect._tcp";
        let service_domain = "_adb-tls-connect._tcp.local";
        let instance = "adb-SERIAL-9._adb-tls-connect._tcp.local";
        let host = "device-9.local";
        let ipv4 = Ipv4Addr::new(192, 168, 50, 9);
        let ipv6 = Ipv6Addr::LOCALHOST;
        let port = 5555;

        let mut txt = TXT::new();
        txt.add_string("serial=SERIAL-9").unwrap();
        txt.add_string("model=fixture-model").unwrap();

        // Deterministic mDNS response packet with the full DNS-SD record
        // chain. Serialize and parse it so this test covers actual wire
        // decoding before passing sections through ZeroConfigDriver.
        let mut packet = Packet::new_reply(0);
        packet.answers = vec![
            ResourceRecord::new(
                Name::new_unchecked(service_domain),
                CLASS::IN,
                120,
                RData::PTR(PTR(Name::new_unchecked(instance))),
            ),
            ResourceRecord::new(
                Name::new_unchecked(instance),
                CLASS::IN,
                120,
                RData::SRV(SRV {
                    priority: 0,
                    weight: 0,
                    port,
                    target: Name::new_unchecked(host),
                }),
            ),
            ResourceRecord::new(
                Name::new_unchecked(host),
                CLASS::IN,
                120,
                RData::A(A::from(ipv4)),
            ),
            ResourceRecord::new(
                Name::new_unchecked(host),
                CLASS::IN,
                120,
                RData::AAAA(AAAA::from(ipv6)),
            ),
            ResourceRecord::new(
                Name::new_unchecked(instance),
                CLASS::IN,
                120,
                RData::TXT(txt),
            ),
        ];
        let raw = packet.build_bytes_vec().unwrap();
        let parsed = Packet::parse(&raw).unwrap();
        assert_eq!(parsed.answers.len(), 5);

        let (_sender, receiver) = crate::zero_config_driver_channel::new().unwrap();
        let mut driver = ZeroConfigDriver::new(ZeroConfig::new(), receiver).unwrap();
        driver.zero_config.set_time(Instant::now());
        driver.process_packet(parsed);
        let (commands, _) = driver.zero_config.tick();

        assert_eq!(commands.len(), 1, "expected one CreateService event: {commands:?}");
        match &commands[0] {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type: actual_type,
                hostname,
                ipv4s,
                ipv6s,
                port: actual_port,
                txt: attributes,
            } => {
                assert_eq!(instance_name, "adb-SERIAL-9");
                assert_eq!(actual_type, service_type);
                assert_eq!(hostname, host);
                assert!(ipv4s.contains(&ipv4));
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(*actual_port, port);
                assert_eq!(attributes.get("serial").map(String::as_str), Some("SERIAL-9"));
                assert_eq!(attributes.get("model").map(String::as_str), Some("fixture-model"));
            }
            other => panic!("expected CreateService, got {other:?}"),
        }
    }
}
