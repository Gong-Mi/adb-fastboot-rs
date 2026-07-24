//! AOSP pairing server for testing and peer acceptance,
//! mirroring `vendor/adb/pairing_connection/pairing_server.cpp`.

use std::io::{Read, Write};

use crate::pairing::{
    PairingError, PairingPacket, PairingPacketType, PeerInfo, validate_pairing_code,
};
use crate::pairing_auth::{PairingCipher, Spake2, SpakeRole};

/// AOSP pairing server implementation (for testing and peer acceptance).
pub struct PairingServer {
    code: String,
    local_info: PeerInfo,
}

impl PairingServer {
    pub fn new(code: &str, local_info: PeerInfo) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            local_info,
        })
    }

    pub fn execute_pairing<T: Read + Write>(
        &mut self,
        transport: &mut T,
    ) -> Result<PeerInfo, PairingError> {
        let mut spake = Spake2::new(
            SpakeRole::Bob,
            b"adb pair server",
            b"adb pair client",
            &self.code,
        );

        let my_spake_msg = spake.generate_msg()?;

        let peer_packet = PairingPacket::read_from(transport)?;
        if peer_packet.packet_type != PairingPacketType::Spake2Msg {
            return Err(PairingError::InvalidHeader("expected Spake2Msg".into()));
        }

        let out_packet = PairingPacket::new(PairingPacketType::Spake2Msg, my_spake_msg)?;
        out_packet.write_to(transport)?;

        let spake_key = spake.process_msg(&peer_packet.payload)?;
        let mut cipher = PairingCipher::from_spake2_key(&spake_key)?;

        let peer_info_packet = PairingPacket::read_from(transport)?;
        if peer_info_packet.packet_type != PairingPacketType::PeerInfo {
            return Err(PairingError::InvalidHeader("expected PeerInfo".into()));
        }

        let decrypted_peer_bytes = cipher.decrypt(&peer_info_packet.payload)?;
        let peer_info = PeerInfo::deserialize(&decrypted_peer_bytes)?;

        let local_bytes = self.local_info.serialize()?;
        let encrypted_local = cipher.encrypt(&local_bytes)?;
        let out_peer_packet = PairingPacket::new(PairingPacketType::PeerInfo, encrypted_local)?;
        out_peer_packet.write_to(transport)?;

        Ok(peer_info)
    }
}
