//! AOSP pairing server for testing and peer acceptance,
//! mirroring `vendor/adb/pairing_connection/pairing_server.cpp`.

use std::io::{Read, Write};

use crate::pairing::{
    PairingError, PairingPacket, PairingPacketType, PeerInfo, validate_pairing_code,
};
#[cfg(not(feature = "pairing-vendored"))]
use crate::pairing_auth::{PairingCipher, Spake2, SpakeRole};
#[cfg(feature = "pairing-vendored")]
use crate::pairing_auth::{PairingAuth, PairingRole};

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
        self.execute_pairing_with_exported_keys(transport, None)
    }

    pub fn execute_pairing_with_exported_keys<T: Read + Write>(
        &mut self,
        transport: &mut T,
        exported_key_material: Option<&[u8]>,
    ) -> Result<PeerInfo, PairingError> {
        // AOSP pairing_connection.cpp: exporter is appended to the password
        // before SPAKE (mirrors the client-side binding).
        let mut pswd = self.code.clone().into_bytes();
        if let Some(exported) = exported_key_material {
            pswd.extend_from_slice(exported);
        }
        #[cfg(not(feature = "pairing-vendored"))]
        let mut spake = Spake2::new(
            SpakeRole::Bob,
            b"adb pair server\0",
            b"adb pair client\0",
            &pswd,
        );
        #[cfg(feature = "pairing-vendored")]
        let mut auth = PairingAuth::new(PairingRole::Server, &pswd)?;

        #[cfg(not(feature = "pairing-vendored"))]
        let my_spake_msg = spake.generate_msg()?;
        #[cfg(feature = "pairing-vendored")]
        let my_spake_msg = auth.msg();

        let peer_packet = PairingPacket::read_from(transport)?;
        if peer_packet.packet_type != PairingPacketType::Spake2Msg {
            return Err(PairingError::InvalidHeader("expected Spake2Msg".into()));
        }

        let out_packet = PairingPacket::new(PairingPacketType::Spake2Msg, my_spake_msg)?;
        out_packet.write_to(transport)?;

        #[cfg(not(feature = "pairing-vendored"))]
        let mut cipher = {
            let spake_key = spake.process_msg(&peer_packet.payload)?;
            PairingCipher::from_spake2_key(&spake_key)?
        };
        #[cfg(feature = "pairing-vendored")]
        let mut cipher = {
            if !auth.init_cipher(&peer_packet.payload)? {
                return Err(PairingError::Crypto(
                    "SPAKE2 password mismatch (pairing_auth_init_cipher=false)".into(),
                ));
            }
            auth
        };

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
