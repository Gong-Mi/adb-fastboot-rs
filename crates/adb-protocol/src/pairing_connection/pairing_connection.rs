//! AOSP pairing connection client, mirroring `vendor/adb/pairing_connection/pairing_connection.cpp`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rsa::RsaPrivateKey;

use crate::pairing::{
    PairingError, PairingPacket, PairingPacketType, PeerInfo, validate_pairing_code,
};
use crate::pairing_auth::{PairingCipher, Spake2, SpakeRole};

/// Paired ADB Keystore Certificate Persistence.
#[derive(Debug, Clone)]
pub struct AdbKeystore {
    pub private_key_pem: String,
    pub public_key_string: String,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
}

/// Save ADB keystore (private key PEM and public key string) to disk.
pub fn save_adb_keystore(
    private_key: &RsaPrivateKey,
    label: &str,
    dir_path: &Path,
) -> Result<AdbKeystore, PairingError> {
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)?;
    }

    let private_key_pem = crate::crypto::key::export_private_key_to_pem(private_key)
        .map_err(|e| PairingError::Crypto(e.to_string()))?;

    let public_key_bytes =
        crate::crypto::rsa_2048_key::encode_adb_public_key_string(
            &private_key.to_public_key(),
            label,
        )
        .map_err(|e| PairingError::Crypto(e.to_string()))?;
    let public_key_string = String::from_utf8_lossy(&public_key_bytes).into_owned();

    let private_key_path = dir_path.join("adbkey");
    let public_key_path = dir_path.join("adbkey.pub");

    std::fs::write(&private_key_path, &private_key_pem)?;
    std::fs::write(&public_key_path, &public_key_string)?;

    Ok(AdbKeystore {
        private_key_pem,
        public_key_string,
        private_key_path,
        public_key_path,
    })
}

/// AOSP pairing client implementation.
pub struct PairingClient {
    code: String,
    peer_info: Option<PeerInfo>,
    rsa_key: Option<RsaPrivateKey>,
}

impl PairingClient {
    pub fn new(code: &str) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            peer_info: None,
            rsa_key: None,
        })
    }

    pub fn with_rsa_key(code: &str, rsa_key: RsaPrivateKey) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            peer_info: None,
            rsa_key: Some(rsa_key),
        })
    }

    pub fn with_peer_info(code: &str, peer_info: PeerInfo) -> Result<Self, PairingError> {
        validate_pairing_code(code)?;
        Ok(Self {
            code: code.trim().to_owned(),
            peer_info: Some(peer_info),
            rsa_key: None,
        })
    }

    pub fn pairing_code(&self) -> &str {
        &self.code
    }

    pub fn peer_info(&self) -> Option<&PeerInfo> {
        self.peer_info.as_ref()
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
        let mut spake = Spake2::new(
            SpakeRole::Alice,
            b"adb pair client",
            b"adb pair server",
            &self.code,
        );

        let my_spake_msg = spake.generate_msg()?;
        let out_packet = PairingPacket::new(PairingPacketType::Spake2Msg, my_spake_msg)?;
        out_packet.write_to(transport)?;

        let peer_packet = PairingPacket::read_from(transport)?;
        if peer_packet.packet_type != PairingPacketType::Spake2Msg {
            return Err(PairingError::InvalidHeader(format!(
                "expected Spake2Msg packet, got {:?}",
                peer_packet.packet_type
            )));
        }

        let spake_key = spake.process_msg(&peer_packet.payload)?;
        let mut cipher =
            PairingCipher::from_spake2_and_exported_key(&spake_key, exported_key_material)?;

        let rsa_key = match &self.rsa_key {
            Some(k) => k.clone(),
            None => crate::crypto::key::generate_rsa_key()
                .map_err(|e| PairingError::Crypto(e.to_string()))?,
        };

        let local_info = match &self.peer_info {
            Some(info) => info.clone(),
            None => {
                let pubkey_bytes =
                    crate::crypto::rsa_2048_key::encode_adb_public_key_string(
                        &rsa_key.to_public_key(),
                        "adb-pairing",
                    )
                    .map_err(|e| PairingError::Crypto(e.to_string()))?;
                let pubkey_str = String::from_utf8_lossy(&pubkey_bytes);
                PeerInfo::from_rsa_pubkey(&pubkey_str)
            }
        };

        let local_bytes = local_info.serialize()?;
        let encrypted_local = cipher.encrypt(&local_bytes)?;

        let out_peer_packet = PairingPacket::new(PairingPacketType::PeerInfo, encrypted_local)?;
        out_peer_packet.write_to(transport)?;

        let peer_info_packet = PairingPacket::read_from(transport)?;
        if peer_info_packet.packet_type != PairingPacketType::PeerInfo {
            return Err(PairingError::InvalidHeader(format!(
                "expected PeerInfo packet, got {:?}",
                peer_info_packet.packet_type
            )));
        }

        let decrypted_peer_bytes = cipher.decrypt(&peer_info_packet.payload)?;
        let peer_info = PeerInfo::deserialize(&decrypted_peer_bytes)?;

        let home_dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let adb_dir = home_dir.join(".android");
        let _ = save_adb_keystore(&rsa_key, "adb-pairing", &adb_dir);

        self.peer_info = Some(peer_info.clone());
        Ok(peer_info)
    }
}
