pub(crate) use adb_protocol::{tls, A_CNXN, A_OPEN, A_STLS, A_STLS_VERSION};
pub(crate) use std::io::{Read, Write};
pub(crate) use std::net::{TcpListener, TcpStream};
pub(crate) use std::path::PathBuf;
pub(crate) use std::process::{Command, Output, Stdio};
pub(crate) use std::sync::{Arc, OnceLock};
pub(crate) use std::thread;
pub(crate) use std::time::{Duration, Instant};

pub(crate) const TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const BANNER: &[u8] = b"device::features=cmd,shell_v2\0";

pub(crate) fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

// Intentionally independent of the production Transport codec.
pub(crate) fn recv_frame(
    io: &mut (impl Read + ?Sized),
) -> std::io::Result<(u32, u32, u32, Vec<u8>)> {
    let mut header = [0; 24];
    io.read_exact(&mut header)?;
    let command = word(&header);
    assert_eq!(word(&header[20..]), command ^ u32::MAX, "ADB magic");
    let length = word(&header[12..]) as usize;
    assert!(length <= 1024 * 1024, "bounded ADB payload");
    let mut payload = vec![0; length];
    io.read_exact(&mut payload)?;
    let checksum: u32 = payload.iter().map(|&byte| u32::from(byte)).sum();
    assert!(
        word(&header[16..]) == 0 || word(&header[16..]) == checksum,
        "ADB checksum"
    );
    Ok((command, word(&header[4..]), word(&header[8..]), payload))
}

pub(crate) fn send_frame(io: &mut (impl Write + ?Sized), command: u32, arg0: u32, payload: &[u8]) {
    send_stream_frame(io, command, arg0, 0, payload)
}

pub(crate) fn send_stream_frame(
    io: &mut (impl Write + ?Sized),
    command: u32,
    arg0: u32,
    arg1: u32,
    payload: &[u8],
) {
    for field in [
        command,
        arg0,
        arg1,
        payload.len() as u32,
        payload.iter().map(|&b| u32::from(b)).sum(),
        command ^ u32::MAX,
    ] {
        io.write_all(&field.to_le_bytes()).unwrap();
    }
    io.write_all(payload).unwrap();
    io.flush().unwrap();
}

// Already-public fixtures only; see fixtures/TLS_IDENTITIES.md.
pub(crate) const HOST_PEM: &str = include_str!("../fixtures/public-rsa2048-host.pem");

pub(crate) fn public_spki(pem: &str) -> Vec<u8> {
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).unwrap();
    key.to_public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

pub(crate) fn server_identity() -> &'static (Vec<u8>, Vec<u8>, String) {
    static IDENTITY: OnceLock<(Vec<u8>, Vec<u8>, String)> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        let source = include_str!("../../../../vendor/boringssl/crypto/x509/x509_test.cc");
        let (_, note) = source
            .split_once("// kCRLTestRoot is a test root certificate. It has private key:")
            .unwrap();
        let begin = concat!("-----BEGIN ", "RSA PRIVATE KEY-----");
        let end = concat!("-----END ", "RSA PRIVATE KEY-----");
        let mut pem = String::new();
        for line in note.lines().filter_map(|line| line.strip_prefix("//     ")) {
            if line == begin || !pem.is_empty() {
                pem.push_str(line);
                pem.push('\n');
            }
            if line == end {
                break;
            }
        }
        let pem = rsa::RsaPrivateKey::from_pkcs1_pem(&pem)
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        assert_ne!(
            public_spki(HOST_PEM),
            public_spki(&pem),
            "independent host/server keys"
        );
        let (cert, key) = tls::generate_self_signed_cert(&pem).unwrap();
        (cert, key, pem)
    })
}

// Checked, definite-length DER reader. No rcgen/production cert parser or
// byte search: follow Certificate -> TBSCertificate -> SubjectPublicKeyInfo.
pub(crate) fn der_item<'a>(
    input: &mut &'a [u8],
    tag: u8,
) -> Result<(&'a [u8], &'a [u8]), &'static str> {
    let whole = *input;
    if whole.len() < 2 || whole[0] != tag {
        return Err("DER tag/truncated header");
    }
    let (header, length) = if whole[1] < 128 {
        (2usize, usize::from(whole[1]))
    } else {
        let count = usize::from(whole[1] & 0x7f);
        if count == 0
            || count > std::mem::size_of::<usize>()
            || whole.len() < 2 + count
            || whole[2] == 0
        {
            return Err("DER invalid length");
        }
        let mut length = 0usize;
        for byte in &whole[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or("DER length overflow")?;
        }
        if length < 128 {
            return Err("DER nonminimal length");
        }
        (2 + count, length)
    };
    let end = header.checked_add(length).ok_or("DER length overflow")?;
    if end > whole.len() {
        return Err("DER truncated value");
    }
    *input = &whole[end..];
    Ok((&whole[..end], &whole[header..end]))
}

pub(crate) fn certificate_spki(cert: &[u8]) -> Result<&[u8], &'static str> {
    let mut outer = cert;
    let (_, mut certificate) = der_item(&mut outer, 0x30)?;
    if !outer.is_empty() {
        return Err("DER trailing certificate bytes");
    }
    let (_, mut tbs) = der_item(&mut certificate, 0x30)?;
    der_item(&mut certificate, 0x30)?; // signature algorithm
    der_item(&mut certificate, 0x03)?; // signature
    if !certificate.is_empty() {
        return Err("DER trailing certificate fields");
    }
    if tbs.first() == Some(&0xa0) {
        let (_, mut version) = der_item(&mut tbs, 0xa0)?;
        der_item(&mut version, 0x02)?;
        if !version.is_empty() {
            return Err("DER invalid version");
        }
    }
    der_item(&mut tbs, 0x02)?; // serial
    for _ in 0..4 {
        der_item(&mut tbs, 0x30)?;
    } // signature, issuer, validity, subject
    let (spki, _) = der_item(&mut tbs, 0x30)?;
    // Independent RSA parser validates the complete SPKI, OID, bit string,
    // modulus/exponent and consumption rather than accepting arbitrary DER.
    use rsa::pkcs8::DecodePublicKey;
    rsa::RsaPublicKey::from_public_key_der(spki).map_err(|_| "DER invalid RSA SPKI")?;
    Ok(spki)
}

#[derive(Debug)]
pub(crate) struct RequireClientCertificate {
    pub(crate) reject: bool,
    pub(crate) authorized_spki: Vec<u8>,
}
impl rustls::server::danger::ClientCertVerifier for RequireClientCertificate {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let actual = certificate_spki(cert.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        // AOSP daemon/auth.cpp:341-384 extracts X509_get_pubkey and compares
        // with the stored authorized RSA pubkey (EVP_PKEY_cmp), not signature
        // possession alone. Canonical RSA SPKI here must match in its entirety.
        if self.reject || actual != self.authorized_spki {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Identity authorization and CertificateVerify proof are independent.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("fixture requires TLS 1.3".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn server_config() -> Arc<rustls::ServerConfig> {
    client_auth_server_config(false)
}

pub(crate) fn client_auth_server_config(reject: bool) -> Arc<rustls::ServerConfig> {
    server_config_for(reject, public_spki(HOST_PEM))
}

pub(crate) fn server_config_for(
    reject: bool,
    authorized_spki: Vec<u8>,
) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cert, key, _) = server_identity();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(RequireClientCertificate {
            reject,
            authorized_spki,
        }))
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.clone())),
        )
        .unwrap(),
    )
}

pub(crate) fn accept_stls(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "CLI never connected");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept: {error}"),
        }
    };
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    let (command, _, _, payload) = recv_frame(&mut socket).unwrap();
    assert_eq!(command, A_CNXN, "initial plaintext host CNXN");
    assert!(payload.starts_with(b"host::"));
    send_frame(&mut socket, A_STLS, A_STLS_VERSION, &[]);
    // Check the first four bytes before decoding: a ClientHello in place of
    // this reply is the missing-host-STLS regression, not a TLS setup error.
    let mut command = [0; 4];
    socket.read_exact(&mut command).expect("host STLS reply");
    assert_eq!(
        &command, b"STLS",
        "host must reply STLS before TLS ClientHello"
    );
    let mut rest = [0; 20];
    socket.read_exact(&mut rest).unwrap();
    assert_eq!(word(&rest), A_STLS_VERSION);
    assert_eq!(word(&rest[4..]), 0, "STLS arg1");
    assert_eq!(word(&rest[8..]), 0, "STLS has no payload");
    assert_eq!(word(&rest[12..]), 0, "empty STLS checksum");
    assert_eq!(word(&rest[16..]), A_STLS ^ u32::MAX);
    socket
}

pub(crate) struct Home(pub(crate) PathBuf);
impl Home {
    pub(crate) fn new(tag: &str) -> Self {
        Self::with_pem(tag, HOST_PEM)
    }
    pub(crate) fn with_pem(tag: &str, pem: &str) -> Self {
        let path = std::env::temp_dir().join(format!("adb-stls-{tag}-{}", std::process::id()));
        let android = path.join(".android");
        std::fs::create_dir_all(&android).unwrap();
        // Public test-only fixture, never read from the user's HOME.
        // Preload it so RSA generation is outside socket/CLI deadlines.
        pub(crate) use std::os::unix::fs::OpenOptionsExt;
        let mut key = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(android.join("adbkey"))
            .unwrap();
        key.write_all(pem.as_bytes()).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
