# Public TLS test identities

`public-rsa2048-host.pem` and `public-rsa2048-host-spki.b64` are the already-public RustCrypto `rsa` 0.9.10 fixtures `tests/examples/pkcs8/rsa2048-priv.pem` and `rsa2048-pub.der` (MIT OR Apache-2.0). The base64 file preserves the original public DER vector.

The independent fake-adbd server uses the already-vendored BoringSSL `crypto/x509/x509_test.cc` documented `kCRLTestRoot` private key. Neither identity is generated from, reads, or represents a user's credentials. NEVER use these publicly known private keys outside disposable tests.

Certificate creation uses production rcgen; authorization independently parses the actual certificate's checked DER SubjectPublicKeyInfo and compares its complete canonical DER to RSA/PKCS#8 public-key encoding of the persisted host fixture. A pinned upstream SPKI vector also checks this oracle, so producer and oracle do not share an encoder.
