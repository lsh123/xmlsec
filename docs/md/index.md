# XML Security Library

XML Security Library is a C library based on [LibXML2](http://xmlsoft.org/).
The library supports major XML security standards:

- [XML Signature](xmldsig.md)
- [XML Encryption](xmlenc.md)
- [Canonical XML](http://www.w3.org/TR/xml-c14n) (part of [LibXML2](http://xmlsoft.org/))
- [Exclusive Canonical XML](http://www.w3.org/TR/xml-exc-c14n) (part of [LibXML2](http://xmlsoft.org/))

XML Security Library is released under the
[MIT Licence](http://www.opensource.org/licenses/mit-license.html);
see the Copyright file in the distribution for details.

## News

- **TODO**
  The [XML Security Library 1.3.11](download.md) release includes the following changes:
  - (xmlsec-docs) The XMLSec API reference, tutorial, and examples have been updated to Markdown files and moved to
    [GitHub Wiki](https://github.com/lsh123/xmlsec/wiki).

- **April 2, 2026**
  The [XML Security Library 1.3.10](download.md) release includes the following changes:
  - The minimum supported versions for dependencies are now: LibXML2 >= 2.9.13 (February 19, 2022), LibXSLT >= 1.1.35 (February 16, 2022),
    OpenSSL >= 3.0.13 (January 30, 2024), LibreSSL >= 3.9.0 (March 9, 2024), NSS >= 3.91 (June 26, 2023), NSPR >= 4.34.1 (June 26, 2023),
    GnuTLS >= 3.8.3 (January 1, 2024).
  - (xmlsec-core) Disabled all key value data for all key types by default (use `--enabled-key-data` flag to re-enable if needed).
  - (xmlsec-core) Added `--enable-asn1-signatures-hack` option to allow generation / verification of ASN1 signature values.
  - (xmlsec-core) Added `--verify-crls` option to verify CRLs when loading from command line.
  - (xmlsec-openssl) Added support for EdDSA signature algorithm; XDH (X25519 and X448) key agreement algorithms;
    HKDF key derivation algorithm; Camellia block cipher and key wrap algorithms; ChaCha20 and ChaCha20-Poly1305 encryption algorithms;
    and **experimental** ML-DSA and SLH-DSA-SHA2 signature algorithms.
  - (xmlsec-gnutls) Added support for EdDSA signature algorithms; ECDH and XDH (X25519 and X448) key agreement algorithms;
    ConcatKDF, PBKDF2, and HKDF key derivation algorithms; ChaCha20 and ChaCha20-Poly1305 encryption algorithms;
    SHA2-224 and SHA3-224 digest algorithms; and **experimental** support for ML-DSA signature algorithms.
  - (xmlsec-nss) Added support for EdDSA (Ed25519) signature algorithms; ECDH and XDH (X25519) key agreement algorithms;
    ConcatKDF and HKDF key derivation algorithms; and ChaCha20-Poly1305 encryption algorithm.
    Camellia block cipher and key wrap algorithms.
  - (xmlsec-mscng) Added support for DSA-SHA256 signature algorithm; XDH (X25519) and DH (X9.42 DHX) key agreement algorithms;
    HKDF key derivation algorithm; and SHA3 digest algorithms.
  - (xmlsec-mscng) Added support for loading CRLs from command line.
  - (xmlsec-test) Created scripts to generate keys, regenerated all keys with standard names, and updated tests accordingly.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/xmlsec_1_3_10)).

- **November 10, 2025**
  The [XML Security Library 1.3.9](download.md) release includes the following changes:
  - (xmlsec-openssl) Added pub/priv key type check for EC and DH keys; improved non-memory EVP keys detection.
  - (xmlsec-openssl) Fixed memory leak in X509 certs verification code.
  - (xmlsec-openssl) Added octet parser in X509 names.
  - (xmlsec-mscng) Added support for non-persistent PKCS12 keys.
  - (xmlsec-windows) Simplified windows build and removed `with-dl` option for `configure.js`.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- **October 15, 2025**
  The [XML Security Library 1.3.8](download.md) release includes the following changes:
  - (xmlsec-openssl) Deprecated support for OpenSSL 1.1.1 ([reached its End of Life in September, 2023](https://openssl-corporation.org/post/2023-09-11-eol-111/)).
  - (xmlsec-openssl) Added AWS-LC support.
  - (xmlsec-openssl, xmlsec-gnutls, xmlsec-mscng) Added support for longer than expected DSA and ECDSA signatures to support broken Java implementations.
  - (xmlsec command line tool) Added option `--add-id-attr` to add ID attributes by name to all nodes in the document.
  - (xmlsec-core) Added RSA MGF1 and digest template API.
  - (xmlsec-core) Added example of signing / verifying signature by ID attribute.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- **June 16, 2025**
  The legacy [XML Security Library 1.2.42](download.md) release includes the following changes:
  - (xmlsec-openssl) Ensured that only certificates from XML file are returned after verification.
  - (xmlsec-core) Fixed includes to support latest LibXML2 / LibXSLT.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

- **February 11, 2025**
  The [XML Security Library 1.3.7](download.md) release includes the following changes:
  - (xmlsec-core) Added `XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED` flag to `xmlSecTransform` to differentiate transforms specified in the input XML file vs transforms automatically added by XMLSec library.
  - (xmlsec-core) Added signature result verification to the examples to demonstrate the need to ensure the correct data is actually signed.
  - (xmlsec-core) Disabled old crypto algorithms (MD5, RIPEMD160) and the old crypto engines (MSCrypto, GCrypt) by default (use `--with-legacy-features` option to reenable everything).
  - (xmlsec-openssl) Fixed excess padding in ECDSA signature generation.
  - (xmlsec-openssl) Fixed build warnings for BoringSSL / AWS-LC.
  - (xmlsec-nss) Fixed certificates search in NSS DB.
  - (xmlsec-openssl, xmlsec-gnutls, xmlsec-mscng) Added an option to skip timestamp checks for certificates and CLRs.
  - (xmlsec-windows) Disabled old crypto algorithms (MD5, RIPEMD160), made "mscng" the default crypto engine on Windows, and added support for "legacy-features" flag for `configure.js`.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- **October 22, 2024**
  The [XML Security Library 1.3.6](download.md) release includes the following changes:
  - (xmlsec-openssl) Fixed build if OpenSSL 3.0 doesn't have engines support enabled.
  - (xmlsec-mscng, xmlsec-mscrypto) Added support for multiple trusted certs with the same subject.
  - (windows) Disabled iconv support by default (use `iconv=yes` option for `configure.js` to re-enable it).
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- **July 19, 2024**
  The [XML Security Library 1.3.5 and legacy 1.2.41](download.md) releases include the following changes:
  - (xmlsec-mscng, xmlsec-mscrypto) Improved certificates verification.
  - (xmlsec-gnutls) Added support for self-signed certificates.
  - (xmlsec-core) Fix deprecated functions in LibXML2 2.13.1 including disabling HTTP support
    by default (use `--enable-http` option to re-enable it).
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

[News page](news.md)
