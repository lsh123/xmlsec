# XML Security Library: XML Digital Signature Interoperability Report

XML Security library supports the following features as defined in
[XML Signature Syntax and Processing 1.1](https://www.w3.org/TR/xmldsig-core1/)
(also see [RFC 9231](https://www.ietf.org/rfc/rfc9231.html)):

### XML Security Library core features

| Feature | [Requirements](https://www.w3.org/TR/xmldsig-core/#sec-AlgID) | Status |
|---|---|---|
| **Processing rules** | | |
| [Reference Generation](https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceGeneration) | Required | Yes |
| [Signature Generation](https://www.w3.org/TR/xmldsig-core1/#sec-SignatureGeneration) | Required | Yes |
| [Reference Validation](https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceValidation) | Required | Yes |
| [Signature Validation](https://www.w3.org/TR/xmldsig-core1/#sec-SignatureValidation) | Required | Yes |
| **Syntax** | | |
| [The ds:CryptoBinary Simple Type](https://www.w3.org/TR/xmldsig-core1/#sec-CryptoBinary) | Required | Yes |
| [The Signature Element](https://www.w3.org/TR/xmldsig-core1/#sec-Signature) | Required | Yes |
| [The SignatureValue Element](https://www.w3.org/TR/xmldsig-core1/#sec-SignatureValue) | Required | Yes |
| [The SignedInfo Element](https://www.w3.org/TR/xmldsig-core1/#sec-SignedInfo) | Required | Yes |
| [The CanonicalizationMethod Element](https://www.w3.org/TR/xmldsig-core1/#sec-CanonicalizationMethod) | Required | Yes |
| [The SignatureMethod Element](https://www.w3.org/TR/xmldsig-core1/#sec-SignatureMethod) | Required | Yes |
| [The Reference Element](https://www.w3.org/TR/xmldsig-core1/#sec-Reference) | Required | Yes |
| [The Reference Element: URI Attribute](https://www.w3.org/TR/xmldsig-core1/#sec-URI) | Required | Yes |
| [The Transforms Element](https://www.w3.org/TR/xmldsig-core1/#sec-Transforms) | Optional | Yes |
| [The DigestMethod Element](https://www.w3.org/TR/xmldsig-core1/#sec-DigestMethod) | Required | Yes |
| [The DigestValue Element](https://www.w3.org/TR/xmldsig-core1/#sec-DigestValue) | Required | Yes |
| [The KeyInfo Element](https://www.w3.org/TR/xmldsig-core1/#sec-KeyInfo) | Optional | Yes |
| [The KeyName Element](https://www.w3.org/TR/xmldsig-core1/#sec-KeyName) | Optional | Yes |
| [The KeyValue Element](https://www.w3.org/TR/xmldsig-core1/#sec-KeyValue) | Optional | Yes (disabled by default; also see [algorithms section](#algorithms)) |
| [The RetrievalMethod Element](https://www.w3.org/TR/xmldsig-core1/#sec-RetrievalMethod) | Optional | Yes |
| [The MgmtData Element](https://www.w3.org/TR/xmldsig-core1/#sec-MgmtData) | NOT RECOMMENDED and SHOULD NOT be used | Yes |
| [XML Encryption EncryptedKey and DerivedKey Elements](https://www.w3.org/TR/xmlenc-core1/#sec-Extensions-to-KeyInfo) | Optional | Yes (see [XML Encryption report](xmlenc.md)) |
| [The KeyInfoReference Element](https://www.w3.org/TR/xmldsig-core1/#sec-KeyInfoReference) | Optional | Yes |
| [The Object Element](https://www.w3.org/TR/xmldsig-core1/#sec-Object) | Optional | Yes (only the Manifest element is supported) |
| [The Manifest Element](https://www.w3.org/TR/xmldsig-core1/#sec-Manifest) | Optional | Yes |
| [The SignatureProperties Element](https://www.w3.org/TR/xmldsig-core1/#sec-SignatureProperties) | Optional | No (ignored) |
| **Transforms** | | |
| [Canonical XML 1.0 (C14N) omit comments](https://www.w3.org/TR/xmldsig-core1/#sec-Canonical) | Required | Yes |
| [Canonical XML 1.0 (C14N) with comments](https://www.w3.org/TR/xmldsig-core1/#sec-Canonical) | Recommended | Yes |
| [Canonical XML 1.1 (C14N11) omit comments](https://www.w3.org/TR/xmldsig-core1/#sec-Canonical11) | Required | Yes |
| [Canonical XML 1.1 (C14N11) with comments](https://www.w3.org/TR/xmldsig-core1/#sec-Canonical11) | Recommended | Yes |
| [Exclusive Canonical XML 1.0 (EXC-C14N) omit comments](https://www.w3.org/TR/xmldsig-core1/#sec-ExcC14N10) | Required | Yes |
| [Exclusive Canonical XML 1.0 (EXC-C14N) with comments](https://www.w3.org/TR/xmldsig-core1/#sec-ExcC14N10) | Recommended | Yes |
| [Base64 Transform](https://www.w3.org/TR/xmldsig-core1/#sec-Base-64) | Required | Yes |
| [XPath Filtering](https://www.w3.org/TR/xmldsig-core1/#sec-XPath) | Recommended | Yes |
| [XPath Filter 2.0](https://www.w3.org/TR/2002/REC-xmldsig-filter2-20021108/) | Recommended | Yes |
| [Enveloped Signature Transform](https://www.w3.org/TR/xmldsig-core1/#sec-EnvelopedSignature) | Required | Yes |
| [XSLT Transform](https://www.w3.org/TR/xmldsig-core1/#sec-XSLT) | Optional | Yes [(6)](#xslt) |
| [Decryption Transform](https://www.w3.org/TR/xmlenc-decrypt/) | Optional | Yes |
| [XPointer Transform](https://www.ietf.org/rfc/rfc9231.html#section-2.5.1) | Optional | Yes |

### XMLSec Cryptographic Libraries features

| Algorithm | [Requirements](https://www.w3.org/TR/xmldsig-core/#sec-AlgID) | XMLSec with OpenSSL | XMLSec with NSS | XMLSec with GnuTLS | XMLSec with MSCng | XMLSec with MSCrypto [(1)](#feature-disabled) | XMLSec with GCrypt [(1)](#feature-disabled) |
|---|---|---|---|---|---|---|---|
| **Message Digests** | | | | | | | |
| [SHA-1](https://www.w3.org/TR/xmldsig-core1/#sec-SHA-1) | Required (use is DISCOURAGED) | Yes | Yes | Yes | Yes | Yes | Yes |
| [SHA2-224](https://www.w3.org/TR/xmldsig-core1/#sec-SHA-224) | Optional | Yes | Yes | Yes | No | No | No |
| [SHA2-256](https://www.w3.org/TR/xmldsig-core1/#sec-SHA-256) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [SHA2-384](https://www.w3.org/TR/xmldsig-core1/#sec-SHA-384) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [SHA2-512](https://www.w3.org/TR/xmldsig-core1/#sec-SHA-512) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [SHA3-224](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms) | Optional | Yes | Yes | Yes | No | No | No |
| [SHA3-256](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms) | Optional | Yes | Yes | Yes | Yes [(2)](#new-windows-required) | No | Yes |
| [SHA3-384](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms) | Optional | Yes | Yes | Yes | Yes [(2)](#new-windows-required) | No | Yes |
| [SHA3-512](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms) | Optional | Yes | Yes | Yes | Yes [(2)](#new-windows-required) | No | Yes |
| [RIPEMD160](https://www.w3.org/TR/xmlenc-core1/#sec-RIPEMD-160) | DEPRECATED | Yes [(1)](#feature-disabled) | No | No | No | No | Yes [(1)](#feature-disabled) |
| GOST-R3411-94 | Optional | Yes [(3)](#openssl-gost) | No | Yes | No | Yes [(4)](#mscrypto-gost) | No |
| GOST-R3411-2012 (256 bit) | Optional | Yes [(3)](#openssl-gost) | No | Yes | No | Yes [(4)](#mscrypto-gost) | No |
| GOST-R3411-2012 (512 bit) | Optional | Yes [(3)](#openssl-gost) | No | Yes | No | Yes [(4)](#mscrypto-gost) | No |
| [MD5](https://www.ietf.org/rfc/rfc9231.html#section-2.1.1) | DEPRECATED | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) |
| **Message Authentication Codes** | | | | | | | |
| [HMAC-SHA1](https://www.w3.org/TR/xmldsig-core1/#sec-HMAC) | Required (use is DISCOURAGED) | Yes | Yes | Yes | Yes | Yes | Yes |
| [HMAC-SHA2-224](https://www.w3.org/TR/xmldsig-core1/#sec-HMAC) | Optional | Yes | Yes | Yes | No | Yes | No |
| [HMAC-SHA2-256](https://www.w3.org/TR/xmldsig-core1/#sec-HMAC) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [HMAC-SHA2-384](https://www.w3.org/TR/xmldsig-core1/#sec-HMAC) | Recommended | Yes | Yes | Yes | Yes | Yes | Yes |
| [HMAC-SHA2-512](https://www.w3.org/TR/xmldsig-core1/#sec-HMAC) | Recommended | Yes | Yes | Yes | Yes | Yes | Yes |
| [HMAC-RIPEMD160](https://www.ietf.org/rfc/rfc9231.html#section-2.2.3) | DEPRECATED | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | No | No | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) |
| [HMAC-MD5](https://www.ietf.org/rfc/rfc9231.html#section-2.2.1) | DEPRECATED | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | No | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) |
| **Signatures** | | | | | | | |
| [DSA-SHA1](https://www.w3.org/TR/xmldsig-core1/#sec-DSA) | Required (use is DISCOURAGED for signature generation) | Yes | Yes | Yes | Yes | Yes | Yes |
| [DSA-SHA256](https://www.w3.org/TR/xmldsig-core1/#sec-DSA) | Optional | Yes | Yes | Yes | Yes | No | No |
| [PKCS1 RSA-SHA1](https://www.w3.org/TR/xmldsig-core1/#sec-PKCS1) | Recommended (use is DISCOURAGED for signature generation) | Yes | Yes | Yes | Yes | Yes | Yes |
| [PKCS1 RSA-SHA2-224](https://www.w3.org/TR/xmldsig-core1/#sec-PKCS1) | Optional | Yes | Yes | Yes | No | No | No |
| [PKCS1 RSA-SHA2-256](https://www.w3.org/TR/xmldsig-core1/#sec-PKCS1) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [PKCS1 RSA-SHA2-384](https://www.w3.org/TR/xmldsig-core1/#sec-PKCS1) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [PKCS1 RSA-SHA2-512](https://www.w3.org/TR/xmldsig-core1/#sec-PKCS1) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [PKCS1 RSA-RIPEMD160](https://www.ietf.org/rfc/rfc9231.html#section-2.3.5) | DEPRECATED | Yes [(1)](#feature-disabled) | No | No | No | No | Yes [(1)](#feature-disabled) |
| [PKCS1 RSA-MD5](https://www.ietf.org/rfc/rfc9231.html#section-2.3.1) | DEPRECATED | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | No | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) |
| [ECDSA-RIPEMD160](https://www.ietf.org/rfc/rfc9231.html#section-2.3.6) | DEPRECATED | Yes [(1)](#feature-disabled) | No | No | No | No | No |
| [ECDSA-SHA1](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA) | Optional (use is DISCOURAGED) | Yes | Yes | Yes | Yes | No | Yes |
| [ECDSA-SHA2-224](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA) | Optional | Yes | Yes | Yes | No | No | No |
| [ECDSA-SHA2-256](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA) | Required | Yes | Yes | Yes | Yes | No | Yes |
| [ECDSA-SHA2-384](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA) | Optional | Yes | Yes | Yes | Yes | No | Yes |
| [ECDSA-SHA2-512](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA) | Optional | Yes | Yes | Yes | Yes | No | Yes |
| [ECDSA-SHA3-224](https://www.ietf.org/rfc/rfc9231.html#name-ecdsa-sha-ecdsa-ripemd160-e) | Optional | Yes | No | Yes | No | No | No |
| [ECDSA-SHA3-256](https://www.ietf.org/rfc/rfc9231.html#name-ecdsa-sha-ecdsa-ripemd160-e) | Optional | Yes | No | Yes | Yes [(2)](#new-windows-required) | No | Yes |
| [ECDSA-SHA3-384](https://www.ietf.org/rfc/rfc9231.html#name-ecdsa-sha-ecdsa-ripemd160-e) | Optional | Yes | No | Yes | Yes [(2)](#new-windows-required) | No | Yes |
| [ECDSA-SHA3-512](https://www.ietf.org/rfc/rfc9231.html#name-ecdsa-sha-ecdsa-ripemd160-e) | Optional | Yes | No | Yes | Yes [(2)](#new-windows-required) | No | Yes |
| [EdDSA](https://www.w3.org/2021/04/xmldsig-more) (Ed25519, Ed25519ctx [(9)](#eddsa-ctx), Ed25519ph, Ed448, Ed448ph) | Optional | Yes [(12)](#openssl35-required)  | Yes [(10)](#only-ed25519) | Yes | No | No | No |
| [RSASSA-PSS-SHA1 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional (use is DISCOURAGED) | Yes | Yes | No | Yes | No | Yes |
| [RSASSA-PSS-SHA2-224 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | Yes | No | No | No | No |
| [RSASSA-PSS-SHA2-256 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | Yes | Yes | Yes | No | Yes |
| [RSASSA-PSS-SHA2-384 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | Yes | Yes | Yes | No | Yes |
| [RSASSA-PSS-SHA2-512 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | Yes | Yes | Yes | No | Yes |
| [RSASSA-PSS-SHA3-224 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | No | No | No | No | No |
| [RSASSA-PSS-SHA3-256 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | No | No | Yes [(2)](#new-windows-required) | No | Yes |
| [RSASSA-PSS-SHA3-384 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | No | No | Yes [(2)](#new-windows-required) | No | Yes |
| [RSASSA-PSS-SHA3-512 without Parameters](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10) | Optional | Yes | No | No | Yes [(2)](#new-windows-required) | No | Yes |
| GOST-R3410-2001 | Optional | Yes [(3)](#openssl-gost) | No | Yes | No | Yes [(4)](#mscrypto-gost) | No |
| GOST-R3410-2012 (256 bit) | Optional | Yes [(3)](#openssl-gost) | No | Yes | No | Yes [(4)](#mscrypto-gost) | No |
| GOST-R3411-2012 (512 bit) | Optional | Yes [(3)](#openssl-gost) | No | Yes | No | Yes [(4)](#mscrypto-gost) | No |
| ML-DSA | EXPERIMENTAL | Yes [(1)](#feature-disabled)[(12)](#openssl35-required)  | No | Yes [(1)](#feature-disabled) [(8)](#no-context-string) | No | No | No |
| SLH-DSA-SHA2 (128, 192, 256; fast and slow variants) | EXPERIMENTAL | Yes [(1)](#feature-disabled)[(12)](#openssl35-required)  | No | No | No | No | No |
| **The KeyInfo Element** | | | | | | | |
| [The DSAKeyValue Element](https://www.w3.org/TR/xmldsig-core1/#sec-DSAKeyValue) | Optional | Yes [(1)](#feature-disabled) [(5)](#dsa-key-value) | Yes [(1)](#feature-disabled) [(5)](#dsa-key-value) | Yes [(1)](#feature-disabled) [(5)](#dsa-key-value) | Yes [(1)](#feature-disabled) [(5)](#dsa-key-value) | Yes [(1)](#feature-disabled) [(5)](#dsa-key-value) | Yes [(1)](#feature-disabled) [(5)](#dsa-key-value) |
| [The RSAKeyValue Element](https://www.w3.org/TR/xmldsig-core1/#sec-RSAKeyValue) | Optional | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) |
| [The ECKeyValue Element](https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue) | Optional | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | No | Yes |
| [The X509Data Element](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data) | Optional | Yes | Yes | Yes | Yes | Yes | No |
| [The X509Digest Element](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data) | Optional | Yes | Yes | Yes | Yes [(7)](#only-sha1-x509-digest) | No | No |
| [The PGPData Element](https://www.w3.org/TR/xmldsig-core1/#sec-PGPData) | Optional | No | No | No | No | No | No |
| [The SPKIData Element](https://www.w3.org/TR/xmldsig-core1/#sec-SPKIData) | Optional | No | No | No | No | No | No |
| [The DEREncodedKeyValue Element](https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue) | Optional | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) | Yes [(1)](#feature-disabled) [(11)](#only-x25519) | No | No |

### Notes

1. <a id="feature-disabled"></a> The feature is disabled by default but can be re-enabled at build time.
2. <a id="new-windows-required"></a> Some cryptographic algorithms are not supported on older versions of Windows.
3. <a id="openssl-gost"></a> GOST support in OpenSSL requires installation of the [GOST OpenSSL Engine](https://github.com/gost-engine/engine).
4. <a id="mscrypto-gost"></a> GOST support in MSCrypto requires installation of a GOST CSP.
5. <a id="dsa-key-value"></a> The Seed and PgenCounter are not supported in DSAKeyValue element.
6. <a id="xslt"></a> Requires [LibXSLT](http://xmlsoft.org/XSLT/downloads.html) library.
7. <a id="only-sha1-x509-digest"></a> Only SHA1 digest algorithm is supported for X509Digest element.
8. <a id="no-context-string"></a> The ContextString is not supported.
9. <a id="eddsa-ctx"></a> Ed25519ctx requires a non-empty context string (per RFC 8032).
10. <a id="only-ed25519"></a> Only Ed25519 (Curve25519) is supported, the Ed448 (Curve448) is not supported.
11. <a id="only-x25519"></a> Only X25519 (Curve25519) is supported, the X448 (Curve448) is not supported.
12. <a id="openssl35-required"></a> Requires OpenSSL 3.5.0 or newer.

### Test vectors

- [XML Signature 1.0 interop (2001)](http://www.w3.org/Signature/2001/04/05-xmldsig.md)
- [XML Signature 1.1 interop (2012)](https://www.w3.org/TR/2012/NOTE-xmldsig-core1-interop-20121113/)
