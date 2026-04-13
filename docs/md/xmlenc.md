# XML Security Library: XML Encryption Interoperability Report

XML Security library supports the following features as defined in
[XML Encryption Syntax and Processing Version 1.1](https://www.w3.org/TR/xmlenc-core1/#sec-AlgID)
(also see [RFC 9231](https://www.ietf.org/rfc/rfc9231.html)):

### XML Security Library core features

| Feature | [Requirements](https://www.w3.org/TR/xmlenc-core1/#sec-AlgID) | Status |
|---|---|---|
| **Processing rules** | | |
| [Type parameter value: Element](https://www.w3.org/TR/xmlenc-core1/#sec-Type-Parameters) | Required | Yes |
| [Type parameter value: Content](https://www.w3.org/TR/xmlenc-core1/#sec-Type-Parameters) | Required | Yes |
| [Type parameter value: EXI](https://www.w3.org/TR/xmlenc-core1/#sec-Type-Parameters) | Optional | No |
| [Encryption](https://www.w3.org/TR/xmlenc-core1/#sec-Processing-Encryption) | Required | Yes |
| [Decryption](https://www.w3.org/TR/xmlenc-core1/#sec-Processing-Decryption) | Required | Yes |
| [XML Encryption](https://www.w3.org/TR/xmlenc-core1/#sec-Processing-XML) | Optional | Yes |
| **Syntax** | | |
| [The EncryptedType Element](https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedType) | Required | Yes |
| [The EncryptionMethod Element](https://www.w3.org/TR/xmlenc-core1/#sec-EncryptionMethod) | Optional | Yes |
| [The CipherData Element](https://www.w3.org/TR/xmlenc-core1/#sec-CipherData) | Required | Yes |
| [The CipherReference Element](https://www.w3.org/TR/xmlenc-core1/#sec-CipherReference) | Optional | Yes |
| [The EncryptedData Element](https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedData) | Required | Yes |
| [The EncryptedKey Element](https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedKey) | Optional | Yes |
| [The DerivedKey Element](https://www.w3.org/TR/xmlenc-core1/#sec-DerivedKey) | Required | Yes [(2)](#derived-key) |
| [The ds:RetrievalMethod Element](https://www.w3.org/TR/xmlenc-core1/#sec-ds-RetrievalMethod) | Optional | Yes |
| [The ReferenceList Element](https://www.w3.org/TR/xmlenc-core1/#sec-ReferenceList) | Optional | Yes |
| [The EncryptionProperties Element](https://www.w3.org/TR/xmlenc-core1/#sec-EncryptionProperties) | Optional | Yes |
| **Transforms** | | |
| [XML Canonicalization](https://www.w3.org/TR/xmlenc-core1/#sec-Alg-Canonicalition) | | See [XMLDsig Report](xmldsig.md) |

### XMLSec Cryptographic Libraries features

| Algorithm | [Requirements](https://www.w3.org/TR/xmlenc-core1/#sec-AlgID) | XMLSec with OpenSSL | XMLSec with NSS | XMLSec with GnuTLS | XMLSec with MSCng | XMLSec with MSCrypto [(1)](#feature-disabled) | XMLSec with GCrypt [(1)](#feature-disabled) |
|---|---|---|---|---|---|---|---|
| **Block Encryption Algorithms** | | | | | | | |
| [Triple DES (DES3)](https://www.w3.org/TR/xmlenc-core1/#sec-tripledes-cbc) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-CBC-128](https://www.w3.org/TR/xmlenc-core1/#sec-AES) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-CBC-192](https://www.w3.org/TR/xmlenc-core1/#sec-AES) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-CBC-256](https://www.w3.org/TR/xmlenc-core1/#sec-AES) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-GCM-128](https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM) | Required | Yes | Yes | Yes | Yes | No | No |
| [AES-GCM-192](https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM) | Optional | Yes | Yes | Yes | Yes | No | No |
| [AES-GCM-256](https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM) | Optional | Yes | Yes | Yes | Yes | No | No |
| [Camellia-CBC-128](https://www.ietf.org/rfc/rfc9231.html#section-2.2.4) | Optional | Yes | Yes | Yes | No | No | No |
| [Camellia-CBC-192](https://www.ietf.org/rfc/rfc9231.html#section-2.2.4) | Optional | Yes | Yes | Yes | No | No | No |
| [Camellia-CBC-256](https://www.ietf.org/rfc/rfc9231.html#section-2.2.4) | Optional | Yes | Yes | Yes | No | No | No |
| [ChaCha20](https://www.w3.org/2021/04/xmldsig-more#chacha20) | Optional | Yes | No | Yes | No | No | No |
| [ChaCha20-Poly1305](https://www.w3.org/2021/04/xmldsig-more#chacha20poly1305) | Optional | Yes | Yes | Yes | No | No | No |
| [Stream Encryption Algorithms](https://www.w3.org/TR/xmlenc-core1/#sec-Alg-Stream) | Optional | Yes | Yes | Yes | Yes | No | No |
| **Key Derivation** | | | | | | | |
| [ConcatKDF](https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF) | Required | Yes [(3)](#openssl3-required) [(4)](#concatkdf) | Yes | Yes [(4)](#concatkdf) | Yes [(4)](#concatkdf) [(5)](#mscng-old-win) | No | No |
| [PBKDF2](https://www.w3.org/TR/xmlenc-core1/#sec-PBKDF2) | Optional | Yes [(3)](#openssl3-required) [(6)](#pbkdf2) | Yes [(6)](#pbkdf2) | Yes [(6)](#pbkdf2) | Yes [(5)](#mscng-old-win) [(6)](#pbkdf2) | No | No |
| [HKDF](http://www.w3.org/2021/04/xmldsig-more#hkdf) | Optional | Yes [(3)](#openssl3-required) | Yes | Yes | Yes [(5)](#mscng-old-win) | No | No |
| **Key Transport** | | | | | | | |
| [RSA PKCS1 v1.5](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-1_5) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [RSA-OAEP (MGF1 with SHA1)](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) | Required | Yes | Yes | No | Yes | Yes | Yes |
| [RSA-OAEP with MGF1-SHA1](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) | Optional | Yes | Yes | No | Yes [(7)](#rsa-oaep-same-algo) | No | Yes [(7)](#rsa-oaep-same-algo) |
| [RSA-OAEP with MGF1-SHA224](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) | Optional | Yes | Yes | No | No | No | Yes [(7)](#rsa-oaep-same-algo) |
| [RSA-OAEP with MGF1-SHA256](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) | Optional | Yes | Yes | No | Yes [(7)](#rsa-oaep-same-algo) | No | Yes [(7)](#rsa-oaep-same-algo) |
| [RSA-OAEP with MGF1-SHA384](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) | Optional | Yes | Yes | No | Yes [(7)](#rsa-oaep-same-algo) | No | Yes [(7)](#rsa-oaep-same-algo) |
| [RSA-OAEP with MGF1-SHA512](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) | Optional | Yes | Yes | No | Yes [(7)](#rsa-oaep-same-algo) | No | Yes [(7)](#rsa-oaep-same-algo) |
| **Key Agreement** | | | | | | | |
| [Elliptic Curve Diffie-Hellman (ECDH)](https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES) | Required | Yes [(3)](#openssl3-required) | Yes | Yes | Yes [(5)](#mscng-old-win) | No | No |
| [XDH Key Agreement](https://www.w3.org/2021/04/xmldsig-more) (X25519, X448) | Optional | Yes [(3)](#openssl3-required) | Yes [(9)](#nss-x25519-only) | Yes | Yes [(10)](#mscng-x25519-only) | No | No |
| [Diffie-Hellman with legacy KDF](https://www.w3.org/TR/xmlenc-core1/#sec-DHKeyAgreement) | Optional | No | No | No | No | No | No |
| [Diffie-Hellman with explicit KDF](https://www.w3.org/TR/xmlenc-core1/#sec-DHKeyAgreement) | Optional | Yes [(3)](#openssl3-required) [(8)](#openssl-dhx) | No | No | Yes | No | No |
| **Symmetric Key Wrap** | | | | | | | |
| [Triple DES Key Wrap](https://www.w3.org/TR/xmlenc-core1/#sec-kw-tripledes) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-128 KeyWrap](https://www.w3.org/TR/xmlenc-core1/#sec-kw-aes) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-192 KeyWrap](https://www.w3.org/TR/xmlenc-core1/#sec-kw-aes) | Optional | Yes | Yes | Yes | Yes | Yes | Yes |
| [AES-256 KeyWrap](https://www.w3.org/TR/xmlenc-core1/#sec-kw-aes) | Required | Yes | Yes | Yes | Yes | Yes | Yes |
| [Camellia-128 KeyWrap](https://www.ietf.org/rfc/rfc9231.html#section-2.3.3) | Optional | Yes | Yes | Yes | No | No | No |
| [Camellia-192 KeyWrap](https://www.ietf.org/rfc/rfc9231.html#section-2.3.3) | Optional | Yes | Yes | Yes | No | No | No |
| [Camellia-256 KeyWrap](https://www.ietf.org/rfc/rfc9231.html#section-2.3.3) | Optional | Yes | Yes | Yes | No | No | No |
| **Message Digest** | | | | | | | |
| [Message Digest Algorithms](https://www.w3.org/TR/xmlenc-core1/#sec-Alg-MessageDigest) | | See [XMLDsig Report](xmldsig.md) | | | | | |

### Notes

1. <a id="feature-disabled"></a> The feature is disabled by default but can be re-enabled at build time.
2. <a id="derived-key"></a> Some optional features in DerivedKey element are not supported ([more details](https://github.com/lsh123/xmlsec/issues/515)).
3. <a id="openssl3-required"></a> Requires OpenSSL 3.0.0 or newer.
4. <a id="concatkdf"></a> Only byte-aligned bit strings in ConcatKDFParams element are supported ([more details](https://github.com/lsh123/xmlsec/issues/514)).
5. <a id="mscng-old-win"></a> The xmlsec-mscng library does not support some cryptographic algorithms on older versions of Windows.
6. <a id="pbkdf2"></a> Only "specified" salt is supported for PBKDF2.
7. <a id="rsa-oaep-same-algo"></a> RSA-OAEP digest algorithm and MGF1 algorithm must be the same.
8. <a id="openssl-dhx"></a> The xmlsec-openssl library only supports DHX (X9.42 format) keys for DH algorithm.
9. <a id="nss-x25519-only"></a> The xmlsec-nss library only supports X25519; X448 (Curve448) is not yet implemented in NSS.
10. <a id="mscng-x25519-only"></a> The xmlsec-mscng library only supports X25519; X448 (Curve448) is not supported.

### Test vectors

- [XML Encryption 1.0 interop (2002)](http://www.w3.org/Encryption/2002/02-xenc-interop.html)
- [XML Encryption 1.1 interop (2012)](https://www.w3.org/TR/2012/NOTE-xmlenc-core1-interop-20121113/)
