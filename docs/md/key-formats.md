# XML Security Library: Key Formats Report

The XML Security Library supports the following key, certificate, and CRL formats:

### Key formats supported by each XMLSec cryptographic library

| Format | XMLSec with OpenSSL | XMLSec with NSS | XMLSec with GnuTLS | XMLSec with MSCng | XMLSec with MSCrypto | XMLSec with GCrypt |
|---|---|---|---|---|---|---|
| **Private keys** | | | | | | |
| PKCS12 | Yes | Yes [(1)](#nss-eddsa) | Yes [(5)](#gnutls-pkcs12) | Yes [(4)](#mscng-pkcs12) | Yes | No |
| PKCS8 (PEM) | Yes | No | Yes | No | No | No |
| PKCS8 (DER) | Yes | No | Yes | No | No | No |
| Unencrypted keys (PEM) | Yes | No | Yes | No | No | No |
| Unencrypted keys (DER) | Yes | Yes | Yes | Yes [(3)](#mscng-der-limited) | No | Yes [(2)](#gcrypt-limited) |
| **Public keys** | | | | | | |
| Public keys from X509 certificates (PEM) | Yes | Yes | Yes | No | No | No |
| Public keys from X509 certificates (DER) | Yes | Yes | Yes | Yes | Yes | No |
| Standalone keys (PEM) | Yes | No | Yes | No | No | No |
| Standalone keys (DER) | Yes | Yes | Yes | Yes | No | Yes [(2)](#gcrypt-limited) |
| **X509** | | | | | | |
| X509 certificates (PEM) | Yes | Yes | Yes | No | No | No |
| X509 certificates (DER) | Yes | Yes | Yes | Yes | Yes | No |
| X509 CRLs (PEM) | Yes | No | Yes | No | No | No |
| X509 CRLs (DER) | Yes | Yes | Yes | Yes | No | No |

### Notes

1. <a id="nss-eddsa"></a> NSS cannot import EdDSA private keys from PKCS#12 files; use unencrypted PKCS#8 DER format instead.
2. <a id="gcrypt-limited"></a> The xmlsec-gcrypt library only supports a limited subset of unencrypted private keys and standalone public keys in DER format.
3. <a id="mscng-der-limited"></a> MSCng can only load DH and XDH private keys in unencrypted DER (PrivateKeyInfo) format.
4. <a id="mscng-pkcs12"></a> MSCng cannot import DH and XDH private keys from PKCS#12 files; use unencrypted DER (PrivateKeyInfo) format instead.
5. <a id="gnutls-pkcs12"></a> GnuTLS cannot import private keys from PKCS#12 files encrypted with PBES2/PBKDF2 (the default encryption used by OpenSSL 3.x `openssl pkcs12 -export`); use unencrypted DER (PrivateKeyInfo) format instead.
