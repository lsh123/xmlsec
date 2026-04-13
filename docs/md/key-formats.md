# XML Security Library: Key Formats Report

XML Security library supports the following key, certificate, and CRL formats:

### XMLSec Cryptographic Libraries key formats

| Format | XMLSec with OpenSSL | XMLSec with NSS | XMLSec with GnuTLS | XMLSec with MSCng | XMLSec with MSCrypto | XMLSec with GCrypt |
|---|---|---|---|---|---|---|
| **Private keys** | | | | | | |
| PKCS12 | Yes | Yes | Yes | Yes | Yes | No |
| PKCS8 (PEM) | Yes | No | Yes | No | No | No |
| PKCS8 (DER) | Yes | No | Yes | No | No | No |
| Unencrypted keys (PEM) | Yes | No | Yes | No | No | No |
| Unencrypted keys (DER) | Yes | No | Yes | No | No | Yes [(1)](#gcrypt-limited) |
| **Public keys** | | | | | | |
| Public keys from X509 certificates (PEM) | Yes | Yes | Yes | No | No | No |
| Public keys from X509 certificates (DER) | Yes | Yes | Yes | Yes | Yes | No |
| Standalone keys (PEM) | Yes | No | Yes | No | No | No |
| Standalone keys (DER) | Yes | Yes | Yes | No | No | Yes [(1)](#gcrypt-limited) |
| **X509** | | | | | | |
| X509 certificates (PEM) | Yes | Yes | Yes | No | No | No |
| X509 certificates (DER) | Yes | Yes | Yes | Yes | Yes | No |
| X509 CRLs (PEM) | Yes | No | Yes | No | No | No |
| X509 CRLs (DER) | Yes | Yes | Yes | Yes | No | No |

### Notes

1. <a id="gcrypt-limited"></a> The xmlsec-gcrypt library only supports a limited subset of unencrypted private keys and standalone public keys in DER format.
