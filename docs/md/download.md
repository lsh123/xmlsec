# XML Security Library: Download

## Source code on GitHub

XML Security Library source code is available on [GitHub](https://github.com/lsh123/xmlsec).

## Stable releases

The latest stable XML Security Library version is **1.3.11**:

- [Sources](https://www.aleksey.com/xmlsec/download/xmlsec1-1.3.11.tar.gz)
  and [signature](https://www.aleksey.com/xmlsec/download/xmlsec1-1.3.11.sig)
  for the latest version ([Coverity report](https://scan.coverity.com/projects/xmlsec)).
- [WIN64 binaries](https://www.aleksey.com/xmlsec/download/win64/) for XML Security Library
  (as well as LibXML2, LibXSLT and OpenSSL).
- XML Security Library is included as part of Debian GNU/Linux. For more information see
  the [coordination page](http://memebeam.org/toys/DebianXmlsec).
- XML Security Library [FreeBSD and](http://www.freebsd.org/cgi/cvsweb.cgi/ports/security/xmlsec/)
  [OpenBSD](https://openports.pl/path/security/xmlsec) ports.

The [previous releases](http://www.aleksey.com/xmlsec/download/) are also available.

The releases [signature key](https://www.aleksey.com/xmlsec/download/aleksey%40aleksey.com.gpg)
fingerprint is: `00FD D6A7 DFB8 1C88 F34B  9BF0 E63E CDEF 9E1D 829E`
([how to verify release tarball signature](https://www.cyberciti.biz/faq/pgp-tarball-file-signature-keys-verification/)).


## Requirements

The XML Security Library requires [LibXML2](http://xmlsoft.org/downloads.html) 2.9.13 or newer,
and optionally [LibXSLT](http://xmlsoft.org/XSLT/downloads.html) 1.1.35 or newer. Plus one of
the following cryptographic libraries:

| XML Security Library | Cryptographic library | Notes |
|---|---|---|
| **xmlsec-openssl** with OpenSSL| [OpenSSL](http://www.openssl.org/) version 3.0.13 or newer. | **OpenSSL 3.5.0 or newer is recommended** (supports all REQUIRED and all RECOMMENDED [XML Digital Signature 1.1](xmldsig.md) and [XML Encryption 1.1](xmlenc.md) algorithms).|
| **xmlsec-openssl** with OpenSSL forks| [AWS-LC](https://github.com/aws/aws-lc) v1.66.0 or newer; [LibreSSL](https://www.libressl.org/) version 3.9.0 or newer; [BoringSSL](https://boringssl.googlesource.com/boringssl/) version 1.1.0 or newer.| Some of the OpenSSL forks do not have stable API (e.g. BoringSSL) and the latest versions of the libraries might not work with XML Security Library. |
| **xmlsec-nss** | [NSS](http://www.mozilla.org/projects/security/pki/nss/) (Mozilla cryptographic library) 3.91 or newer | Requires [NSPR](https://firefox-source-docs.mozilla.org/nspr/index.html) 4.34.1 or newer |
| **xmlsec-gnutls** | [GnuTLS](http://www.gnu.org/software/gnutls/) 3.8.3 or newer | Supports multiple cryptographic backends, the exact features set for xmlsec-gnutls depends on the backend in use. |
| **xmlsec-mscng** | [Microsoft Cryptography API: Next Generation](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) (requires Windows 7, Windows Server 2008 R2, or newer) | xmlsec-mscng is the recommended version on Windows platform. |
| **xmlsec-mscrypto** | [Microsoft CryptoAPI (MSCrypto)](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography--cryptoapi--and-capicom) (requires Windows Server 2003, or newer) | In maintenance mode starting from xmlsec 1.3.0, April 2023. |
| **xmlsec-gcrypt** | [LibGCrypt](https://www.gnupg.org/software/libgcrypt/index.html) 1.4.0 or newer | In maintenance mode starting from xmlsec 1.3.0, April 2023. |

The supported [key formats report](key-formats.md),
[XML Digital Signature Interoperability report](xmldsig.md), and
[XML Encryption Interoperability report](xmlenc.md) provide detailed information about
the features supported by each library.

## Build and install

The XML Security Library is using the standard Unix/Linux build steps
with configure / make. For more details and other operatings systems
support see [tutorial](tutorial/install.md).

## Other languages

- [Python xmlsec module](https://github.com/mehcode/python-xmlsec)
- [Perl LibXML-Sec module](https://github.com/estrelow/Perl-LibXML-Sec)

