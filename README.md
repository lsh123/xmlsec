# XMLSec Library

XMLSec library provides C based implementation for major XML Security
standards:
- [XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core)
- [XML Encryption Syntax and Processing](https://www.w3.org/TR/xmlenc-core/)

Detailed information about supported features and algorithms can be found in
the [XMLDsig](https://www.aleksey.com/xmlsec/xmldsig.html) and
the [XMLEnc](https://www.aleksey.com/xmlsec/xmlenc.html) interoperability reports.

## Documentation
Complete XMLSec library documentation is published on [XMLSec website](https://www.aleksey.com/xmlsec/).

## License
XMLSec library is released under the MIT Licence (see the [Copyright file](Copyright)).

## Building and installing XMLSec

### Prerequisites
XMLSec requires the following libraries:
- [LibXML2](https://gitlab.gnome.org/GNOME/libxml2) >= 2.9.13
- [LibXSLT](https://gitlab.gnome.org/GNOME/libxslt) >= 1.1.35 (optional)

And at least one of the following cryptographic libraries:
- [OpenSSL](https://www.openssl.org) >= 3.0.13 (>= 3.5.0 is recommended)
- [LibreSSL](https://www.libressl.org/) >= 3.9.0
- [BoringSSL](https://boringssl.googlesource.com/boringssl/) >= 1.1.0
- [NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html) >= 3.91 (with [NSPR](https://firefox-source-docs.mozilla.org/nspr/index.html) >= 4.34.1)
- [GnuTLS](https://www.gnutls.org/) >= 3.8.3
- [Microsoft Cryptography API: Next Generation (CNG)](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
- (Deprecated) [Microsoft Cryptography API](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-portal)
- (Deprecated) [GCrypt](https://www.gnupg.org/software/libgcrypt/index.html)

For example, the following packages need to be installed on Ubuntu to build
XMLSec library:
```
# common build tools
apt install automake autoconf libtool libtool-bin gcc

# ltdl is required to support dynamic crypto libs loading
apt install libltdl7 libltdl-dev

# core libxml2 and libxslt libraries
apt install libxml2 libxml2-dev libxslt1.1 libxslt1-dev

# openssl libraries
apt install openssl libssl3 libssl-dev

# nspr/nss libraries
apt install libnspr4 libnspr4-dev libnss3 libnss3-dev libnss3-tools

# gnutls libraries
apt install libgnutls30

# gnutls libraries
apt install libgcrypt20 libgcrypt20-dev

# required for building man pages and docs
apt install help2man man2html gtk-doc-tools pandoc
```

### Building XMLSec on Linux, Unix, MacOSX, MinGW, Cygwin, etc

To build and install XMLSec library on Unix-like systems from a release tarball, run the following commands:

```
gunzip -c xmlsec1-<version>.tar.gz | tar xvf -
cd xmlsec1-<version>
./configure [possible configure options]
make
make check
make install
```

To see the configuration options, run:

```
./configure --help
```

To build from GitHub, run the following commands:

```
git clone https://github.com/lsh123/xmlsec.git
cd xmlsec
autoreconf -i -f
./configure [possible configure options]
make
make check
make install
```

### Building XMLSec on Windows

See [win32/README.md](win32/README.md) for details.
