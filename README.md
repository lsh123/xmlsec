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
- [LibXML2](http://xmlsoft.org)
- [LibXSLT](http://xmlsoft.org/XSLT/)

And at least one of the following cryptographic libraries:
- [OpenSSL](http://www.openssl.org)
- [NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html)
- [GCrypt/GnuTLS](https://www.gnutls.org/)
- MS Crypto API (Windows only)
- MS Crypto API NG (Windows only)

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
apt install help2man man2html gtk-doc-tools
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
./autogen.sh [possible configure options]
make
make check
make install
```

### Building XMLSec on Windows

See [win32/README.md](win32/README.md) for details.
