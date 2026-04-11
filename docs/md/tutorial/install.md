# Building and installing the XML Security Library

## Prerequisites
XML Security Library requires the following libraries:
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

For example, install the following packages on Ubuntu to build the
XML Security Library:

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
apt install help2man pandoc doxygen python3
```

## Building the XML Security Library on Linux, Unix, macOS, MinGW, Cygwin, etc.

To build and install XML Security Library on Unix-like systems from a
release tarball, run the following commands:

```
gunzip -c xmlsec1-<version>.tar.gz | tar xvf -
cd xmlsec1-<version>
./configure [possible configure options]
make
make check
make install
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

To see the configuration options, run:

```
./configure --help
```

## Building the XML Security Library on Windows using Microsoft Visual Studio

Building from the command line is the only supported method. To build
from the command line, you must make sure that your compiler works
there as well. The simplest way is to launch the
`x64 Native Tools Command Prompt for VS 2022` (or a similar)
specialized shell environment that automatically sets the necessary
environment variables. Alternatively, you can use `vcvars64.bat` (or
similar) scripts.

The XML Security Library on Windows uses `JScript` to configure the
build automatically. `JScript` is widely available, but if it is not
available on your machine for any reason, you can also configure the
build manually.

To build and install XML Security Library on Windows using Microsoft
Visual Studio, run the following commands:

```
gunzip -c xmlsec1-<version>.tar.gz | tar xvf -
cd xmlsec1-<version>\win32
cscript configure.js [possible configure options]
nmake
nmake install
```

To see the configuration options, run:

```
cscript configure.js help
```

Note: Do not use path names that contain spaces. This will fail.

### Example

The following command configures the build as follows:
- Use [Microsoft Cryptography API: Next Generation (CNG)](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal);
- Use the multithreaded, DLL-specific version of the Microsoft Visual
  Studio C Runtime libraries;
- Use `c:\opt\include` and `c:\opt\lib` as additional search paths
  for the compiler and the linker;
- Include debug symbols in the binaries.

```
cscript configure.js crypto=mscng cruntime=/MD prefix=c:\opt include=c:\opt\include lib=c:\opt\lib debug=yes
```
