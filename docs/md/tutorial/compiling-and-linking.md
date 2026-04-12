# Building the application with XML Security Library

## Overview

Compiling and linking an application with XML Security Library requires
the correct compilation flags, include paths, libraries, and library
paths for XML Security Library itself and for all of its dependencies.
The XML Security Library consists of the core xmlsec library and
several xmlsec-crypto libraries. An application can select the crypto
library at link time or load it dynamically at run time. Please note
that dynamically loading crypto engines may introduce security issues
on some platforms.

## Include files

To use XML Security Library, an application should include one
or more of the following files:
- `xmlsec/xmlsec.h` - XML Security Library initialization and
  shutdown functions;
- `xmlsec/xmldsig.h` - XML Digital Signature functions;
- `xmlsec/xmlenc.h` - XML Encryption functions;
- `xmlsec/xmltree.h` - helper functions for XML documents manipulation;
- `xmlsec/templates.h` - helper functions for creating dynamic XML
	Digital Signature and XML Encryption templates;
- `xmlsec/crypto.h` - automatic XML Security Crypto Library selection.

If necessary, the application should also include LibXML, LibXSLT and
crypto library header files.

### Example: includes file section

```c
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
```

## Compiling and linking on Unix

There are several ways to obtain the required compilation and linking
information on Linux/Unix. An application can use any of these methods
to select a crypto engine either at link time or at run time.

### PKG_CHECK_MODULES() macro

#### Example: PKG_CHECK_MODULES() to select OpenSSL at link time

```autoconf
dnl
dnl Check for xmlsec and friends
dnl
PKG_CHECK_MODULES(XMLSEC, xmlsec1-openssl >= 1.3.0 xml2 libxslt,,exit)
CFLAGS="$CFLAGS $XMLSEC_CFLAGS"
CPPFLAGS="$CPPFLAGS $XMLSEC_CFLAGS"
LDFLAGS="$LDFLAGS $XMLSEC_LIBS"
```

#### Example: PKG_CHECK_MODULES() to enable dynamic xmlsec-crypto loading

```autoconf
dnl
dnl Check for xmlsec and friends
dnl
PKG_CHECK_MODULES(XMLSEC, xmlsec1 >= 1.3.0 xml2 libxslt,,exit)
CFLAGS="$CFLAGS $XMLSEC_CFLAGS"
CPPFLAGS="$CPPFLAGS $XMLSEC_CFLAGS"
LDFLAGS="$LDFLAGS $XMLSEC_LIBS"
```

### pkg-config script

#### Example: pkg-config to select NSS at link time

```makefile
PROGRAM = test
PROGRAM_FILES = test.c

CFLAGS	+= -g $(shell pkg-config --cflags xmlsec1-nss)
LDFLAGS	+= -g
LIBS 	+= $(shell pkg-config --libs xmlsec1-nss)

all: $(PROGRAM)

%: %.c
	$(cc) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
```

#### Example: pkg-config to enable dynamic xmlsec-crypto loading

```makefile
PROGRAM = test
PROGRAM_FILES = test.c

CFLAGS	+= -g $(shell pkg-config --cflags xmlsec1)
LDFLAGS	+= -g
LIBS 	+= $(shell pkg-config --libs xmlsec1)

all: $(PROGRAM)

%: %.c
	$(cc) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
```

### xmlsec1-config script

#### Example: xmlsec1-config to select GnuTLS at link time

```makefile
PROGRAM = test
PROGRAM_FILES = test.c

CFLAGS	+= -g $(shell xmlsec1-config --crypto gnutls --cflags)
LDFLAGS	+= -g
LIBS 	+= $(shell xmlsec1-config --crypto gnutls --libs)

all: $(PROGRAM)

%: %.c
	$(cc) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
```

#### Example: xmlsec1-config to enable dynamic xmlsec-crypto loading

```makefile
PROGRAM = test
PROGRAM_FILES = test.c

CFLAGS	+= -g $(shell xmlsec1-config --cflags)
LDFLAGS	+= -g
LIBS 	+= $(shell xmlsec1-config --libs)

all: $(PROGRAM)

%: %.c
	$(cc) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
```

## Compiling and linking on Windows

On Windows there is no easy way to automatically configure compilation
options or paths. You have to do everything manually.

### Global Defines

If you want to use automatic crypto library configuration with the
`xmlsec/crypto.h` file, add one of the following global defines:

```c
#define XMLSEC_CRYPTO_MSCNG
#define XMLSEC_CRYPTO_OPENSSL
#define XMLSEC_CRYPTO_GNUTLS
#define XMLSEC_CRYPTO_NSS
#define XMLSEC_CRYPTO_MSCRYPTO
```

You will also need to define all configuration parameters used when
building XML Security Library (`XMLSEC_NO_AES`, `XMLSEC_NO_X509`, ...).

There are three options for loading the `xmlsec-crypto` library in an
application:

- To load the `xmlsec-crypto` library at runtime, add the following
	global define:

```c
#define XMLSEC_CRYPTO_DYNAMIC_LOADING
```

- To select the `xmlsec-crypto` library at build/link time, add the
	selected `xmlsec-crypto` library, along with all of its
	dependencies, to the linker.

- To statically link with XML Security Library, add the following
	global defines:

```c
#define LIBXML_STATIC
#define LIBXSLT_STATIC
#define XMLSEC_STATIC
```

### Setting include and library paths.

As usual, you need the correct include and library paths for XMLSec,
LibXML, LibXSLT, OpenSSL, or any other library used by your
application.

### Selecting correct Windows runtime libraries.

Microsoft Visual Studio provides several C runtimes for different
combinations of single-threaded vs multi-threaded mode, static vs
dynamic linking, and debug vs release builds. The
rule is simple: ***exactly the same runtime MUST be used throughout
the application (including all dependencies)***.

By default, `configure.ps1` uses the `/MD` (non-debug version of 
the multithreaded DLL runtime) runtime libraries. 
Use `cruntime=<new runtime>` option to change it (see the XML Security
Library [installation tutorial](install.md) for more details).

