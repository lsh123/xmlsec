# Building the application with XML Security Library

## Overview

Compiling and linking application with XML Security Library requires specifying correct compilation flags, library files and paths to include and library files. As we discussed before, XML Security Library consist of the core xmlsec library and several xmlsec-crypto libraries. Application has a choice of selecting crypto library at link time or dynamicaly loading it at run time. Please note, that loading crypto engines dynamicaly may introduce security problems on some platforms.

## Include files

In order to use XML Security Library an application should include one or more of the following files:
- [xmlsec/xmlsec.h](#xmlsec-xmlsec) - XML Security Library initialization and shutdown functions;
- [xmlsec/xmldsig.h](#xmlsec-xmldsig) - XML Digital Signature functions;
- [xmlsec/xmlenc.h](#xmlsec-xmlenc) - XML Encryption functions;
- [xmlsec/xmltree.h](#xmlsec-xmltree) - helper functions for XML documents manipulation;
- [xmlsec/templates.h](#xmlsec-templates) - helper functions for dynamic XML Digital Signature and XML Encryption templates creation;
- [xmlsec/crypto.h](#xmlsec-crypto) - automatic XML Security Crypto Library selection.

If necessary, the application should also include LibXML, LibXSLT and crypto library header files.

**Example: Example includes file section**
```
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

There are several ways to get necessary compilation and linking information on Unix and application can use any of these methods to do crypto engine selection either at linking or run time.

### PKG_CHECK_MODULES() macro

**Example: Using PKG_CHECK_MODULES() macro in a configure.in file to select crypto engine (openssl) at linking time**

```autoconf
dnl
dnl Check for xmlsec and friends
dnl
PKG_CHECK_MODULES(XMLSEC, xmlsec1-openssl >= 1.3.0 xml2 libxslt,,exit)
CFLAGS="$CFLAGS $XMLSEC_CFLAGS"
CPPFLAGS="$CPPFLAGS $XMLSEC_CFLAGS"
LDFLAGS="$LDFLAGS $XMLSEC_LIBS"
```

**Example: Using PKG_CHECK_MODULES() macro in a configure.in file to enable dynamical loading of xmlsec-crypto library**

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

**Example: Using pkg-config script in a Makefile to select crypto engine (nss) at linking time**

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

**Example: Using pkg-config script in a Makefile to enable dynamical loading of xmlsec-crypto library**

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

**Example: Using xmlsec1-config script in a Makefile to select crypto engine (e.g. gnutls) at linking time**

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

**Example: Using xmlsec1-config script in a Makefile to enable dynamical loading of xmlsec-crypto library**

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

On Windows there is no such simple and elegant solution. Please check `README` file in `win32` folder of the library package for latest instructions. However, there are few general things, that you need to remember:

- *All libraries linked to your application must be compiled with the same Microsoft Runtime Libraries.*

- *Static linking with XML Security Library requires additional global defines:*

```c
#define LIBXML_STATIC
#define LIBXSLT_STATIC
#define XMLSEC_STATIC
```

- If you do not want to dynamicaly load xmlsec-crypto library and prefer to select crypto engine at linking then you should link your application with xmlsec and at least one of xmlsec-crypto libraries.

- In order to enable dynamic loading for xmlsec-crypto library you should add additional global define:

```c
#define XMLSEC_CRYPTO_DYNAMIC_LOADING
```

## Compiling and linking on other systems

Well, nothing is impossible, it's only software (you managed to compile the library itself, do you?). I'll be happy to include in this manual your expirience with compiling and linking applications with XML Security Library on other platforms (if you would like to share it).

