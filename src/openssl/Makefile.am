NULL =

EXTRA_DIST = \
	globals.h \
	$(NULL)

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(OPENSSL_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	-Wall -ansi \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-openssl.la \
	$(NULL)

libxmlsec1_openssl_la_SOURCES =\
	app.c \
	bn.c \
	ciphers.c \
	crypto.c \
	digests.c \
	evp.c \
	hmac.c \
	kw_aes.c \
	kw_des.c \
	kt_rsa.c \
	signatures.c \
	symkeys.c \
	x509.c \
	x509vfy.c \
	$(NULL)

libxmlsec1_openssl_la_LIBADD = \
	$(OPENSSL_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_openssl_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
