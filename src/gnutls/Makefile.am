NULL =

EXTRA_DIST = \
	globals.h \
	$(NULL)

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(XMLSEC_GNUTLS_DEFINES) \
	$(GNUTLS_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	-Wall -ansi \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-gnutls.la \
	$(NULL)

libxmlsec1_gnutls_la_SOURCES =\
	app.c \
	ciphers.c \
	crypto.c \
	digests.c \
	hmac.c \
	symkeys.c \
	$(NULL)

libxmlsec1_gnutls_la_LIBADD = \
	$(GNUTLS_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_gnutls_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
