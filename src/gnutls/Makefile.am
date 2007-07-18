NULL =

EXTRA_DIST = \
	README \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-gnutls.la \
	$(NULL)

libxmlsec1_gnutls_la_CPPFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(GNUTLS_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

libxmlsec1_gnutls_la_SOURCES =\
	app.c \
	ciphers.c \
	crypto.c \
	digests.c \
	hmac.c \
	symkeys.c \
	globals.h \
	$(NULL)

if SHAREDLIB_HACK
libxmlsec1_gnutls_la_SOURCES += ../strings.c
endif

libxmlsec1_gnutls_la_LIBADD = \
	../libxmlsec1.la \
	$(GNUTLS_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)

libxmlsec1_gnutls_la_DEPENDENCIES = \
	$(NULL)

libxmlsec1_gnutls_la_LDFLAGS = \
	@XMLSEC_CRYPTO_EXTRA_LDFLAGS@ \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
