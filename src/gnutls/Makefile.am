NULL =

EXTRA_DIST = \
	globals.h \
	README \
	$(NULL)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(GNUTLS_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
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
	../libxmlsec1.la \
	$(GNUTLS_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_gnutls_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
