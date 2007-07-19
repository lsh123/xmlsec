NULL =

EXTRA_DIST = \
	mingw-crypt32.def \
	README \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-mscrypto.la \
	$(NULL)

libxmlsec1_mscrypto_la_CPPFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(MSCRYPTO_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

libxmlsec1_mscrypto_la_SOURCES =\
	app.c \
	certkeys.c \
	ciphers.c \
	crypto.c \
	digests.c \
	keysstore.c \
	kt_rsa.c \
	signatures.c \
	symkeys.c \
	x509.c \
	x509vfy.c \
	csp_calg.h \
	csp_oid.h \
	globals.h \
	xmlsec-mingw.h \
	$(NULL)

if SHAREDLIB_HACK
libxmlsec1_mscrypto_la_SOURCES += ../strings.c
endif

libxmlsec1_mscrypto_la_LIBADD = \
	../libxmlsec1.la \
	$(MSCRYPTO_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)

libxmlsec1_mscrypto_la_DEPENDENCIES = \
	mingw-crypt32.def \
	$(NULL)

libxmlsec1_mscrypto_la_LDFLAGS = \
	@XMLSEC_CRYPTO_EXTRA_LDFLAGS@ \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
