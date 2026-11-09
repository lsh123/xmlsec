NULL =

EXTRA_DIST = \
	README.md \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-gcrypt.la \
	$(NULL)

libxmlsec1_gcrypt_la_CPPFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-DGCRYPT_MIN_VERSION=\"$(GCRYPT_MIN_VERSION)\" \
	-I../../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(GCRYPT_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

libxmlsec1_gcrypt_la_SOURCES =\
	app.c \
	asn1.c \
	asn1.h \
	asymkeys.c \
	ciphers.c \
	crypto.c \
	digests.c \
	globals.h \
	hmac.c \
	kt_rsa.c \
	kw_des.c \
	kw_rfc_3394.c \
	signatures.c \
	symkeys.c \
	$(NULL)

libxmlsec1_gcrypt_la_LIBADD = \
	$(GCRYPT_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	../libxmlsec1.la \
	$(NULL)

libxmlsec1_gcrypt_la_DEPENDENCIES = \
	$(NULL)

libxmlsec1_gcrypt_la_LDFLAGS = \
	@XMLSEC_CRYPTO_EXTRA_LDFLAGS@ \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
