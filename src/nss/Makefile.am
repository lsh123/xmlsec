NULL =

EXTRA_DIST = \
	README.md \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-nss.la \
	$(NULL)

libxmlsec1_nss_la_CPPFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(NSS_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

libxmlsec1_nss_la_SOURCES =\
	app.c \
	ciphers_cbc.c \
	ciphers_gcm.c \
	crypto.c \
	digests.c \
	globals.h \
	hmac.c \
	keysstore.c \
	keytrans.c \
	kw_des.c \
	kw_rfc_3394.c \
	kdf.c \
	der_encoded_value.c \
	pkikeys.c \
	private.h \
	key_agrmnt.c \
	signatures.c \
	symkeys.c \
	x509.c \
	x509vfy.c \
	$(NULL)

libxmlsec1_nss_la_LIBADD = \
	$(NSS_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	../libxmlsec1.la \
	$(NULL)

libxmlsec1_nss_la_DEPENDENCIES = \
	$(NULL)

libxmlsec1_nss_la_LDFLAGS = \
	@XMLSEC_CRYPTO_EXTRA_LDFLAGS@ \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
