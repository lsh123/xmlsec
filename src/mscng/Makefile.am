NULL =

EXTRA_DIST = \
	README.md \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-mscng.la \
	$(NULL)

libxmlsec1_mscng_la_CPPFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(MSCNG_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

libxmlsec1_mscng_la_SOURCES =\
	app.c \
	certkeys.c \
	ciphers_cbc.c \
	ciphers_gcm.c \
	concatkdf.c \
	crypto.c \
	digests.c \
	globals.h \
	hmac.c \
	key_agrmnt.c \
	keysstore.c \
	kt_rsa.c \
	kw_aes.c \
	kw_des.c \
	pbkdf2.c \
	private.h \
	signatures.c \
	symkeys.c \
	x509.c \
	x509vfy.c \
	$(NULL)

libxmlsec1_mscng_la_LIBADD = \
	$(MSCNG_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	../libxmlsec1.la \
	$(NULL)

libxmlsec1_mscng_la_LDFLAGS = \
	@XMLSEC_CRYPTO_EXTRA_LDFLAGS@ \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
