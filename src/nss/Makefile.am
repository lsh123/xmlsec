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
	$(NSS_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1-nss.la \
	$(NULL)

libxmlsec1_nss_la_SOURCES =\
	app.c \
	bignum.c \
	ciphers.c \
	crypto.c \
	digests.c \
	hmac.c \
	pkikeys.c \
	signatures.c \
	symkeys.c \
	x509.c \
	x509vfy.c \
	keysstore.c \
	kt_rsa.c \
	kw_des.c \
	kw_aes.c \
	$(NULL)

libxmlsec1_nss_la_LIBADD = \
	../libxmlsec1.la \
	$(NSS_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_nss_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)

