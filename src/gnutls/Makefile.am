NULL =

EXTRA_DIST = \
	globals.h \
$(NULL)

INCLUDES = \
-I$(top_srcdir) \
-I$(top_srcdir)/include \
$(XMLSEC_NSS_DEFINES) \
$(NSS_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
-Wall -ansi \
$(NULL)

lib_LTLIBRARIES = libxmlsec-gnutls.la

libxmlsec_gnutls_la_SOURCES =\
app.c \
ciphers.c \
crypto.c \
digests.c \
hmac.c \
symkeys.c \
$(NULL)

libxmlsec_gnutls_la_LIBADD = \
$(NSS_LIBS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        
libxmlsec_gnutls_la_LDFLAGS = -version-info @XMLSEC_VERSION_INFO@

# what is this include dir ?
libxmlsec_gnutlsincdir = $(includedir)/xmlsec
