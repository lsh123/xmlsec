NULL =

INCLUDES = \
-I$(top_srcdir) \
-I$(top_srcdir)/include \
$(XMLSEC_OPENSSL_DEFINES) \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
-Wall -ansi \
$(NULL)

lib_LTLIBRARIES = libxmlsec-openssl.la

libxmlsec_openssl_la_SOURCES =\
app.c \
bn.c \
ciphers.c \
crypto.c \
digests.c \
dsa.c \
evp.c \
hmac.c \
kwaes.c \
kwdes.c \
rsa.c \
symkeys.c \
x509.c \
x509vfy.c \
$(NULL)

libxmlsec_openssl_la_LIBADD = \
$(OPENSSL_LIBS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        
libxmlsec_openssl_la_LDFLAGS = -version-info @XMLSEC_VERSION_INFO@

# what is this include dir ?
libxmlsec_opensslincdir = $(includedir)/xmlsec
