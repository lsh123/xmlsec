NULL =

INCLUDES = \
-I$(top_srcdir) \
-I$(top_srcdir)/include \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
-Wall -ansi \
$(NULL)

lib_LTLIBRARIES = libxmlsec-openssl.la

libxmlsec_openssl_la_SOURCES =\
aes.c \
bn.c \
crypto.c \
des.c \
dsa.c \
evp.c \
hmac.c \
keysmngr.c \
ripemd160.c \
rsa.c \
sha1.c \
x509.c \
$(NULL)

libxmlsec_openssl_la_LIBADD = \
$(OPENSSL_LIBS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        
libxmlsec_openssl_la_LDFLAGS = -version-info @XMLSEC_VERSION_INFO@

# what is this include dir ?
libxmlsec_opensslincdir = $(includedir)/xmlsec
