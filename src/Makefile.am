NULL =

INCLUDES = \
-I$(top_srcdir)/include \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
-Wall -ansi \
$(NULL)

lib_LTLIBRARIES = libxmlsec.la

libxmlsec_la_SOURCES =\
xmlsec.c \
xmltree.c \
bn.c \
debug.c \
transforms.c \
keys.c \
keyinfo.c \
x509.c \
keysmngr.c \
buffered.c \
membuf.c \
base64.c \
io.c \
digests.c \
ciphers.c \
sha1.c \
ripemd160.c \
hmac.c \
c14n.c \
dsa.c \
rsa.c \
xpath.c \
enveloped.c \
xslt.c \
xmldsig.c \
des.c \
aes.c \
xmlenc.c \
xpathalt.c \
$(NULL)


libxmlsec_la_LIBADD = \
$(OPENSSL_LIBS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        
libxmlsec_la_LDFLAGS = -version-info @XMLSEC_VERSION_INFO@

# what is this include dir ?
libxmlsecincdir = $(includedir)/xmlsec

libxmlsecinc_HEADERS = \
$(NULL)
