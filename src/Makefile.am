NULL =

SUBDIRS = $(XMLSEC_CRYPTO)

INCLUDES = \
-I$(top_srcdir) \
-I$(top_srcdir)/include \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
-Wall -ansi \
$(NULL)

lib_LTLIBRARIES = libxmlsec.la

libxmlsec_la_SOURCES =\
base64.c \
buffered.c \
c14n.c \
ciphers.c \
debug.c \
digests.c \
enveloped.c \
errors.c \
io.c \
keyinfo.c \
keys.c \
keysmngr.c \
membuf.c \
nodeset.c \
transforms.c \
x509.c \
xmldsig.c \
xmlenc.c \
xmlsec.c \
xmltree.c \
xpath.c \
xslt.c \
$(NULL)


libxmlsec_la_LIBADD = \
-L./$(XMLSEC_CRYPTO) -l$(XMLSEC_CRYPTO_LIB) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        
libxmlsec_la_LDFLAGS = -version-info @XMLSEC_VERSION_INFO@

# what is this include dir ?
libxmlsecincdir = $(includedir)/xmlsec


