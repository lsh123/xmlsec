NULL =

SUBDIRS = openssl

INCLUDES = \
-I$(top_srcdir) \
-I$(top_srcdir)/include \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
$(NULL)

lib_LTLIBRARIES = libxmlsec.la

libxmlsec_la_SOURCES =\
base64.c \
buffered.c \
c14n.c \
debug.c \
enveloped.c \
errors.c \
io.c \
keyinfo.c \
keys.c \
keysdata.c \
keysmngr.c \
list.c \
membuf.c \
nodeset.c \
strings.c \
templates.c \
transforms.c \
xmldsig.c \
xmlenc.c \
xmlsec.c \
xmltree.c \
xpath.c \
xslt.c \
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

