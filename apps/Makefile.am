NULL =

bin_PROGRAMS = xmlsec

if XMLSEC_CRYPTO_OPENSSL
XMLSEC_CRYPTO_INCLUDES = \
    -DXMLSEC_CRYPTO_OPENSSL=1 \
    $(OPENSSL_CFLAGS) \
    $(NULL) 

XMLSEC_CRYPTO_LIB=\
    $(top_builddir)/src/openssl/libxmlsec-openssl.la \
    $(NULL)

XMLSEC_CRYPTO_LIBS = \
    $(OPENSSL_LDADDS) \
    $(NULL)
else 
if XMLSEC_CRYPTO_NSS
XMLSEC_CRYPTO_INCLUDES = \
    -DXMLSEC_CRYPTO_NSS=1 \
    $(NSS_CFLAGS) \
    $(NULL) 

XMLSEC_CRYPTO_LIB=\
    $(top_builddir)/src/nss/libxmlsec-nss.la \
    $(NULL)

XMLSEC_CRYPTO_LIBS = \
    $(NSS_LDADDS) \
    $(NULL)
else 
    "Error: no crypto library defined"
endif
endif

INCLUDES = \
    -DXMLSEC_CRYPTO=\"$(XMLSEC_CRYPTO)\" \
    -I$(top_srcdir)/include \
    $(XMLSEC_CRYPTO_INCLUDES) \
    $(LIBXSLT_CFLAGS) \
    $(LIBXML_CFLAGS) \
    $(NULL)

DEPS = \
    $(XMLSEC_CRYPTO_LIB) \
    $(top_builddir)/src/libxmlsec.la \
    $(NULL)

# xmlsec command line utility
xmlsec_SOURCES = \
    xmlsec.c \
    crypto.c crypto.h \
    $(NULL)

if XMLSEC_DYNAMIC_LINKING
xmlsec_LDFLAGS = 
else 
xmlsec_LDFLAGS = -static
endif

xmlsec_LDADD = \
    $(XMLSEC_CRYPTO_LIB) \
    $(top_builddir)/src/libxmlsec.la \
    $(XMSLEC_CRYPTO_LIBS) \
    $(LIBXSLT_LIBS) \
    $(LIBXML_LIBS) \
    $(XMLSEC_CRYPTO_LIB) \
    $(NULL)
