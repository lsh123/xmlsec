NULL =

bin_PROGRAMS = xmlsec1

INCLUDES = \
    -DPACKAGE=\"@PACKAGE@\" \
    -DVERSION=\"@VERSION@\" \
    -DXMLSEC_CRYPTO=\"@XMLSEC_CRYPTO@\" \
    -I$(top_srcdir)/include \
    $(XMLSEC_DEFINES) \
    $(XMLSEC_CRYPTO_CFLAGS) \
    $(LIBXSLT_CFLAGS) \
    $(LIBXML_CFLAGS) \
    $(NULL)
    
DEPS = \
    $(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
    $(top_builddir)/src/libxmlsec1.la \
    $(NULL)

# xmlsec command line utility
xmlsec1_SOURCES = \
    xmlsec.c \
    crypto.c crypto.h \
    cmdline.c cmdline.h \
    $(NULL)

if XMLSEC_DYNAMIC_LINKING
xmlsec1_LDFLAGS = 
else 
xmlsec1_LDFLAGS = -static
endif

xmlsec1_LDADD = \
    $(DEPS) \
    $(LIBXSLT_LIBS) \
    $(LIBXML_LIBS) \
    $(XMLSEC_CRYPTO_LIBS) \
    $(NULL)
