NULL =

bin_PROGRAMS = xmlsec

INCLUDES = \
    -DXMLSEC_CRYPTO=\"@XMLSEC_CRYPTO@\" \
    -I$(top_srcdir)/include \
    $(XMLSEC_DEFINES) \
    $(XMLSEC_CRYPTO_CFLAGS) \
    $(LIBXSLT_CFLAGS) \
    $(LIBXML_CFLAGS) \
    $(NULL)

DEPS = \
    $(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
    $(top_builddir)/src/libxmlsec.la \
    $(NULL)

# xmlsec command line utility
xmlsec_SOURCES = \
    xmlsec.c \
    crypto.c crypto.h \
    cmdline.c cmdline.h \
    $(NULL)

if XMLSEC_DYNAMIC_LINKING
xmlsec_LDFLAGS = 
else 
xmlsec_LDFLAGS = -static
endif

xmlsec_LDADD = \
    $(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
    $(top_builddir)/src/libxmlsec.la \
    $(LIBXSLT_LIBS) \
    $(LIBXML_LIBS) \
    $(XMLSEC_CRYPTO_LIBS) \
    $(NULL)
