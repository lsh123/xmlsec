NULL =

bin_PROGRAMS = xmlsec

DEPS = \
$(top_builddir)/src/openssl/libxmlsec-openssl.la \
$(top_builddir)/src/libxmlsec.la \
$(NULL)

INCLUDES = \
-I$(top_srcdir)/include \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
$(NULL) 


xmlsec_SOURCES = \
xmlsec.c \
crypto.c crypto.h \
$(NULL)

if XMLSEC_DYNAMIC_LINKING
xmlsec_LDFLAGS =
else
xmlsec_LDFLAGS = -static -L$(top_builddir)/src -lxmlsec
endif
xmlsec_LDADD = \
$(top_builddir)/src/openssl/libxmlsec-openssl.la \
$(top_builddir)/src/libxmlsec.la \
$(OPENSSL_LDADDS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)


