NULL =

bin_PROGRAMS = xmlsec

DEPS = $(top_builddir)/src/libxmlsec.la

INCLUDES =\
-I$(top_srcdir)/include \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
$(NULL) 


if XMLSEC_DYNAMIC_LINKING
xmlsec_LDFLAGS =
else
xmlsec_LDFLAGS = -static
endif

xmlsec_LDADD = \
$(top_builddir)/src/libxmlsec.la \
$(OPENSSL_LDADDS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)


