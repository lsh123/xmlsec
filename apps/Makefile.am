NULL =

bin_PROGRAMS = xmlsec

DEPS = $(top_builddir)/src/libxmlsec.la

INCLUDES =\
-I$(top_srcdir)/include \
$(OPENSSL_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
$(NULL)

LDFLAGS = \
-static \
$(NULL) 

LDADD = \
$(top_builddir)/src/libxmlsec.la \
$(OPENSSL_LDADDS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        



