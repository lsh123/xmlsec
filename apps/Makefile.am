NULL =

bin_PROGRAMS = xmlsec

DEPS = \
$(top_builddir)/src/libxmlsec.la \
$(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
$(NULL)

INCLUDES =\
-I$(top_srcdir)/include \
$(XMLSEC_CRYPTO_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
$(NULL) 


if XMLSEC_DYNAMIC_LINKING
xmlsec_LDFLAGS =
else
xmlsec_LDFLAGS = -static
endif

xmlsec_LDADD = \
$(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
$(top_builddir)/src/libxmlsec.la \
$(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
$(XMLSEC_CRYPTO_LDADDS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)


