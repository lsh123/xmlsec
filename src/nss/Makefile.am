NULL =

INCLUDES = \
-I$(top_srcdir) \
-I$(top_srcdir)/include \
$(NSS_CFLAGS) \
$(LIBXSLT_CFLAGS) \
$(LIBXML_CFLAGS) \
-Wall -ansi \
$(NULL)

lib_LTLIBRARIES = libxmlsec-nss.la

libxmlsec_nss_la_SOURCES =\
crypto.c \
keysmngr.c \
$(NULL)

libxmlsec_nss_la_LIBADD = \
$(NSS_LIBS) \
$(LIBXSLT_LIBS) \
$(LIBXML_LIBS) \
$(NULL)
        
libxmlsec_nss_la_LDFLAGS = -version-info @XMLSEC_VERSION_INFO@

# what is this include dir ?
libxmlsec_nssincdir = $(includedir)/xmlsec
