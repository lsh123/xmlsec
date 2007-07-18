NULL =

bin_PROGRAMS = xmlsec1

# check if we use dynamic loading for xmlsec-crypto or not
if XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING

CRYPTO_DEPS = \
	$(top_builddir)/src/$(XMLSEC_CRYPTO)/lib$(XMLSEC_CRYPTO_LIB).la \
	$(top_builddir)/src/libxmlsec1.la \
	$(NULL)    

CRYPTO_INCLUDES = \
	$(XMLSEC_CRYPTO_CFLAGS) \
	$(NULL)

CRYPTO_LD_FLAGS = \
	$(NULL)

CRYPTO_LD_ADD = \
	$(CRYPTO_DEPS) \
	$(XMLSEC_CRYPTO_LIBS) \
	$(NULL)

else

CRYPTO_DEPS =  \
	$(top_builddir)/src/libxmlsec1.la \
	$(NULL)

CRYPTO_INCLUDES = \
	-DXMLSEC_CRYPTO_DYNAMIC_LOADING=1
	$(NULL)

CRYPTO_LD_FLAGS = \
	$(NULL)
    
CRYPTO_LD_ADD = \
	$(CRYPTO_DEPS) \
	$(NULL)

endif 


INCLUDES = \
	-DXMLSEC_CRYPTO=\"@XMLSEC_CRYPTO@\" \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(XMLSEC_APP_DEFINES) \
	$(CRYPTO_INCLUDES) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(XMLSEC_DL_INCLUDES) \
	$(NULL)

# xmlsec command line utility
xmlsec1_SOURCES = \
	xmlsec.c \
	crypto.c crypto.h \
	cmdline.c cmdline.h \
	$(NULL)


xmlsec1_LDFLAGS = \
	$(CRYPTO_LD_FLAGS) \
	@XMLSEC_STATIC_BINARIES@ \
	$(NULL)

xmlsec1_LDADD = \
	$(CRYPTO_LD_ADD) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(XMLSEC_DL_LIBS) \
	$(NULL)

xmlsec1_DEPENDENCIES = \
	$(CRYPTO_DEPS) \
	$(NULL)

