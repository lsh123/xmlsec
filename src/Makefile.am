NULL =

SUBDIRS = $(XMLSEC_CRYPTO_LIST)

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	globals.h \
	skeleton \
	$(XMLSEC_CRYPTO_DISABLED_LIST) \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1.la \
	$(NULL)

libxmlsec1_la_SOURCES =\
	base64.c \
	buffer.c \
	c14n.c \
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
	parser.c \
	strings.c \
	templates.c \
	transforms.c \
	x509.c \
	xkms.c \
	xmldsig.c \
	xmlenc.c \
	xmlsec.c \
	xmltree.c \
	xpath.c \
	xslt.c \
	$(NULL)

libxmlsec1_la_LIBADD = \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)

