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
	$(XMLSEC_CRYPTO_DISABLED_LIST) \
	$(NULL)

pkglib_LTLIBRARIES = \
	libxmlsec.la \
	$(NULL)

libxmlsec_la_SOURCES =\
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
	xmldsig.c \
	xmlenc.c \
	xmlsec.c \
	xmltree.c \
	xpath.c \
	xslt.c \
	$(NULL)

libxmlsec_la_LIBADD = \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	-release @XMLSEC_RELEASE@ \
	-rpath $(pkglibdir) \
	-R $(pkglibdir) \
	$(NULL)

remove-old-libraries:
	@if test "x$(DESTDIR)" = "x" && test -e "$(libdir)/libxmlsec.so"; then \
	    echo "----------------------------------------------------------------------"; \
	    echo; \
	    echo "*** WARNING ***:"; \
	    echo; \
	    echo "You seem to have old xmlsec library files installed in:"; \
	    echo; \
	    echo "  \"$(libdir)\""; \
	    echo; \
	    echo "All xmlsec library files from this directory will be removed now."; \
	    echo "To allow parallel installation of different xmlsec library versions,"; \
	    echo "the header files are now installed in a version specific subdirectory:"; \
	    echo; \
	    echo "  \"$(pkglibdir)\""; \
	    echo; \
	    echo "----------------------------------------------------------------------"; \
	    echo; \
	    rm -rf $(libdir)/libxmlsec.*; \
	    rm -rf $(libdir)/libxmlsec-*; \
	fi

install-exec-hook: remove-old-libraries
