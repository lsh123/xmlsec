## Process this file with automake to produce Makefile.in
NULL =
SUBDIRS = $(XMLSEC_CRYPTO_LIST)
EXTRA_DIST = skeleton $(XMLSEC_CRYPTO_DISABLED_LIST)

xmlsecincdir = $(includedir)/xmlsec1/xmlsec

xmlsecinc_HEADERS = \
	base64.h \
	buffer.h \
	crypto.h \
	errors.h \
	exports.h \
	io.h \
	keyinfo.h \
	keysdata.h \
	keys.h \
	keysmngr.h \
	list.h \
	membuf.h \
	nodeset.h \
	parser.h \
	strings.h \
	templates.h \
	transforms.h \
	version.h \
	xmldsig.h \
	xmlenc.h \
	xmlsec.h \
	xmltree.h \
	$(NULL)

remove-old-headers:
	@if test "x$(DESTDIR)" = "x" && test -d "$(includedir)/xmlsec"; then \
	    echo "----------------------------------------------------------------------"; \
	    echo; \
	    echo "*** WARNING ***:"; \
	    echo; \
	    echo "You seem to have old xmlsec header files installed in:"; \
	    echo; \
	    echo "  \"$(includedir)/xmlsec\""; \
	    echo; \
	    echo "The entire directory will be removed now."; \
	    echo "To allow parallel installation of different xmlsec library versions,"; \
	    echo "the header files are now installed in a version specific subdirectory:"; \
	    echo; \
	    echo "  \"$(xmlsecincdir)\""; \
	    echo; \
	    echo "----------------------------------------------------------------------"; \
	    echo; \
	    rm -rf "$(includedir)/xmlsec"; \
	fi

install-exec-hook: remove-old-headers
	$(mkinstalldirs) $(DESTDIR)$(xmlsecincdir)

