## Process this file with automake to produce Makefile.in

xmlsecincdir = $(includedir)/xmlsec0/xmlsec

xmlsecinc_HEADERS = \
base64.h \
bn.h \
buffered.h \
ciphers.h \
digests.h \
debug.h \
errors.h \
io.h \
keyinfo.h \
keys.h \
keysInternal.h \
keysmngr.h \
membuf.h \
nodeset.h \
transforms.h \
transformsInternal.h \
version.h \
x509.h \
xmldsig.h \
xmlenc.h \
xmlsec.h \
xmltree.h

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

