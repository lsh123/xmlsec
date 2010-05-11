NULL =

SUBDIRS=api

TARGET_DIR=@XMLSEC_DOCDIR@

EXTRA_DIST=\
	images \
	xmlsec.xsl \
	$(NULL)

# just do nothing
all:

docs: api-docs-create docs-format

api-docs-create:
	@(cd api; \
	    $(MAKE) docs; \
	    echo "Cleaning up result files"; \
	    perl ../../scripts/remove-gtkdoclink.pl `find . -name "*.html" -print` \
	)

api-docs-clean:
	@(cd api; $(MAKE) clean)

docs-format:
	@(echo "Formatting html documents"; \
	for i in `find . -name "*.html" -print`; \
	do \
	    top_folder=`echo $$i | sed 's#/[^/]*$$#/#' | sed 's#\./##' | \
			sed 's#[^/]*/#../#g'`; \
	    echo "Processing $$i ($$top_folder)"; \
	    xsltproc --html --stringparam topfolder "$$top_folder" \
		     --output $$i.tmp ./xmlsec.xsl $$i; \
	    if [ $$? != 0 ]; \
	    then \
		echo "ERROR: processing file $$i"; \
		exit 1; \
	    fi; \
	    mv $$i.tmp $$i; \
	done)
	@(echo "Cleaning html documents"; \
	for i in `find . -name "*.html" -print`; \
	do \
	    echo Cleaning $$i ; \
	    sed 's/\xA0/ /g' $$i > $$i.tmp ; \
	    mv $$i.tmp $$i ; \
	done)

dist-hook:
	@$(CP) -p $(srcdir)/*.html $(distdir)

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/api
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/api/images
	-@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/images/*.gif $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images
	-@INSTALL@ -m 0644 $(srcdir)/api/*.html $(srcdir)/api/*.png $(srcdir)/api/*.sgml $(DESTDIR)$(TARGET_DIR)/api
	-@INSTALL@ -m 0644 $(srcdir)/api/images/*.png $(DESTDIR)$(TARGET_DIR)/api/images

uninstall-local:
	@rm -rf $(DESTDIR)$(TARGET_DIR)
