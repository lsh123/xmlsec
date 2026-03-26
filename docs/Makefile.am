NULL =

SUBDIRS=api

TARGET_DIR=@XMLSEC_DOCDIR@


# files that are copied from sources
EXTRA_DIST := \
	$(srcdir)/images 					\
	$(srcdir)/css 						\
	$(srcdir)/xmlsec.xsl				\
	$(srcdir)/favicon.ico				\
    $(NULL)

XMLSEC1_MAN=$(builddir)/../man/xmlsec1.1
XMLSEC_HTML=$(builddir)/xmlsec-man.html

.PHONY: all docs docs-api docs-manpages docs-copy

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"


# if we build api docs then we also have xsltproc
if BUILD_API_DOCS

docs: docs-manpages docs-api docs-copy
	@(echo "-- Formatting html documents"; \
	for i in `find $(builddir) -name "*.html" -print`; \
	do \
	    top_folder=`echo $$i | $(SED) 's#/[^/]*$$#/#' | $(SED) 's#\./##' | \
			$(SED) 's#[^/]*/#../#g'`; \
	    echo "--- Processing $$i (topfolder='$$top_folder')"; \
	    $(XSLTPROC) --html --stringparam topfolder "$$top_folder" \
		     --output $$i.tmp $(srcdir)/xmlsec.xsl $$i; \
	    if [ $$? != 0 ]; \
	    then \
			echo "ERROR: processing file $$i"; \
			exit 1; \
	    fi; \
	    $(MV) $$i.tmp $$i; \
	done)
	@(echo "-- Cleaning html documents"; \
	for i in `find $(builddir) -name "*.html" -print`; \
	do \
	    echo "--- Cleaning $$i" ; \
	    $(SED) 's/\xC2\xA0/ /g' $$i > $$i.tmp ; \
	    $(MV) $$i.tmp $$i ; \
	done)

else

docs: docs-manpages docs-api
	@(echo "=== ERROR: To build docs, make sure all necessary tools are installed" ; exit 1; )

endif

if BUILD_MAN_DOCS
docs-manpages: docs-copy $(XMLSEC1_MAN)
	@echo "-- Building docs for man page ..."
	@($(MAN2HTML) $(XMLSEC1_MAN) | \
		  $(GREP) -v '^Content-type: text/html' | \
		  tr "[:cntrl:]" " " > \
		  $(XMLSEC_HTML) \
	)
else

docs-manpages: docs-copy
	@echo "-- Skipping building docs for man page ..."

endif

docs-copy:
	@( \
		echo "-- Copying source html to build folder ..." ; \
		if [ z"$(srcdir)" != z"$(builddir)" ] ; then  \
			$(CP)  $(srcdir)/*.html $(builddir)/ ; \
		fi ; \
	)

docs-api:
	make -C api docs

clean-local:
	@( \
		$(RM) -f *.stamp ; \
		if [ z"$(srcdir)" != z"$(builddir)" ] ; then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
		fi ; \
	 )

dist-hook:
	@( \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Copying to dist builddir html docs ..." ; \
			$(CP) $(builddir)/*.html $(distdir)/ ; \
		else \
			echo "-- Copying to dist source html docs ..." ; \
			$(CP) $(srcdir)/*.html $(distdir)/ ; \
		fi ; \
	)

distclean-local: clean-local

install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Installing builddir html docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "-- Installing srcdir html docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
		fi ; \
	)
	@( \
		echo "-- Installing images ..." ; \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
		@INSTALL@ -m 0644 $(srcdir)/*.ico  $(DESTDIR)$(TARGET_DIR) ; \
		@INSTALL@ -m 0644 $(srcdir)/images/*.gif $(DESTDIR)$(TARGET_DIR)/images/ ; \
		@INSTALL@ -m 0644 $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
	)
	@( \
		echo "-- Installing css ..." ; \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/css ; \
		@INSTALL@ -m 0644 $(srcdir)/css/*.css $(DESTDIR)$(TARGET_DIR)/css/ ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)

