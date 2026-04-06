NULL =

SUBDIRS = \
	$(NULL)

TARGET_DIR = @XMLSEC_DOCDIR@


# files that are copied from sources
EXTRA_DIST := \
	$(srcdir)/images 					\
	$(srcdir)/css 						\
	$(srcdir)/xmlsec.xsl				\
	$(srcdir)/pandoc-template.html5		\
	$(srcdir)/favicon.ico				\
    $(NULL)

XMLSEC1_MAN  = $(top_builddir)/man/xmlsec1.1
XMLSEC_HTML  = $(builddir)/xmlsec-man.html

.PHONY: all docs docs-manpages docs-copy

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"


# if we build html docs then we need to have xsltproc
if BUILD_HTML_DOCS

docs: docs-manpages docs-copy
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
	@$(MAKE) $(AM_MAKEFLAGS)

else

docs: docs-manpages
	@( \
		echo "=== ERROR: To build docs, make sure all necessary tools are installed" ; \
		echo "SED:      $SED" ; \
		echo "SORT:     $SORT" ; \
		echo "XSLTPROC: $XSLTPROC" ; \
		exit 1; \
	)

endif

if BUILD_MAN_DOCS
docs-manpages: docs-copy $(XMLSEC1_MAN)
	@echo "-- Building docs for man page ..."
	@($(MAN2HTML) $(XMLSEC1_MAN) | \
		  $(GREP) -v '^Content-type: text/html' | \
		  tr "[:cntrl:]" " " | \
		  $(SED) -e 's|<a href="/cgi-bin/man/man2html">Return to Main Contents</a>||ig' \
		         -e 's|<a href="/cgi-bin/man/man2html">\([^<]*\)</a>|\1|ig' > \
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
			$(CP)  $(srcdir)/*.ico $(builddir)/ ; \
			mkdir -p  $(builddir)/images $(builddir)/css ; \
			$(CP) -r $(srcdir)/images/* $(builddir)/images/ ; \
			$(CP) -r $(srcdir)/css/* $(builddir)/css/ ; \
		fi ; \
	)


clean-local:
	@( \
		$(RM) -f *.stamp ; \
		if [ z"$(srcdir)" != z"$(builddir)" ] ; then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
			$(RM) -rf $(builddir)/images ; \
			$(RM) -rf $(builddir)/css ; \
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

