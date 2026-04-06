NULL =

SUBDIRS = \
	$(NULL)

TARGET_DIR = @XMLSEC_DOCDIR@

# Markdown source files for generated HTML pages (all *.md in docs/md/)
MD_SRCDIR     = $(top_srcdir)/docs/md
MD_SRC_FILES  = $(wildcard $(MD_SRCDIR)/*.md)

# files that are copied from sources
EXTRA_DIST := \
	$(srcdir)/images 					\
	$(srcdir)/css 						\
	$(srcdir)/xmlsec.xsl				\
	$(srcdir)/pandoc-template.html5		\
	$(srcdir)/favicon.ico				\
    $(NULL)

.PHONY: all docs docs-copy docs-md

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"


# if we build html docs then we need to have xsltproc
if BUILD_HTML_DOCS

docs: docs-copy docs-md
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

docs: docs-copy docs-md
	@( \
		echo "=== ERROR: To build docs, make sure all necessary tools are installed" ; \
		echo "SED:      $(SED)" ; \
		echo "SORT:     $(SORT)" ; \
		echo "XSLTPROC: $(XSLTPROC)" ; \
		exit 1; \
	)

endif

# Convert all *.md files from docs/md/ to HTML using pandoc.
# The pandoc template adds the <head> structure; xsltproc (above) then wraps
# each output with the navigation panel just like all other HTML pages.
if BUILD_MD_DOCS
docs-md: $(MD_SRC_FILES)
	@echo "-- Generating HTML from Markdown files in $(MD_SRCDIR) ..."
	@for f in $(MD_SRC_FILES); do \
		out=$(builddir)/`basename $$f .md`.html ; \
		echo "--- Converting $$f -> $$out" ; \
		$(PANDOC) \
			--standalone \
			--template=$(srcdir)/pandoc-template.html5 \
			--from=markdown --to=html5 \
			--output=$$out \
			$$f ; \
	done
else
docs-md:
	@echo "-- Note: Skipping Markdown-to-HTML generation (pandoc not available)"
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

