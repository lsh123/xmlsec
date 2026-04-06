NULL =

SUBDIRS = \
	$(NULL)

TARGET_DIR = @XMLSEC_DOCDIR@

# Markdown source files for generated HTML pages (all *.md in docs/md/)
MD_SRCDIR     = $(top_srcdir)/docs/md
MD_BUILDDIR   = $(top_builddir)/docs/md
MD_SRC_FILES  = \
	$(wildcard $(MD_SRCDIR)/*.md) \
	$(wildcard $(MD_BUILDDIR)/*.md) \
	$(NULL)

# files that are copied from sources
EXTRA_DIST := \
	$(srcdir)/images 					\
	$(srcdir)/css 						\
	$(srcdir)/pandoc-template.html5		\
	$(srcdir)/favicon.ico				\
    $(NULL)

.PHONY: all docs docs-copy docs-build-html

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

docs: docs-copy docs-build-html


if BUILD_HTML_DOCS
# Convert all *.md files from docs/md/ to HTML using pandoc.
# The pandoc template adds the navigation panel and <head> structure.
docs-build-html: $(MD_SRC_FILES)
	@echo "-- Generating HTML from Markdown files in $(MD_SRCDIR) ..."
	@for f in $(MD_SRC_FILES); do \
		out=$(builddir)/`basename $$f .md`.html ; \
		title=`grep -m1 '^# ' $$f | sed -E 's/^# //'` ; \
		echo "--- Converting $$f -> $$out (title: $$title)" ; \
		$(PANDOC) \
			--standalone \
			--template=$(srcdir)/pandoc-template.html5 \
			--from=markdown --to=html5 \
			--metadata title="$$title" \
			--output=$$out \
			$$f ; \
		$(SED) -E -i 's|href="(\.\./)*api/index\.md(#[^"]*)?"|href="https://github.com/lsh123/xmlsec/wiki/API-Index\2"|g' $$out ; \
		$(SED) -E -i 's|href="(\.\./)*tutorial/index\.md(#[^"]*)?"|href="https://github.com/lsh123/xmlsec/wiki/Tutorial-Index\2"|g' $$out ; \
		$(SED) -E -i 's|href="(\.\./)*examples/index\.md(#[^"]*)?"|href="https://github.com/lsh123/xmlsec/wiki/Examples-Index\2"|g' $$out ; \
		$(SED) -E -i 's|href="([^"#:]*)\.md(#[^"]*)?"|href="\1.html\2"|g' $$out ; \
		$(SED) -E -i 's|<td([^>]*)>(Yes)|<td class="supported-feature"\1>\2|g' $$out ; \
	done
else
docs-build-html:
	@( \
		echo "=== ERROR: To build docs, make sure all necessary tools are installed" ; \
		echo "SED:      $(SED)" ; \
		echo "SORT:     $(SORT)" ; \
		echo "PANDOC:   $(PANDOC)" ; \
		exit 1; \
	)

endif

docs-copy:
	@( \
		echo "-- Copying source html to build folder ..." ; \
		if [ z"$(srcdir)" != z"$(builddir)" ] ; then  \
			$(CP)  $(srcdir)/*.ico $(builddir)/ ; \
			mkdir -p  $(builddir)/images $(builddir)/css ; \
			$(CP) -r $(srcdir)/images/* $(builddir)/images/ ; \
			$(CP) -r $(srcdir)/css/* $(builddir)/css/ ; \
		fi ; \
	)


clean-local:
	@( \
		$(RM) -f *.stamp ; \
		$(RM) -rf $(builddir)/*.html ; \
		if [ z"$(srcdir)" != z"$(builddir)" ] ; then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.ico ; \
			$(RM) -rf $(builddir)/images ; \
			$(RM) -rf $(builddir)/css ; \
		fi ; \
	 )

