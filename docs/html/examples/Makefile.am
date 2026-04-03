#
# docs/html/examples/Makefile.am
# HTML generation for the examples documentation from Markdown files.
# Example Markdown files are generated from C/XML source files, then
# converted to HTML with pandoc. One HTML file per Markdown source file.
#
NULL =
MODULE = xmlsec

TARGET_DIR = @XMLSEC_DOCDIR@/examples

# Markdown source directory (generated files are kept in the source tree)
MD_SRC_DIR = $(top_srcdir)/docs/md/examples

# Script that generates example Markdown files from C/XML source
GEN_EXAMPLES_MD = $(top_srcdir)/scripts/gen-examples-md.sh

# C and XML source files used as inputs for examples-md
EXAMPLES_SOURCE_DIR = $(top_srcdir)/examples
EXAMPLES_SOURCE_FILES = \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print)

# files that are distributed from sources
EXTRA_DIST := \
    $(NULL)

.PHONY: all docs html examples-md

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs: html

else

docs:
	@(echo "=== ERROR: To build examples docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

#
# Generate (or refresh) the per-example Markdown files from C/XML sources.
# The resulting files live in the source tree so they are always available
# even without a build; make clean does NOT remove them.
#
examples-md: $(EXAMPLES_SOURCE_FILES)
	@echo "-- Generating examples Markdown files ..."
	@sh $(GEN_EXAMPLES_MD) $(EXAMPLES_SOURCE_DIR) $(top_srcdir)/docs/md/examples

html: examples-md
	@echo "-- Generating examples HTML from Markdown ..."
	@for md in $(MD_SRC_DIR)/*.md; do \
		base=$$(basename $$md .md); \
		title=$$(head -1 $$md | $(SED) 's/^# //'); \
		echo "--- Converting $$base.md -> $$base.html"; \
		$(PANDOC) -f gfm -t html5 --standalone --wrap=none \
			--template=$(top_srcdir)/docs/html/pandoc-template.html5 \
			-M title="XML Security Library: $$title" \
			-o $(builddir)/$$base.html $$md || exit 1; \
		$(SED) -i 's/href="\([^"]*\)\.md"/href="\1.html"/g' $(builddir)/$$base.html; \
	done

dist-hook:
	@( \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Copying to dist builddir examples html ..." ; \
			$(CP) $(builddir)/*.html $(distdir)/ ; \
		else \
			echo "-- Copying to dist source examples html ..." ; \
			$(CP) $(srcdir)/*.html $(distdir)/ ; \
		fi ; \
	)

clean-local:
	@$(RM) -f *.stamp *.bak fixxref.sed
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
		fi ; \
	)

distclean-local: clean-local

install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Installing builddir examples html docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "-- Installing srcdir examples html docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)

