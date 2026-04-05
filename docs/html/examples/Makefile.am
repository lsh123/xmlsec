#
# docs/html/examples/Makefile.am
# HTML generation for the examples documentation from Markdown files.
# Example Markdown files are generated into the build directory by
# docs/md/examples/Makefile.am (which runs before this step).
# One HTML file is produced per Markdown source file.
#
NULL =
MODULE = xmlsec

TARGET_DIR = @XMLSEC_DOCDIR@/examples

# Markdown source directory (generated ditorectobuild in the ry by docs/)
MD_SRC_DIR = $(top_builddir)/docs/md/examples

# files that are distributed from sources
EXTRA_DIST := \
    $(NULL)

.PHONY: all docs html

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs: html

else

docs:
	@(echo "=== ERROR: To build examples docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

html:
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

