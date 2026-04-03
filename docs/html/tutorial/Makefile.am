#
# docs/html/tutorial/Makefile.am
# HTML generation for the tutorial documentation from Markdown files.
# One HTML file is produced per Markdown source file.
#
NULL =
MODULE = xmlsec

TARGET_DIR = @XMLSEC_DOCDIR@/tutorial

# Markdown source directory (committed to the source tree)
MD_SRC_DIR = $(top_srcdir)/docs/md/tutorial

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
	@(echo "=== ERROR: To build tutorial docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

html:
	@echo "-- Generating tutorial HTML from Markdown ..."
	@for md in $(MD_SRC_DIR)/*.md; do \
		base=$$(basename $$md .md); \
		title=$$(head -1 $$md | $(SED) 's/^# //'); \
		echo "--- Converting $$base.md -> $$base.html"; \
		$(PANDOC) -f gfm -t html5 --standalone --wrap=none \
			--template=$(top_srcdir)/docs/html/pandoc-template.html5 \
			-M title="XML Security Library: $$title" \
			-o $(builddir)/$$base.html $$md || exit 1; \
		$(SED) -i \
			-e 's/href="\([^"]*\)\.md"/href="\1.html"/g' \
			-e 's|<a href="[a-z][a-z]*:[A-Za-z][^"]*">\([^<]*\)</a>|<code>\1</code>|g' \
			$(builddir)/$$base.html; \
	done
	@if [ -d $(MD_SRC_DIR)/images ]; then \
		echo "-- Copying tutorial images ..."; \
		$(mkinstalldirs) $(builddir)/images; \
		$(CP) -r $(MD_SRC_DIR)/images/* $(builddir)/images/; \
	fi

dist-hook:
	@( \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Copying to dist builddir tutorial html ..." ; \
			$(CP) $(builddir)/*.html $(distdir)/ ; \
		else \
			echo "-- Copying to dist source tutorial html ..." ; \
			$(CP) $(srcdir)/*.html $(distdir)/ ; \
		fi ; \
	)
	@( \
		if test -d $(builddir)/images ; then  \
			echo "-- Copying to dist builddir tutorial images ..." ; \
			$(CP) -r $(builddir)/images $(distdir)/images ; \
		elif test -d $(srcdir)/images ; then \
			echo "-- Copying to dist source tutorial images ..." ; \
			$(CP) -r $(srcdir)/images $(distdir)/images ; \
		fi ; \
	)

clean-local:
	@$(RM) -f *.stamp *.bak
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; \
		then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
			$(RM) -rf $(builddir)/images ; \
		fi ; \
	)

distclean-local: clean-local

install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Installing builddir tutorial html docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "-- Installing srcdir tutorial html docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
		fi ; \
	)
	@( \
		echo "-- Installing tutorial images ..." ; \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
		if test -d $(builddir)/images ; then \
			@INSTALL@ -m 0644 $(builddir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
		elif test -d $(srcdir)/images ; then \
			@INSTALL@ -m 0644 $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)

