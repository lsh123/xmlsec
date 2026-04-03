#
# docs/html/api/Makefile.am
# HTML-only generation for the API reference documentation.
# SGML preparation (scanning, mkdb, fixups) is handled by docs/sgml/.
#
NULL =
MODULE = xmlsec

TARGET_DIR = @XMLSEC_DOCDIR@/api

# Processed SGML produced by docs/sgml/Makefile.am
MAIN_SGML_FILE = $(top_builddir)/docs/sgml/api/sgml.tmp/xmlsec.sgml

# files that are distributed from sources (HTML + assets committed in tree)
EXTRA_DIST := \
    $(NULL)

.PHONY: all docs html

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

# if build API docs, then we also have xsltproc
if BUILD_API_DOCS

docs: html
	@( \
		echo "-- Cleaning up result files"; \
		for f in `find . -name "*.html" -print` ; do \
			echo "-- Processing $$f..."; \
			$(SED) -i 's/<GTKDOCLINK[^>]*>/<font>/gI; s/<\/GTKDOCLINK[^>]*>/<\/font>/gI' "$$f" ; \
		done \
	)
else

docs:
	@(echo "=== ERROR: To build API docs, make sure all necessary tools are installed" ; exit 1; )
endif


html: $(MAIN_SGML_FILE)
	@$(GTKDOC_MKHTML) xmlsec $(MAIN_SGML_FILE)

dist-hook:
	@( \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Copying to dist builddir html docs, css, png ..." ; \
			$(CP) $(builddir)/*.html $(distdir)/ ; \
			$(CP) $(builddir)/*.css $(distdir)/ ; \
			$(CP) $(builddir)/*.png $(distdir)/ ; \
		else \
			echo "-- Copying to dist source html docs, css, png ..." ; \
			$(CP) $(srcdir)/*.html $(distdir)/ ; \
			$(CP) $(srcdir)/*.css $(distdir)/ ; \
			$(CP) $(srcdir)/*.png $(distdir)/ ; \
		fi ; \
	)

clean-local:
	@$(RM) -f *.stamp *.bak
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
			(chmod -Rf u+w $(builddir)/*.css 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.css ; \
			(chmod -Rf u+w $(builddir)/*.png 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.png ; \
			(chmod -Rf u+w $(builddir)/xmlsec.devhelp2 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/xmlsec.devhelp2 ; \
		fi ; \
	)

distclean-local: clean-local

install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Installing builddir api html docs, css, png ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/*.css $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/*.png $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "-- Installing srcdir api html docs, css, png ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/*.css $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/*.png $(DESTDIR)$(TARGET_DIR) ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)
