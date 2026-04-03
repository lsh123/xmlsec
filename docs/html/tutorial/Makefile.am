#
# docs/html/tutorial/Makefile.am
# HTML-only generation for the tutorial documentation.
# SGML preparation (fixups) is handled by docs/sgml/.
#
NULL =
MODULE = xmlsec

TARGET_DIR = @XMLSEC_DOCDIR@/tutorial

# Processed SGML produced by docs/sgml/Makefile.am
MAIN_SGML_FILE = $(top_builddir)/docs/sgml/tutorial/sgml.tmp/xmlsec-tutorial.sgml

# API devhelp2 file used for cross-reference fixing
API_DEVHELP = $(top_builddir)/docs/html/api/xmlsec.devhelp2

# files that are distributed from sources
EXTRA_DIST := \
    $(srcdir)/images \
    $(NULL)

.PHONY: all docs html

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

# if build API docs, then we also have xsltproc
if BUILD_API_DOCS

docs: html
	@$(top_srcdir)/scripts/fix-html-cross-refs.sh \
		"tutorial" \
		"$(API_DEVHELP)" \
		"$(abs_builddir)" \
		"$(GREP)" \
		"$(SED)"

else

docs:
	@(echo "=== ERROR: To build tutorial docs, make sure all necessary tools are installed" ; exit 1; )

endif


html: $(MAIN_SGML_FILE)
	@$(GTKDOC_MKHTML) xmlsec $(MAIN_SGML_FILE)

dist-hook:
	@( \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Copying to dist builddir tutorial html, css, png ..." ; \
			$(CP) $(builddir)/*.html $(distdir)/ ; \
			$(CP) $(builddir)/*.css $(distdir)/ ; \
			$(CP) $(builddir)/*.png $(distdir)/ ; \
		else \
			echo "-- Copying to dist source tutorial html, css, png ..." ; \
			$(CP) $(srcdir)/*.html $(distdir)/ ; \
			$(CP) $(srcdir)/*.css $(distdir)/ ; \
			$(CP) $(srcdir)/*.png $(distdir)/ ; \
		fi ; \
	)

clean-local:
	@$(RM) -f *.stamp *.bak fixxref.sed
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; \
		then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
			(chmod -Rf u+w $(builddir)/*.css 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.css ; \
			(chmod -Rf u+w $(builddir)/*.png 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.png ; \
		fi ; \
	)

distclean-local: clean-local

install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Installing builddir tutorial html docs, css, png ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/*.css $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/*.png $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "-- Installing srcdir tutorial html docs, css, png ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/*.css $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/*.png $(DESTDIR)$(TARGET_DIR) ; \
		fi ; \
	)
	@( \
		echo "-- Installing tutorial images ..." ; \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
		@INSTALL@ -m 0644 $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)
