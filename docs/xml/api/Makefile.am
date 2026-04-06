NULL =

DOXYFILE    = Doxyfile
XML_OUTDIR  = xml
HTML_OUTDIR = html
# TODO: remove html output here and in Doxyfile.in after Doxygen upgrades to version > 1.13.0
# there is a bug with Doxygen that generates incorrect warning w/o html output (https://github.com/doxygen/doxygen/issues/11147)

.PHONY: all docs clean-docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs/xml/api folder to rebuild doxygen docs"

if BUILD_XML_API_DOCS

docs:
	@echo "-- Generating doxygen XML API docs..."
	@$(DOXYGEN) $(builddir)/$(DOXYFILE)
	@echo "-- Done. XML output: $(abs_top_builddir)/docs/xml/api/$(XML_OUTDIR)"
	@echo "--       HTML output: $(abs_top_builddir)/docs/xml/api/$(HTML_OUTDIR)"

else

docs:
	@echo "=== ERROR: doxygen not found, cannot build API docs"; exit 1

endif

clean-local:
	-rm -rf "$(abs_top_builddir)/docs/xml/api/$(HTML_OUTDIR)"
	-rm -rf "$(abs_top_builddir)/docs/xml/api/$(XML_OUTDIR)"

DISTCLEANFILES = \
    $(DOXYFILE) \
    $(NULL)

EXTRA_DIST = \
    Doxyfile.in \
    wincrypt.h \
    windows.h \
    $(NULL)

