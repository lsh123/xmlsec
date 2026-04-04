NULL =

DOXYFILE    = Doxyfile
HTML_OUTDIR = html

.PHONY: all docs clean-docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs.doxygen folder to rebuild doxygen docs"

if BUILD_DOXYGEN_DOCS

docs:
	@echo "-- Generating doxygen HTML API docs..."
	@$(DOXYGEN) $(builddir)/$(DOXYFILE)
	@echo "-- Done. HTML output: $(abs_top_builddir)/docs.doxygen/$(HTML_OUTDIR)"

else

docs:
	@echo "=== ERROR: doxygen not found, cannot build API docs"; exit 1

endif

clean-local:
	-rm -rf "$(abs_top_builddir)/docs.doxygen/$(HTML_OUTDIR)"

DISTCLEANFILES = \
    $(DOXYFILE) \
    $(NULL)

EXTRA_DIST = \
    Doxyfile.in \
    $(NULL)
