NULL =

DOXYFILE    = Doxyfile
XML_OUTDIR  = xml

.PHONY: all docs clean-docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs/xml/api folder to rebuild doxygen docs"

if BUILD_DOXYGEN_DOCS

docs:
	@echo "-- Generating doxygen XML API docs..."
	@$(DOXYGEN) $(builddir)/$(DOXYFILE)
	@echo "-- Done. XML output: $(abs_top_builddir)/docs/xml/api/$(XML_OUTDIR)"

else

docs:
	@echo "=== ERROR: doxygen not found, cannot build API docs"; exit 1

endif

clean-local:
	-rm -rf "$(abs_top_builddir)/docs/xml/api/$(XML_OUTDIR)"

DISTCLEANFILES = \
    $(DOXYFILE) \
    $(NULL)

EXTRA_DIST = \
    Doxyfile.in \
    wincrypt.h \
    windows.h \
    $(NULL)
