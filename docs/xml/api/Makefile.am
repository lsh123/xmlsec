#
# make all 		: prints info message
# make docs		: Generates the XML files (if necessary tools are present) or prints error
# make install  : does nothing
# make dist     : does nothing (on top of usual stuff)
#
NULL =

DOXYFILE    = Doxyfile
XML_OUTDIR  = xml
HTML_OUTDIR = html
# TODO: remove html output here and in Doxyfile.in after Doxygen upgrades to version > 1.13.0
# there is a bug with Doxygen that generates incorrect warning w/o html output (https://github.com/doxygen/doxygen/issues/11147)


DISTCLEANFILES = \
    $(DOXYFILE) \
    $(NULL)

EXTRA_DIST = \
    Doxyfile.in \
    wincrypt.h \
    windows.h \
    $(NULL)


.PHONY: all docs clean-docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs/xml/api folder to rebuild doxygen docs"


#
# Generate XML and HTML files from C sources into $(builddir).
#
if BUILD_XML_API_DOCS

docs:
	@echo "-- Generating doxygen XML API docs..."
	@$(DOXYGEN) $(builddir)/$(DOXYFILE)
	@echo "-- Done. XML output: $(abs_top_builddir)/docs/xml/api/$(XML_OUTDIR)"

else

docs:
	@(echo "=== ERROR: To build API XML docs, make sure doxygen is installed"; exit 1; )

endif

clean-local:
	-rm -rf "$(abs_top_builddir)/docs/xml/api/$(HTML_OUTDIR)"
	-rm -rf "$(abs_top_builddir)/docs/xml/api/$(XML_OUTDIR)"

distclean-local: clean-local
