#
# make all 		: prints info message
# make docs		: generates the XML and HTML API docs (if the necessary tools are present) or prints an error
# make install  : does nothing
# make dist     : does nothing (on top of usual stuff)
#
NULL =

DOXYFILE    = Doxyfile
XML_OUTDIR  = xml
HTML_OUTDIR = html
# TODO: remove html output here and in Doxyfile.in after Doxygen upgrades to version > 1.13.0
# there is a bug with Doxygen that generates incorrect warnings without HTML output (https://github.com/doxygen/doxygen/issues/11147)


DISTCLEANFILES = \
	$(DOXYFILE) \
	$(NULL)

EXTRA_DIST = \
	Doxyfile.in \
	doxygen_filter.py \
	wincrypt.h \
	windows.h \
	$(NULL)


.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs/xml/api folder to rebuild doxygen docs"


#
# Generate XML and HTML files from C sources into $(builddir).
#
if BUILD_XML_API_DOCS

docs: $(DOXYFILE)
	@echo "-- Generating doxygen XML and HTML API docs..."
	@$(DOXYGEN) $(builddir)/$(DOXYFILE)
	@echo "-- Done. Output: $(builddir)/$(XML_OUTDIR) (XML), $(builddir)/$(HTML_OUTDIR) (HTML)"

else

docs:
	@(echo "=== ERROR: To build API XML docs, make sure doxygen and python3 are installed"; exit 1; )

endif

clean-local:
	-$(RM) -rf "$(builddir)/$(HTML_OUTDIR)"
	-$(RM) -rf "$(builddir)/$(XML_OUTDIR)"

distclean-local: clean-local
