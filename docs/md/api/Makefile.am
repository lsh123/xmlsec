#
# docs/md/api/Makefile.am
# Generate per-group API Markdown files from Doxygen XML output.
# Files are generated into the build directory ($(builddir)).
# make clean removes them; make dist includes them via dist-hook.
#
NULL =
MODULE = xmlsec

# Script that generates API Markdown files from Doxygen XML group files
GEN_API_MD = $(srcdir)/gen-api-md.py

# Input directory: Doxygen XML output (produced by docs/xml/api)
XML_API_DIR = $(abs_top_builddir)/docs/xml/api/xml

# files that are distributed from sources
EXTRA_DIST := \
	$(srcdir)/gen-api-md.py \
	$(NULL)

.PHONY: all docs api-md

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs: api-md

else

docs:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

#
# Generate per-group API Markdown files from Doxygen XML into $(builddir).
# The xml docs target must run first to produce the XML input files.
#
api-md:
	@echo "-- Generating API Markdown files ..."
	@if [ ! -d "$(XML_API_DIR)" ]; then \
		echo "-- XML API directory not found, generating XML files first ..."; \
		$(MAKE) $(AM_MAKEFLAGS) -C $(abs_top_builddir)/docs/xml/api docs; \
	fi
	@$(PYTHON3) $(GEN_API_MD) "$(XML_API_DIR)" "$(builddir)"

dist-hook: api-md
	@echo "-- Copying API Markdown files to dist ..."
	@$(CP) $(builddir)/*.md $(distdir)/

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/*.md ; \
		fi ; \
	)
