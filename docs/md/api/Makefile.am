#
# make all 		: prints info message
# make docs		: regenerates the MD files (if necessary tools are present) or prints error
# make install  : tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
# make dist     : tries to copy MD files to dist dir first from builddir, then srcdir, then prints warning
#
NULL =

# target installation directory
TARGET_DIR = @XMLSEC_DOCDIR@/api

# Script that generates API Markdown files from Doxygen XML group files
GEN_API_MD = $(srcdir)/gen-api-md.py

# Input directory: Doxygen XML output (produced by docs/xml/api)
XML_API_DIR = $(abs_top_builddir)/docs/xml/api/xml

# files that are distributed from sources
EXTRA_DIST := \
	$(srcdir)/gen-api-md.py \
	$(NULL)

.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

#
# Generate per-group API Markdown files from Doxygen XML into $(builddir).
# The xml docs target must run first to produce the XML input files.
#
if BUILD_MD_DOCS

docs:
	@echo "-- Generating API Markdown files ..."
	@if [ ! -d "$(XML_API_DIR)" ]; then \
		echo "-- XML API directory not found, generating XML files first ..."; \
		$(MAKE) $(AM_MAKEFLAGS) -C $(abs_top_builddir)/docs/xml/api docs; \
	fi
	@$(PYTHON3) $(GEN_API_MD) "$(PACKAGE_VERSION)" "$(XML_API_DIR)" "$(builddir)"

else

docs:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/*.md ; \
		fi ; \
	)

distclean-local: clean-local

#
# Tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
#
install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Installing builddir API docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Installing srcdir API docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "WARNING: Skipping API docs installation: missing necessary tools to build API docs" ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)


#
# Tries to copy MD files to dist dir first from builddir, then srcdir, then prints warning
#
dist-hook:
	@( \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Copying builddir API docs ..." ; \
			$(CP) $(builddir)/*.md $(distdir)/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Copying srcdir API docs ..." ; \
			$(CP) $(srcdir)/*.md $(distdir)/ ; \
		else \
			echo "WARNING: Skipping API docs dist (rebuild docs with 'make -C docs docs')" ; \
		fi ; \
	)


