#
# make all 		: prints info message
# make docs		: generates the MD files (if necessary tools are present) or prints error
# make install  : tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
# make dist     : tries to copy MD files to dist dir first from builddir, then srcdir, then prints warning
#
NULL =

# target installation directory
TARGET_DIR = @XMLSEC_DOCDIR@/examples

# Script that generates example Markdown files from C/XML source
GEN_EXAMPLES_MD = $(srcdir)/gen-examples-md.py

# C and XML source files used as inputs for examples-md
EXAMPLES_SOURCE_DIR = $(top_srcdir)/examples
EXAMPLES_SOURCE_FILES = \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print)

# files that are distributed from sources
EXTRA_DIST := \
	$(srcdir)/gen-examples-md.py \
	$(NULL)

.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"


#
# Generate per-example Markdown files from C/XML sources into $(builddir).
#
if BUILD_MD_DOCS

docs: $(EXAMPLES_SOURCE_FILES)
	@echo "-- Generating examples Markdown files ..."
	@$(PYTHON3) $(GEN_EXAMPLES_MD) $(EXAMPLES_SOURCE_DIR) $(builddir)

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
			echo "-- Installing builddir examples docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Installing srcdir examples docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "WARNING: Skipping examples docs installation (rebuild docs with 'make -C docs docs')" ; \
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
			echo "-- Copying builddir examples docs ..." ; \
			$(CP) $(builddir)/*.md $(distdir)/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Copying srcdir examples docs ..." ; \
			$(CP) $(srcdir)/*.md $(distdir)/ ; \
		else \
			echo "WARNING: Skipping examples docs dist (rebuild docs with 'make -C docs docs')" ; \
		fi ; \
	)

