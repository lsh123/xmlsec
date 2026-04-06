#
# docs/md/examples/Makefile.am
# Logic to generate per-example Markdown files from C/XML source files.
# Files are generated into the build directory ($(builddir)).
# make clean removes them; make dist includes them via dist-hook.
#
NULL =
MODULE = xmlsec

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

.PHONY: all docs examples-md

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs: examples-md

else

docs:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

#
# Generate per-example Markdown files from C/XML sources into $(builddir).
#
examples-md: $(EXAMPLES_SOURCE_FILES)
	@echo "-- Generating examples Markdown files ..."
	@$(PYTHON3) $(GEN_EXAMPLES_MD) $(EXAMPLES_SOURCE_DIR) $(builddir)

dist-hook: examples-md
	@echo "-- Copying examples Markdown files to dist ..."
	@$(CP) $(builddir)/*.md $(distdir)/

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/*.md ; \
		fi ; \
	)
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
			echo "WARNING: Skipping examples docs installation: missing necessary tools to build examples docs" ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)
