#
# make all 		: prints info message
# make docs		: generates the doc files (if necessary tools are present) or prints error
# make install  : tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
# make dist     : tries to copy MD files to dist dir first from builddir, then srcdir, then prints warning
#
NULL =
SUBDIRS = examples api tutorial

# target installation directory
TARGET_DIR = @XMLSEC_DOCDIR@

XMLSEC1_MAN = $(top_builddir)/man/xmlsec1.1
XMLSEC1_MAN_MD = $(builddir)/xmlsec-man.md

.PHONY: all docs docs-copy docs-manpages

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

#
# Generates MD files:
#   - Static *.md files are copied from sources
#   - Manpage doc file is generated from man
#   - API, examples, and tutorial, docs are generated (in that order)
#
if BUILD_MD_DOCS

docs: docs-manpages docs-copy
	@$(MAKE) $(AM_MAKEFLAGS) -C api docs
	@$(MAKE) $(AM_MAKEFLAGS) -C examples docs
	@$(MAKE) $(AM_MAKEFLAGS) -C tutorial docs

docs-copy:
	@if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
		echo "-- Copying top-level Markdown files to build dir ..." ; \
		$(CP) $(srcdir)/*.md $(builddir)/ ; \
	fi

docs-manpages:
	@if [ ! -f " $(XMLSEC1_MAN)" ]; then \
		echo "-- Man page is not built yet, rebuilding ..."; \
		$(MAKE) $(AM_MAKEFLAGS) -C $(abs_top_builddir)/man docs ; \
	fi
	@echo "-- Building docs for man page ..."
	@printf '# XML Security Library: Command Line Utility\n\n' > $(XMLSEC1_MAN_MD)
	@$(PANDOC) \
		--from=man \
		--to=markdown \
		$(XMLSEC1_MAN) >> $(XMLSEC1_MAN_MD)

else

docs, docs-copy, docs-manpages:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/*.md ; \
		fi ; \
		$(RM) -f $(XMLSEC1_MAN_MD) ; \
	)

distclean-local: clean-local

#
# Tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
#
install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Installing builddir top level docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Installing srcdir top level docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "WARNING: Skipping top level docs installation: missing necessary tools to build docs" ; \
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
			echo "-- Copying builddir top level docs ..." ; \
			$(CP) $(builddir)/*.md $(distdir)/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Copying srcdir top level docs ..." ; \
			$(CP) $(srcdir)/*.md $(distdir)/ ; \
		else \
			echo "WARNING: Skipping top level docs dist (rebuild docs with 'make -C docs docs')" ; \
		fi ; \
	)

