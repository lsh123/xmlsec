#
# docs/md/Makefile.am
# Markdown source files for the XML Security Library documentation.
# Per-example Markdown generation is handled by docs/md/examples/Makefile.am.
#
NULL =
MODULE = xmlsec

# target installation directory
TARGET_DIR = @XMLSEC_DOCDIR@

SUBDIRS = examples api tutorial

XMLSEC1_MAN = $(top_builddir)/man/xmlsec1.1
XMLSEC1_MAN_MD = $(builddir)/xmlsec-man.md

# Top-level Markdown source files distributed from here
TOPLEVEL_MD_FILES = $(notdir $(wildcard $(srcdir)/*.md))

# files that are distributed from sources
EXTRA_DIST := \
	$(TOPLEVEL_MD_FILES) \
	$(NULL)

.PHONY: all docs docs-copy docs-manpages

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"


docs: docs-manpages docs-copy
	@$(MAKE) $(AM_MAKEFLAGS) -C examples docs
	@$(MAKE) $(AM_MAKEFLAGS) -C api docs
	@$(MAKE) $(AM_MAKEFLAGS) -C tutorial docs

docs-copy:
	@if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
		echo "-- Copying top-level Markdown files to build dir ..." ; \
		$(CP) $(srcdir)/*.md $(builddir)/ ; \
	fi

if BUILD_MD_DOCS

docs-manpages: $(XMLSEC1_MAN)
	@echo "-- Building docs for man page ..."
	@printf '# XML Security Library: Command Line Utility\n\n' > $(XMLSEC1_MAN_MD)
	@$(PANDOC) \
		--from=man \
		--to=markdown \
		$(XMLSEC1_MAN) >> $(XMLSEC1_MAN_MD)

else

docs-manpages:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

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

