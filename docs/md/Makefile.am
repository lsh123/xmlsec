#
# docs/md/Makefile.am
# Markdown source files for the XML Security Library documentation.
# Per-example Markdown generation is handled by docs/md/examples/Makefile.am.
#
NULL =
MODULE = xmlsec

SUBDIRS = examples api tutorial

# Top-level Markdown source files distributed from here
TOPLEVEL_MD_FILES = $(notdir $(wildcard $(srcdir)/*.md))

# files that are distributed from sources
EXTRA_DIST := \
	$(TOPLEVEL_MD_FILES) \
	$(NULL)

XMLSEC1_MAN = $(top_builddir)/man/xmlsec1.1
XMLSEC1_MAN_MD = $(builddir)/xmlsec-man.md

.PHONY: all docs docs-manpages

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C examples docs
	@$(MAKE) $(AM_MAKEFLAGS) -C api docs
	@$(MAKE) $(AM_MAKEFLAGS) -C tutorial docs
	@$(MAKE) $(AM_MAKEFLAGS) docs-manpages

docs-manpages: $(XMLSEC1_MAN)
	@echo "-- Building docs for man page ..."
	@$(PANDOC) \
		--from=man \
		--to=markdown \
		--output=$(XMLSEC1_MAN_MD) \
		$(XMLSEC1_MAN)

else

docs:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

docs-manpages:
	@echo "-- Skipping building docs for man page (pandoc not available) ..."

endif
