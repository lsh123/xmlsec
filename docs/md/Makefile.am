#
# docs/md/Makefile.am
# Markdown source files for the XML Security Library documentation.
# Per-example Markdown generation is handled by docs/md/examples/Makefile.am.
#
NULL =
MODULE = xmlsec

SUBDIRS = examples api tutorial


.PHONY: all docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C examples docs
	@$(MAKE) $(AM_MAKEFLAGS) -C api docs
	@$(MAKE) $(AM_MAKEFLAGS) -C tutorial docs

else

docs:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif
