NULL =

SUBDIRS = sgml html

.PHONY: all docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C sgml docs
	@$(MAKE) $(AM_MAKEFLAGS) -C html docs
