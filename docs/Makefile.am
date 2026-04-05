NULL =

SUBDIRS = xml md html

.PHONY: all docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C xml docs
	@$(MAKE) $(AM_MAKEFLAGS) -C md docs
	@$(MAKE) $(AM_MAKEFLAGS) -C html docs

