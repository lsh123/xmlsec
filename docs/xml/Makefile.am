NULL =

SUBDIRS = api

.PHONY: all docs

all:
	@echo "======= Run 'make docs' in the xmlsec/docs/xml folder to rebuild doxygen XML docs"

docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C api docs
