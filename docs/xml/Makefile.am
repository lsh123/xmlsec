#
# make all 		: prints info message
# make docs		: generates the doc files (if necessary tools are present) or prints error
#
NULL =

SUBDIRS = api

.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs/xml folder to rebuild doxygen XML docs"

docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C api docs
