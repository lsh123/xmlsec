#
# make all 		: prints info message
# make docs		: generates the doc files (if necessary tools are present) or prints error
#

NULL =

SUBDIRS = xml md html

.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

#
# Special docs build
#
docs:
	@$(MAKE) $(AM_MAKEFLAGS) -C xml docs
	@$(MAKE) $(AM_MAKEFLAGS) -C md docs
	@$(MAKE) $(AM_MAKEFLAGS) -C html docs

