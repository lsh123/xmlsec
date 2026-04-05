#
# docs/md/tutorial/Makefile.am
# Tutorial Markdown source files for the XML Security Library documentation.
# Files are copied from $(srcdir) to $(builddir) when they differ.
#
NULL =
MODULE = xmlsec

TUTORIAL_MD_FILES = $(notdir $(wildcard $(srcdir)/*.md))

TUTORIAL_IMAGE_FILES = $(addprefix images/,$(notdir $(wildcard $(srcdir)/images/*.png)))

# files that are distributed from sources
EXTRA_DIST := \
	$(TUTORIAL_MD_FILES) \
	$(TUTORIAL_IMAGE_FILES) \
	$(NULL)

.PHONY: all docs tutorial-md

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

if BUILD_MD_DOCS

docs: tutorial-md

else

docs:
	@(echo "=== ERROR: To build Markdown docs, make sure pandoc and python3 are installed" ; exit 1; )

endif

#
# Copy tutorial Markdown and image files from $(srcdir) to $(builddir) when they differ.
#
tutorial-md:
	@if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
		echo "-- Copying tutorial Markdown files to build dir ..." ; \
		$(MKDIR_P) $(builddir)/images ; \
		for f in $(TUTORIAL_MD_FILES) ; do \
			$(CP) $(srcdir)/$$f $(builddir)/$$f ; \
		done ; \
		for f in $(TUTORIAL_IMAGE_FILES) ; do \
			$(CP) $(srcdir)/$$f $(builddir)/$$f ; \
		done ; \
	fi

dist-hook: tutorial-md
	echo "--- All tutoria Markdown files are already copied"

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/*.md ; \
			$(RM) -f $(builddir)/images/*.png ; \
		fi ; \
	)
