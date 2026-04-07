#
# make all 		: prints info message
# make docs		: generates the MD files (if necessary tools are present) or prints error
# make install  : tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
# make dist     : tries to copy MD files to dist dir first from builddir, then srcdir, then prints warning
#
NULL =

# target installation directory
TARGET_DIR = @XMLSEC_DOCDIR@/tutorial

.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

#
# Copy tutorial Markdown and image files from $(srcdir) to $(builddir) when they differ.
#
docs:
	@if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
		echo "-- Copying tutorial files to build dir ..." ; \
		$(MKDIR_P) $(builddir)/images ; \
		$(CP) $(srcdir)/*.md $(builddir)/ ; \
		$(CP) $(srcdir)/images/*.png $(builddir)/images/ ; \
	fi

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/*.md ; \
			$(RM) -rf $(builddir)/images ; \
		fi ; \
	)

distclean-local: clean-local

#
# Tries to copy MD files to install dir first from builddir, then srcdir, then prints warning
#
install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Installing builddir tutorial docs ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Installing srcdir tutorial docs ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
    		@INSTALL@ -m 0644 $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
		else \
			echo "WARNING: Skipping tutorial docs installation: missing necessary tools to build tutorial docs" ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)


#
# Tries to copy MD files to dist dir first from builddir, then srcdir, then prints warning
#
dist-hook:
	@( \
		mkdir -p  $(distdir)/images ; \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Copying builddir tutorial docs ..." ; \
			$(CP) $(builddir)/*.md $(distdir)/ ; \
			$(CP) $(builddir)/images/* $(distdir)/images/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Copying srcdir tutorial docs ..." ; \
			$(CP) $(srcdir)/*.md $(distdir)/ ; \
			$(CP) $(srcdir)/images/* $(distdir)/images/ ; \
		else \
			echo "WARNING: Skipping tutorial docs dist (rebuild docs with 'make -C docs docs')" ; \
		fi ; \
	)


