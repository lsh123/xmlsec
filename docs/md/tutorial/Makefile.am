#
# make all 		: prints info message
# make docs		: copies the static MD files and images from srcdir to builddir
# make install  : tries to copy MD files to install dir first from builddir, then srcdir, then prints a warning
# make dist     : tries to copy MD files to dist dir first from builddir, then srcdir, then prints a warning
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
# Tries to copy MD files to install dir first from builddir, then srcdir, then prints a warning
#
install-data-local:
	@( \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Installing builddir tutorial docs ..." ; \
			$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
			$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
			@INSTALL@ -m 0644 $(builddir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Installing srcdir tutorial docs ..." ; \
			$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
			$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
			@INSTALL@ -m 0644 $(srcdir)/*.md $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
		else \
			echo "WARNING: Skipping tutorial docs installation: missing tutorial docs sources in $(srcdir)" ; \
		fi ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)


#
# Tries to copy MD files to dist dir first from builddir, then srcdir, then prints a warning
#
dist-hook:
	@( \
		if test -f $(builddir)/index.md ; then  \
			echo "-- Copying builddir tutorial docs ..." ; \
			$(MKDIR_P) $(distdir)/images ; \
			$(CP) $(builddir)/*.md $(distdir)/ ; \
			$(CP) $(builddir)/images/*.png $(distdir)/images/ ; \
		elif test -f $(srcdir)/index.md ; then  \
			echo "-- Copying srcdir tutorial docs ..." ; \
			$(MKDIR_P) $(distdir)/images ; \
			$(CP) $(srcdir)/*.md $(distdir)/ ; \
			$(CP) $(srcdir)/images/*.png $(distdir)/images/ ; \
		else \
			echo "WARNING: Skipping tutorial docs dist: missing tutorial docs sources in $(srcdir)" ; \
		fi ; \
	)


