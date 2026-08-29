#
# make all 		: prints info message
# make docs		: generates the man pages (if the necessary tools are present) or prints an error
# make install  : copies the man pages from builddir to the install dir, or prints a warning if they are missing
# make dist     : copies the man pages from builddir to the dist dir, or prints a warning if they are missing
#
NULL =

# target installation directory
TARGET_DIR = @XMLSEC_MANDIR@

XMLSEC1_MAN=xmlsec1.1
XMLSEC1_CONFIG_MAN=xmlsec1-config.1

XMLSEC_PROGRAM=$(top_builddir)/apps/xmlsec1
XMLSEC_CONFIG_PROGRAM=$(top_builddir)/xmlsec1-config

.PHONY: all docs

#
# Docs are not built as part of normal build
#
all:
	@echo "======= Run 'make docs' in the xmlsec/man folder to rebuild man pages"

#
# Generate man pages into $(builddir).
#
if BUILD_MAN_DOCS

docs:
	@if [ ! -f "$(XMLSEC_PROGRAM)" ]; then \
		echo "-- XMLSec command line tool app is not built yet, rebuilding ..."; \
		$(MAKE) $(AM_MAKEFLAGS) -C $(abs_top_builddir) all ; \
	fi
	@echo "Building xmlsec1 manpage ..."
	@$(HELP2MAN) --help-option=--help-all --no-info \
		--name="sign, verify, encrypt and decrypt XML documents" \
		--version-option=--version \
		--output=$(XMLSEC1_MAN) \
		$(XMLSEC_PROGRAM)
	@echo "Building xmlsec1-config manpage ..."
	@$(HELP2MAN) --help-option=--help --no-info \
		--name="details about the installed version of the xmlsec library" \
		--version-option=--version \
		--output=$(XMLSEC1_CONFIG_MAN) \
		$(XMLSEC_CONFIG_PROGRAM)
else

docs:
	@(echo "=== ERROR: To build man pages, make sure help2man is installed" ; exit 1; )

endif

clean-local:
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
			$(RM) -f $(builddir)/$(XMLSEC1_MAN) ; \
			$(RM) -f $(builddir)/$(XMLSEC1_CONFIG_MAN) ; \
		fi ; \
	)

distclean-local: clean-local

#
# Copies the man pages from builddir to the install dir, or prints a warning if they are missing.
#
install-data-local:
	@( \
		if test -f $(builddir)/$(XMLSEC1_MAN); then  \
			echo "-- Installing builddir man pages ..." ; \
			$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/$(XMLSEC1_MAN) $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/$(XMLSEC1_CONFIG_MAN) $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "WARNING: Skipping man pages installation (rebuild man pages with 'make -C man docs')" ; \
		fi ; \
	)

# man pages are installed into a shared folder, we can't just remove it
uninstall-local:
	@$(RM) -f $(DESTDIR)$(TARGET_DIR)/$(XMLSEC1_MAN)
	@$(RM) -f $(DESTDIR)$(TARGET_DIR)/$(XMLSEC1_CONFIG_MAN)

#
# Copies the man pages from builddir to the dist dir, or prints a warning if they are missing.
#
dist-hook:
	@( \
		if test -f $(builddir)/$(XMLSEC1_MAN) ; then  \
			echo "-- Copying builddir man pages ..." ; \
			$(CP) $(builddir)/$(XMLSEC1_MAN) $(distdir)/ ; \
			$(CP) $(builddir)/$(XMLSEC1_CONFIG_MAN) $(distdir)/ ; \
		else \
			echo "WARNING: Skipping man pages dist (rebuild man pages with 'make -C man docs')" ; \
		fi ; \
	)
