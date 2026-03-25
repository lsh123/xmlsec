NULL =

SUBDIRS=api

TARGET_DIR=@XMLSEC_DOCDIR@

# we copy over all folders to builddir to make it easier to test docs
EXTRA_DIST=	                \
    $(builddir)/images      \
    $(builddir)/css         \
    $(builddir)/*.html      \
    $(builddir)/*.ico       \
    $(builddir)/*.xsl       \
    $(NULL)

SOURCE_FILES_TO_COPY=       \
    $(srcdir)/images        \
    $(srcdir)/css           \
    $(srcdir)/*.html        \
    $(srcdir)/*.ico         \
    $(srcdir)/*.xsl         \
    $(NULL)

XMLSEC1_MAN=$(top_builddir)/man/xmlsec1.1
XMLSEC_HTML=$(builddir)/xmlsec-man.html

all: docs-copy
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

docs: docs-api docs-copy man-docs docs-format

docs-api:
	make -C api docs

docs-copy: $(builddir)/index.html
	@( \
		echo "-- Copying docs..."; \
		if [ z"$(srcdir)" != z"$(builddir)" -a z"`uname`" != z"Darwin" ]; \
		then \
		    $(CP) -ru $(SOURCE_FILES_TO_COPY) $(builddir)/  ; \
		fi \
	)

# if we build docs then we also have xsltproc
if BUILD_MAN_DOCS
man-docs: $(XMLSEC_HTML) docs-copy

$(XMLSEC_HTML): docs-copy $(XMLSEC1_MAN)
	@($(MAN2HTML) $(XMLSEC1_MAN) | \
		  grep -v '^Content-type: text/html' | \
		  tr "[:cntrl:]" " " > \
		  $(XMLSEC_HTML) \
	)
else
# do nothing, we aready copied this file
man-docs:

endif

if HAS_XSLTPROC
docs-format: docs-copy man-docs
	@(echo "-- Formatting html documents"; \
	for i in `find $(builddir) -name "*.html" -print`; \
	do \
	    top_folder=`echo $$i | sed 's#/[^/]*$$#/#' | sed 's#\./##' | \
			sed 's#[^/]*/#../#g'`; \
	    echo "--- Processing $$i (topfolder='$$top_folder')"; \
	    $(XSLTPROC) --html --stringparam topfolder "$$top_folder" \
		     --output $$i.tmp $(srcdir)/xmlsec.xsl $$i; \
	    if [ $$? != 0 ]; \
	    then \
			echo "ERROR: processing file $$i"; \
			exit 1; \
	    fi; \
	    mv $$i.tmp $$i; \
	done)
	@(echo "-- Cleaning html documents"; \
	for i in `find $(builddir) -name "*.html" -print`; \
	do \
	    echo "--- Cleaning $$i" ; \
	    sed 's/\xC2\xA0/ /g' $$i > $$i.tmp ; \
	    mv $$i.tmp $$i ; \
	done)

else
# do nothing
docs-format: docs-copy man-docs

endif

clean-local:
	@( \
		rm -f *.stamp ; \
		if [ z"$(srcdir)" != z"$(builddir)" ] ; \
		then \
			(chmod -R u+w $(EXTRA_DIST)  || true) ; \
			rm -rf $(EXTRA_DIST) ; \
		fi ; \
	 )

distclean-local: clean-local

install-data-local:
	@echo "Installing docs ..."
	@$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	@$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images
	@$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/css
	@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR)
	@INSTALL@ -m 0644 $(builddir)/*.ico  $(DESTDIR)$(TARGET_DIR)
	@INSTALL@ -m 0644 $(builddir)/images/*.gif $(builddir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images
	@INSTALL@ -m 0644 $(builddir)/css/*.css $(DESTDIR)$(TARGET_DIR)/css

uninstall-local:
	@rm -rf $(DESTDIR)$(TARGET_DIR)

