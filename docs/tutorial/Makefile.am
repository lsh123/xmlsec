#
#
#
NULL=
MODULE=xmlsec

TARGET_DIR=@XMLSEC_DOCDIR@/tutorial

SGML_DIR=$(builddir)/sgml.tmp
EXAMPLES_DIR=$(SGML_DIR)/examples

# We need to copy some files to make gtkdoc happy that
# everything is in one folder
MAIN_SGML_FILE=$(SGML_DIR)/xmlsec-tutorial.sgml
MAIN_SGML_SRC_FILE=$(srcdir)/src/xmlsec-tutorial.sgml

SGML_CHAPTERS_DIR=$(SGML_DIR)/chapters
SGML_CHAPTERS_SRC_DIR=$(srcdir)/src/chapters

# API devhelp2 file used for cross-reference fixing
API_DEVHELP=$(top_builddir)/docs/api/xmlsec.devhelp2

# files that are copied from sources
EXTRA_DIST := \
    $(srcdir)/src    \
    $(srcdir)/images \
    $(NULL)

EXAMPLES_SOURCE_DIR=$(top_srcdir)/examples
EXAMPLES_SOURCE_FILES=\
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print)

.PHONY: all docs html sgml

all:
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

# if build API docs, then we also have xsltproc
if BUILD_API_DOCS

docs: html
	@( echo "-- Fixing cross-references in tutorial to API docs..."; \
	   if test -f $(API_DEVHELP) ; then \
	       echo "-- Found API devhelp2: $(API_DEVHELP)"; \
	       FIXXREF_SED=$(SGML_DIR)/fixxref.sed; \
	       $(RM) -f $$FIXXREF_SED; \
	       $(GREP) '<keyword' $(API_DEVHELP) | \
	           $(SED) 's/.*name="\([^"(]*\)[^"]*" link="\([^"]*\)".*/\1\t\2/' | \
	           $(GREP) -v '^[[:space:]]*$$' | \
	           awk -F'\t' '$$1 != "" && $$2 != "" { \
	               name=$$1; \
	               sub(/[^a-zA-Z_0-9].*$$/, "", name); \
	               link=$$2; gsub(/[[:space:]]*$$/, "", link); \
	               if (name != "") print "s|<GTKDOCLINK HREF=\"" name "\">\\([^<]*\\)</GTKDOCLINK>|<a href=\"../api/" link "\">\\1<\\/a>|gI" \
	           }' >> $$FIXXREF_SED; \
	       for f in `find . -name "*.html" -print` ; do \
	           echo "-- Fixing cross-refs in $$f..."; \
	           test -s $$FIXXREF_SED && $(SED) -i -f $$FIXXREF_SED "$$f" ; \
	       done; \
	   else \
	       echo "-- WARNING: API devhelp2 not found, skipping cross-reference fix"; \
	   fi \
	)
	@( echo "-- Cleaning up remaining unresolved cross-references"; \
	   for f in `find . -name "*.html" -print` ; do \
	       echo "-- Processing $$f..."; \
	       $(SED) -i 's/<GTKDOCLINK[^>]*>/<font>/gI; s/<\/GTKDOCLINK[^>]*>/<\/font>/gI' "$$f" ; \
	   done \
	)

else

docs:
	@(echo "=== ERROR: To build tutorial docs, make sure all necessary tools are installed" ; exit 1; )

endif



html: sgml $(MAIN_SGML_FILE) $(SGML_CHAPTERS_DIR) example_sources
	@$(GTKDOC_MKHTML) xmlsec $(MAIN_SGML_FILE)

$(SGML_CHAPTERS_DIR): $(SGML_CHAPTERS_SRC_DIR) $(SGML_CHAPTERS_DIR)/.sentinel
	@( \
		echo "-- Copying chapters..." ; \
		$(CP) -r $(SGML_CHAPTERS_SRC_DIR)/* $(SGML_CHAPTERS_DIR) \
	)

$(MAIN_SGML_FILE): $(MAIN_SGML_SRC_FILE)
	@( \
		echo "-- Copying main sgml file..."; \
		$(CP) $(MAIN_SGML_SRC_FILE) $(MAIN_SGML_FILE) \
	)

#
# Prepare sgml files by fixing up XML DSig/Enc namespace tags and
# other gtkdoc quirks (same fixups as in the api build)
#
sgml: $(SGML_DIR)/.sentinel
	@(for i in `find $(SGML_DIR) -name "*.sgml" -or -name "*.xml" -print` ; do \
			echo "--- Fixing up '$$i'" ; \
	        cat $$i | \
	          $(SED) 's!\(<dsig:\)\([^/]*\)\(\/>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          $(SED) 's!\(<enc:\)\([^/]*\)\(\/>\)!\&lt;enc:\2\/\&gt;!g' | \
	          $(SED) 's!\(<dsig:\)\(\w*\)\(>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          $(SED) 's!\(<enc:\)\(\w*\)\(>\)!\&lt;enc:\2\/\&gt;!g' | \
	          $(SED) 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          $(SED) 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          $(SED) 's!<para \/>!<para></para>!g' | \
	          $(SED) 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' | \
	          $(SED) 's!<colspec [^/]*\/>!!g' | \
	          $(SED) 's!<programlisting language="C"!<programlisting!g' | \
	          $(SED) 's!\%gtkdocentities;!!g' | \
	          $(SED) 's!title>\n!title>!g' | \
		  $(SED) 's!<\/title><\/refsect1>\n!<\/title><para><\/para><\/refsect1>!g' | \
		  $(SED) 's!para>\n!para>!g' > \
	          $$i.tmp; \
	        $(MV) -f $$i.tmp $$i; \
	 done);

#
# The following code converts C example file to sgml RefEntry files.
# We get file title from a string "XML Security Library example: ..."
# which is usually placed at the top of the file. Also all "unsafe" xml
# characters (<, >, &) are escaped.
#
example_sources: $(EXAMPLES_DIR)/.sentinel
	@echo "-- Preprocessing example source files into '$(EXAMPLES_DIR)' ..."
	@$(RM) -rf $(EXAMPLES_DIR)/*
	@(for i in $(EXAMPLES_SOURCE_FILES) ; do \
	    file_name=`echo $$i | $(SED) 's#.*/##' | $(SED) 's#\..*$$##'`; \
	    file_ext=`echo $$i | $(SED) 's#.*/##' | $(SED) 's#.*\.##'`; \
	    echo "--- Converting $$file_name.$$file_ext to $$file_name.sgml ..."; \
	    file_title=`cat $$i | $(GREP) 'XML Security Library example: ' | $(SED) 's#^.*: *##'`; \
	    echo "<sect2 id=\"xmlsec-example-$$file_name\" >" > \
	        $(EXAMPLES_DIR)/$$file_name.sgml; \
	    echo "<title>$$file_name.$$file_ext</title><para><informalexample><programlisting>" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	    cat $$i | \
		$(SED) "s#&#\&amp;#g" | \
		$(SED) "s#<#\&lt;#g" | \
		$(SED) "s#>#\&gt;#g" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	    echo "</programlisting></informalexample></para></sect2>" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	done);


# A single pattern rule will create all appropriate folders as required
# otherwise make (annoyingly) deletes it
.PRECIOUS: %/.sentinel
%/.sentinel:
	@echo "-- Creating folder '${@D}' ..."
	@mkdir -p ${@D}
	@touch $@

dist-hook:
	@( \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Copying to dist builddir tutorial html, css, png ..." ; \
			$(CP) $(builddir)/*.html $(distdir)/ ; \
			$(CP) $(builddir)/*.css $(distdir)/ ; \
			$(CP) $(builddir)/*.png $(distdir)/ ; \
		else \
			echo "-- Copying to dist source tutorial html, css, png ..." ; \
			$(CP) $(srcdir)/*.html $(distdir)/ ; \
			$(CP) $(srcdir)/*.css $(distdir)/ ; \
			$(CP) $(srcdir)/*.png $(distdir)/ ; \
		fi ; \
	)

clean-local:
	@$(RM) -rf $(EXAMPLES_DIR) $(SGML_DIR)
	@$(RM) -f *.stamp *.bak
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; \
		then \
			(chmod -Rf u+w $(builddir)/*.html 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.html ; \
			(chmod -Rf u+w $(builddir)/*.css 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.css ; \
			(chmod -Rf u+w $(builddir)/*.png 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/*.png ; \
	 	fi ; \
	)

distclean-local: clean-local

install-data-local:
	@( \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR) ; \
		if test -f $(builddir)/index.html ; then  \
			echo "-- Installing builddir tutorial html docs, css, png ..." ; \
			@INSTALL@ -m 0644 $(builddir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/*.css $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(builddir)/*.png $(DESTDIR)$(TARGET_DIR) ; \
		else \
			echo "-- Installing srcdir tutorial html docs, css, png ..." ; \
			@INSTALL@ -m 0644 $(srcdir)/*.html $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/*.css $(DESTDIR)$(TARGET_DIR) ; \
			@INSTALL@ -m 0644 $(srcdir)/*.png $(DESTDIR)$(TARGET_DIR) ; \
		fi ; \
	)
	@( \
		echo "-- Installing tutorial images ..." ; \
		$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images ; \
		@INSTALL@ -m 0644 $(srcdir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images/ ; \
	)

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)
