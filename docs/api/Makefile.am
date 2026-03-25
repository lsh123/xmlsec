#
#
#
NULL=
MODULE=xmlsec
SOURCE_DIR=$(top_srcdir)/src
SOURCE_DIR2=$(top_builddir)/src
INCLUDE_DIR=$(top_srcdir)/include
INCLUDE_DIR2=$(top_builddir)/include

TARGET_DIR=@XMLSEC_DOCDIR@/api

SCAN_DIR=$(builddir)
SGML_DIR=$(builddir)/sgml.tmp
EXAMPLES_DIR=$(SGML_DIR)/examples
SOURCE_CODE_DIR=$(builddir)/code

GTKDOC_MKDB_OUTPUT_DIR=$(builddir)/xml

# We need to copy some files to make gkdoc happy that
# everything is in one folder
MAIN_SGML_FILE=$(SGML_DIR)/xmlsec.sgml
MAIN_SGML_SRC_FILE=$(srcdir)/src/xmlsec.sgml

SGML_CHAPTERS_DIR=$(SGML_DIR)/chapters
SGML_CHAPTERS_SRC_DIR=$(srcdir)/src/chapters


EXTRA_DIST = \
	$(builddir)/src \
	$(builddir)/images \
	$(builddir)/*.css \
	$(builddir)/*.html  \
	$(builddir)/*.png \
	$(NULL)

SOURCE_FILES_TO_COPY = \
	$(srcdir)/src \
	$(srcdir)/images \
	$(srcdir)/*.css \
	$(srcdir)/*.html \
	$(srcdir)/*.png \
	$(NULL)

CRYPTO_LIBS_LIST = \
	openssl \
	nss \
	gnutls \
	mscng \
	mscrypto \
	gcrypt \
	$(NULL)

#
# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
SOURCE_CODE_FILES=\
	$(shell find $(SOURCE_DIR) -name '*.c' -print )  \
	$(shell find $(SOURCE_DIR2) -name '*.c' -print )  \
	$(shell find $(INCLUDE_DIR) -name '*.h' -a ! -name "symbols.h" -print ) \
	$(shell find $(INCLUDE_DIR2) -name '*.h' -a ! -name "symbols.h" -print )

EXAMPLES_SOURCE_DIR=$(top_srcdir)/examples
EXAMPLES_SOURCE_FILES=\
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print)

all: docs-copy
	@echo "======= Run 'make docs' in the xmlsec/docs folder to rebuild docs"

# if build API docs, then we also have xsltproc
if BUILD_API_DOCS
docs: html-cleanup

else

docs: docs-copy
	@echo "ERROR: To build API docs, make sure all necessary tools are installed"

endif

docs-copy:
	@( \
		echo "-- Copying api docs..."; \
		if [ z"$(srcdir)" != z"$(builddir)" ]; \
		then \
			(chmod -Rf u+w $(EXTRA_DIST)  2>/dev/null || true) ; \
			$(CP) -r $(SOURCE_FILES_TO_COPY) $(builddir)/ ; \
		fi \
	)

html-cleanup: html
	@( echo "-- Cleaning up result files"; \
	   for f in `find . -name "*.html" -print` ; do \
	       echo "-- Processing $$f..."; \
	       $(SED) -i 's/<GTKDOCLINK[^>]*>/<font>/gI; s/<\/GTKDOCLINK[^>]*>/<\/font>/gI' "$$f" ; \
	   done \
	)

html: docs-copy sgml $(MAIN_SGML_FILE) $(SGML_CHAPTERS_DIR) xmlsec-index
	@$(GTKDOC_MKHTML) xmlsec $(MAIN_SGML_FILE)

$(SGML_CHAPTERS_DIR): $(SGML_CHAPTERS_SRC_DIR) $(SGML_CHAPTERS_DIR)/.sentinel
	@( \
		echo "-- Copying chaptres..." ; \
		$(CP) -r $(SGML_CHAPTERS_SRC_DIR)/* $(SGML_CHAPTERS_DIR) \
	)

$(MAIN_SGML_FILE): $(MAIN_SGML_SRC_FILE)
	@( \
		echo "-- Copying main sgml file..."; \
		$(CP) $(MAIN_SGML_SRC_FILE) $(MAIN_SGML_FILE) \
	)
#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references.
#
# We also fix a bunch of stupid errors from gtkdoc
#
sgml: sgml-base
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

# gtkdoc-mkdb doesn't support --output-dir thus we have to "hack" it a litle bit
sgml-base: scan $(SGML_DIR)/.sentinel
	@( \
	    echo "-- Create DocBook files for xmlsec-core" ; \
	    $(RM) -rf $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/base ; \
	    $(GTKDOC_MKDB) --module=xmlsec \
		--xml-mode \
		--main-sgml-file=$(SGML_DIR)/xmlsec-base.sgml \
		--source-dir=$(SOURCE_CODE_DIR)/src/base \
		--source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/base ; \
	    $(MV) $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/base ; \
	);
	@(for i in $(CRYPTO_LIBS_LIST) ; do \
	    echo "-- Create DocBook files for xmlsec-$$i" ; \
	    $(RM) -rf $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/$$i ; \
	    $(GTKDOC_MKDB) --module=xmlsec-$$i \
		--xml-mode \
		--main-sgml-file=$(SGML_DIR)/xmlsec-$$i.sgml \
		--source-dir=$(SOURCE_CODE_DIR)/src/$$i \
		--source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/$$i ; \
	    $(MV) $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/$$i ; \
	done);

scan: SOURCE_CODEs example_sources
	@( \
	    echo "-- Scanning source code for xmlsec-core" ; \
	    $(GTKDOC_SCAN) --module=xmlsec \
	            --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(SOURCE_CODE_DIR)/src/base \
		    --source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/base ; \
	);
	@(for i in $(CRYPTO_LIBS_LIST) ; do \
	    echo "-- Scanning source code for xmlsec-$$i" ; \
	    $(GTKDOC_SCAN) --module=xmlsec-$$i \
	            --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(SOURCE_CODE_DIR)/src/$$i \
		    --source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/$$i ; \
	done);

#
# Prepare source files by coping them to "code" folder and
# removing XMLSEC_EXPORT_* stuff that makes gtkdoc crazy
#
SOURCE_CODEs: $(SOURCE_CODE_FILES) $(SOURCE_CODE_DIR)/.sentinel SOURCE_CODEs_cleanup
	@echo "-- Preprocessing source files into '$(SOURCE_CODE_DIR)' ..."
	@mkdir -p $(SOURCE_CODE_DIR)/src/base $(SOURCE_CODE_DIR)/include/xmlsec/base
	@( \
	for i in $(SOURCE_CODE_FILES) ; do \
		folder_name=`echo "$$i" | \
	        $(SED) 's#$(top_srcdir)/##' | \
	        $(SED) 's#$(top_builddir)/##' | \
	        $(SED) 's#/[^/]*$$##'`; \
	    file_name=`echo "$$i" | \
	        $(SED) 's#.*/##'`; \
	    mkdir -p "$(SOURCE_CODE_DIR)/$$folder_name"; \
	    cat "$$i" | \
	        $(SED) 's/#if.*//' | \
	        $(SED) 's/#el.*//' | \
	        $(SED) 's/#end.*//' | \
	        $(SED) 's/XMLSEC_CRYPTO_EXPORT//' | \
	        $(SED) 's/XMLSEC_EXPORT_VAR//' | \
	        $(SED) 's/XMLSEC_EXPORT//' | \
	        $(SED) 's/XMLSEC_ERRORS_PRINTF_ATTRIBUTE//' > \
	        $(SOURCE_CODE_DIR)/$$folder_name/$$file_name; \
	done);
	@$(MV) -f $(SOURCE_CODE_DIR)/src/*.c $(SOURCE_CODE_DIR)/src/base
	@$(MV) -f $(SOURCE_CODE_DIR)/include/xmlsec/*.h $(SOURCE_CODE_DIR)/include/xmlsec/base
	@$(RM) -f $(SOURCE_CODE_DIR)/include/xmlsec/*/symbols.h
	@echo "-- Remove macros documented in openssl module to avoid duplicate IDs"
	@$(SED) -i '/^#define XMLSEC_NO_MD5\b/d; /^#define XMLSEC_NO_EDDSA\b/d; /^#define XMLSEC_NO_HKDF\b/d' \
	    $(SOURCE_CODE_DIR)/include/xmlsec/nss/crypto.h

SOURCE_CODEs_cleanup: $(SOURCE_CODE_DIR)/.sentinel
	@$(RM) -rf $(SOURCE_CODE_DIR)/*

#
# Create index for all functions. For macros and defines need to add -CAPS suffix
#
xmlsec-index: scan $(SGML_DIR)/.sentinel
	@$(GREP) -h '<NAME>.*</NAME>' $(SCAN_DIR)/xmlsec-*decl.txt | \
		$(GREP) -v '<NAME>extern</NAME>' | \
		$(SORT) -u | \
		$(SED) 's#_#-#g' | \
		$(SED) 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		$(SED) 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		$(SGML_DIR)/xmlsec-index.sgml

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
	@(for i in `find $(distdir) -name ".sentinel" -print` ; do \
		echo "Removing some files '$$i' before dist ... " ; \
		$(RM) $$i ; \
	done )
	@(for i in `find $(distdir) -name "*.sgml.bak" -print` ; do \
		echo "Removing some files '$$i' before dist ... " ; \
		$(RM) "$$i" ; \
	done ; )

clean-local:
	@$(RM) -rf $(SOURCE_CODE_DIR) $(EXAMPLES_DIR) $(SCAN_DIR)/*.txt $(SGML_DIR) $(GTKDOC_MKDB_OUTPUT_DIR)
	@$(RM) -f *.stamp *.types index.sgml
	@( \
		if [ z"$(builddir)" != z"$(srcdir)" ] ; \
		then \
			(chmod -Rf u+w $(builddir)/xmlsec.devhelp2 $(EXTRA_DIST) 2>/dev/null || true) ; \
			$(RM) -rf $(builddir)/xmlsec.devhelp2 $(EXTRA_DIST) ; \
	 	fi ; \
	)

distclean-local: clean-local

install-data-local:
	@echo "Installing api docs ..."
	@$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	@$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)/images
	@INSTALL@ -m 0644 $(builddir)/*.html $(builddir)/*.png $(builddir)/*.css $(DESTDIR)$(TARGET_DIR)
	@INSTALL@ -m 0644 $(builddir)/images/*.png $(DESTDIR)$(TARGET_DIR)/images

uninstall-local:
	@$(RM) -rf $(DESTDIR)$(TARGET_DIR)

