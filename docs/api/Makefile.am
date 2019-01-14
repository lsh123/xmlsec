#
#
#
NULL=
MODULE=xmlsec
SOURCE_DIR=$(top_srcdir)/src
SOURCE_DIR2=$(top_builddir)/src
INCLUDE_DIR=$(top_srcdir)/include
INCLUDE_DIR2=$(top_builddir)/include


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
	$(srcdir)/src \
	$(srcdir)/images \
	$(srcdir)/style.css \
	$(NULL)

SOURCE_FILES_TO_COPY = \
	$(srcdir)/src \
	$(srcdir)/images \
	$(srcdir)/style.css \
	$(srcdir)/*.html \
	$(srcdir)/*.png \
	$(NULL)	

CRYPTO_LIBS_LIST = \
        openssl \
        nss \
        gnutls \
        gcrypt \
        mscrypto \
        mscng \
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

#
# This script removes gtkdoc crap from final html
#
REMOVE_GTKDOCLINK=$(top_srcdir)/scripts/remove-gtkdoclink.pl

# docs is legacy
all: docs


# if build API docs, then we also have xsltproc
if BUILD_API_DOCS
docs: html-cleanup

else
docs:
	@( \
		echo "Copying api-docs..."; \
		if [ z"$(srcdir)" != z"$(builddir)" -a z"`uname`" != z"Darwin" ]; \
		then \
		    $(CP) -ru $(SOURCE_FILES_TO_COPY) $(builddir)/ ; \
		fi \
	)
endif

html-cleanup: html
	@( echo "Cleaning up result files"; \
	   $(PERL) $(REMOVE_GTKDOCLINK) `find . -name "*.html" -print` \
	)

# need to cleanup "bad" chars
html: sgml $(MAIN_SGML_FILE) $(SGML_CHAPTERS_DIR) xmlsec-index
	$(GTKDOC_MKHTML) xmlsec $(MAIN_SGML_FILE)

$(SGML_CHAPTERS_DIR): $(SGML_CHAPTERS_SRC_DIR) $(SGML_CHAPTERS_DIR)/.sentinel
	$(CP) -ru $(SGML_CHAPTERS_SRC_DIR)/* $(SGML_CHAPTERS_DIR)

$(MAIN_SGML_FILE): $(MAIN_SGML_SRC_FILE)
	$(CP) -u $(MAIN_SGML_SRC_FILE) $(MAIN_SGML_FILE)
#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references.
#
# We also fix a bunch of stupid errors from gtkdoc 
#
sgml: sgml-base
	(for i in `find $(SGML_DIR) -name "*.sgml" -or -name "*.xml" -print` ; do \
			echo "Fixing up '$$i'" ; \
	        cat $$i | \
	          sed 's!\(<dsig:\)\([^/]*\)\(\/>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          sed 's!\(<enc:\)\([^/]*\)\(\/>\)!\&lt;enc:\2\/\&gt;!g' | \
	          sed 's!\(<dsig:\)\(\w*\)\(>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          sed 's!\(<enc:\)\(\w*\)\(>\)!\&lt;enc:\2\/\&gt;!g' | \
	          sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          sed 's!<para \/>!<para></para>!g' | \
	          sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' | \
	          sed 's!<colspec [^/]*\/>!!g' | \
	          sed 's!<programlisting language="C"!<programlisting!g' | \
	          sed 's!\%gtkdocentities;!!g' | \
	          $(PERL) -pe 's!title>\n!title>!g' | \
	          $(PERL) -pe 's!title>\n!title>!g' | \
	          $(PERL) -pe 's!<\/title><\/refsect1>\n!<\/title><para><\/para><\/refsect1>!g' | \
	          $(PERL) -pe 's!para>\n!para>!g' > \
	          $$i.tmp; \
	        mv -f $$i.tmp $$i; \
	 done);

# gtkdoc-mkdb doesn't support --output-dir thus we have to "hack" it a litle bit
sgml-base: scan $(SGML_DIR)/.sentinel
	@( \
	    echo "Create DocBook files for xmlsec-core" ; \
	    rm -rf $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/base ; \
	    $(GTKDOC_MKDB) --module=xmlsec \
		--xml-mode \
		--main-sgml-file=$(SGML_DIR)/xmlsec-base.sgml \
		--source-dir=$(SOURCE_CODE_DIR)/src/base \
		--source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/base ; \
	    mv $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/base ; \
	);
	@(for i in $(CRYPTO_LIBS_LIST) ; do \
	    echo "Create DocBook files for xmlsec-$$i" ; \
	    rm -rf $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/$$i ; \
	    $(GTKDOC_MKDB) --module=xmlsec-$$i \
		--xml-mode \
		--main-sgml-file=$(SGML_DIR)/xmlsec-$$i.sgml \
		--source-dir=$(SOURCE_CODE_DIR)/src/$$i \
		--source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/$$i ; \
	    mv $(GTKDOC_MKDB_OUTPUT_DIR) $(SGML_DIR)/$$i ; \
	done);

scan: SOURCE_CODEs example_sources
	@( \
	    echo "Scanning source code for xmlsec-core" ; \
	    $(GTKDOC_SCAN) --module=xmlsec \
	            --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(SOURCE_CODE_DIR)/src/base \
		    --source-dir=$(SOURCE_CODE_DIR)/include/xmlsec/base ; \
	);
	@(for i in $(CRYPTO_LIBS_LIST) ; do \
	    echo "Scanning source code for xmlsec-$$i" ; \
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
	@echo "Preprocessing source files into '$(SOURCE_CODE_DIR)' ..." 
	@mkdir -p $(SOURCE_CODE_DIR)/src/base $(SOURCE_CODE_DIR)/include/xmlsec/base
	@( \
	for i in $(SOURCE_CODE_FILES) ; do \
		folder_name=`echo "$$i" | \
			sed 's#$(top_srcdir)/##' | \
			sed 's#$(top_builddir)/##' | \
			sed 's#/[^/]*$$##'`; \
	    file_name=`echo "$$i" | \
	    	sed 's#.*/##'`; \
	    mkdir -p "$(SOURCE_CODE_DIR)/$$folder_name"; \
	    cat "$$i" | \
		    sed 's/#if.*//' | \
		    sed 's/#el.*//' | \
		    sed 's/#end.*//' | \
		    sed 's/XMLSEC_CRYPTO_EXPORT//' | \
		    sed 's/XMLSEC_EXPORT_VAR//' | \
		    sed 's/XMLSEC_EXPORT//' | \
		    sed 's/XMLSEC_ERRORS_PRINTF_ATTRIBUTE//' > \
		    $(SOURCE_CODE_DIR)/$$folder_name/$$file_name; \
	done);
	-@mv -f $(SOURCE_CODE_DIR)/src/*.c $(SOURCE_CODE_DIR)/src/base
	-@mv -f $(SOURCE_CODE_DIR)/include/xmlsec/*.h $(SOURCE_CODE_DIR)/include/xmlsec/base
	-@rm -f $(SOURCE_CODE_DIR)/include/xmlsec/*/symbols.h

SOURCE_CODEs_cleanup: $(SOURCE_CODE_DIR)/.sentinel
	@rm -rf $(SOURCE_CODE_DIR)/*

#
# Create index for all functions. For macros and defines need to add -CAPS suffix
#
xmlsec-index: scan $(SGML_DIR)/.sentinel
	@grep -h '<NAME>.*</NAME>' $(SCAN_DIR)/xmlsec-*decl.txt | \
		grep -v '<NAME>extern</NAME>' | \
		sort -u | \
		sed 's#_#-#g' | \
		sed 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		sed 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		$(SGML_DIR)/xmlsec-index.sgml

#
# The following code converts C example file to sgml RefEntry files.
# We get file title from a string "XML Security Library example: ..."
# which is usually placed at the top of the file. Also all "unsafe" xml 
# characters (<, >, &) are escaped. 
#
example_sources: $(EXAMPLES_DIR)/.sentinel
	@echo "Preprocessing example source files into '$(EXAMPLES_DIR)' ..." 
	@rm -rf $(EXAMPLES_DIR)/*
	@(for i in $(EXAMPLES_SOURCE_FILES) ; do \
	    file_name=`echo $$i | sed 's#.*/##' | sed 's#\..*$$##'`; \
	    file_ext=`echo $$i | sed 's#.*/##' | sed 's#.*\.##'`; \
	    echo Converting $$file_name.$$file_ext to $$file_name.sgml ...; \
	    file_title=`cat $$i | grep 'XML Security Library example: ' | sed 's#^.*: *##'`; \
	    echo "<sect2 id=\"xmlsec-example-$$file_name\" >" > \
	        $(EXAMPLES_DIR)/$$file_name.sgml; \
	    echo "<title>$$file_name.$$file_ext</title><para><informalexample><programlisting>" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	    cat $$i | \
		sed "s#&#\&amp;#g" | \
		sed "s#<#\&lt;#g" | \
		sed "s#>#\&gt;#g" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	    echo "</programlisting></informalexample></para></sect2>" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	done);

# A single pattern rule will create all appropriate folders as required
# otherwise make (annoyingly) deletes it
.PRECIOUS: %/.sentinel
%/.sentinel:
	@echo "Creating folder '${@D}' ..."
	mkdir -p ${@D}
	touch $@

dist-hook:
	@cp -p $(srcdir)/*.html $(srcdir)/*.png $(distdir)/
	(for i in `find $(distdir) -name ".sentinel" -print` ; do \
		echo "Removing some files '$$i' before dist ... " ; \
		rm $$i ; \
	done )
	(for i in `find $(distdir) -name "*.sgml.bak" -print` ; do \
		echo "Removing some files '$$i' before dist ... " ; \
		rm "$$i" ; \
	done ; )
	
clean-local:
	-rm -rf $(SOURCE_CODE_DIR) $(EXAMPLES_DIR) $(SCAN_DIR)/*.txt $(SGML_DIR) $(GTKDOC_MKDB_OUTPUT_DIR)
	-rm -f *.stamp *.types index.sgml
	@( if [ z"$(builddir)" != z"$(srcdir)" ] ; then \
    	chmod -R u+w $(builddir)/src && rm -rf $(builddir)/src ; \
    	chmod -R u+w $(builddir)/images && rm -rf $(builddir)/images ; \
    	chmod -R u+w $(builddir)/*.png && rm -rf $(builddir)/*.png ; \
	 fi ; )

distclean-local: clean-local

maintainer-clean-local: clean-local
	-rm -f *.html

