NULL =

XMLSEC1_MAN=xmlsec1.1
XMLSEC1_CONFIG_MAN=xmlsec1-config.1

XMLSEC1_MAN_SRC=$(srcdir)/xmlsec1.1
XMLSEC1_CONFIG_MAN_SRC=$(srcdir)/xmlsec1-config.1

man_MANS = \
	$(abs_builddir)/$(XMLSEC1_MAN) \
	$(abs_builddir)/$(XMLSEC1_CONFIG_MAN) \
	$(NULL)

EXTRA_DIST = \
	$(XMLSEC1_MAN) \
	$(XMLSEC1_CONFIG_MAN) \
	$(NULL)

XMLSEC_PROGRAM=$(top_builddir)/apps/xmlsec1
XMLSEC_CONFIG_PROGRAM=$(top_builddir)/xmlsec1-config

all: $(man_MANS)

$(abs_builddir)/$(XMLSEC1_MAN):
	@if test "z$(HELP2MAN)" = "z" -o ! -f $(XMLSEC_PROGRAM) ; then \
		echo "Copying xmlsec1 manpage ..."; \
		if [ z"$(XMLSEC1_MAN_SRC)" != z"$(XMLSEC1_MAN)" ]; \
		then \
		   $(CP) $(XMLSEC1_MAN_SRC) $(XMLSEC1_MAN) ; \
		fi ; \
	else \
		echo "Building xmlsec1 manpage ..."; \
		$(HELP2MAN) --help-option=--help-all --no-info \
		  --name="sign, verify, encrypt and decrypt XML documents" \
		  --version-option=--version \
		  --output=$(XMLSEC1_MAN) \
		  $(XMLSEC_PROGRAM) ; \
	fi

$(abs_builddir)/$(XMLSEC1_CONFIG_MAN):
	@if test "z$(HELP2MAN)" = "z" -o ! -f $(XMLSEC_CONFIG_PROGRAM) ; then \
		echo "Copying xmlsec1-config manpage ..."; \
		if [ z"$(XMLSEC1_CONFIG_MAN_SRC)" != z"$(XMLSEC1_CONFIG_MAN)" ]; then \
		    $(CP) $(XMLSEC1_CONFIG_MAN_SRC) $(XMLSEC1_CONFIG_MAN) ; \
		fi ; \
	else \
		echo "Building xmlsec1-config manpage ..."; \
		$(HELP2MAN) --help-option=--help --no-info \
		  --name="detail installed version of xmlsec library" \
		  --version-option=--version \
		  --output=$(XMLSEC1_CONFIG_MAN) \
		  $(XMLSEC_CONFIG_PROGRAM) ; \
	fi

clean-local:
	@( if [ z"$(XMLSEC1_MAN_SRC)" != z"$(XMLSEC1_MAN)" ]; then \
		$(RM) -rf $(XMLSEC1_MAN) ; \
	fi )
	@( if [ z"$(XMLSEC1_CONFIG_MAN_SRC)" != z"$(XMLSEC1_CONFIG_MAN)" ];  then \
		$(RM) -rf $(XMLSEC1_CONFIG_MAN) ; \
	fi )

distclean-local: clean-local

