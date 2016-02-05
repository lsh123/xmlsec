NULL =

XMLSEC1_MAN=$(top_builddir)/man/xmlsec1.1
XMLSEC1_CONFIG_MAN=$(top_builddir)/man/xmlsec1-config.1

XMLSEC1_MAN_SRC=$(top_srcdir)/man/xmlsec1.1
XMLSEC1_CONFIG_MAN_SRC=$(top_srcdir)/man/xmlsec1-config.1

man_MANS = \
	$(XMLSEC1_MAN) \
	$(XMLSEC1_CONFIG_MAN) \
	$(NULL)

EXTRA_DIST = \
	$(XMLSEC1_MAN) \
	$(XMLSEC1_CONFIG_MAN) \
	$(NULL)

XMLSEC_PROGRAM=$(top_builddir)/apps/xmlsec1
XMLSEC_CONFIG_PROGRAM=$(top_builddir)/xmlsec1-config
XMLSEC_HTML=$(top_builddir)/docs/xmlsec-man.html

all: $(man_MANS) $(XMLSEC_HTML)
	
clean:
	@rm -rf $(man_MANS)

if HAS_MAN2HTML
$(XMLSEC_HTML): $(XMLSEC1_MAN)
	$(MAN2HTML) $(XMLSEC1_MAN) | \
		  grep -v '^Content-type: text/html' | \
		  tr "[:cntrl:]" " " > \
		  $(XMLSEC_HTML)
endif

if HAS_HELP2MAN
$(XMLSEC1_MAN): $(XMLSEC_PROGRAM)
	$(HELP2MAN) --help-option=--help-all --no-info \
		  --name="sign, verify, encrypt and decrypt XML documents" \
		  --version-option=--version \
		  --output=$(XMLSEC1_MAN) \
		  $(XMLSEC_PROGRAM)
else
$(XMLSEC1_MAN):
	$(CP) -u $(XMLSEC1_MAN_SRC) $(XMLSEC1_MAN)
endif

if HAS_HELP2MAN
$(XMLSEC1_CONFIG_MAN): $(XMLSEC_CONFIG_PROGRAM)
	$(HELP2MAN) --help-option=--help --no-info \
		  --name="detail installed version of xmlsec library" \
		  --version-option=--version \
		  --output=$(XMLSEC1_CONFIG_MAN) \
		  $(XMLSEC_CONFIG_PROGRAM)
else
$(XMLSEC1_CONFIG_MAN):
	$(CP) -u $(XMLSEC1_CONFIG_MAN_SRC) $(XMLSEC1_CONFIG_MAN)
endif

$(XMLSEC_PROGRAM): 
	@cd ../apps;make

$(XMLSEC_CONFIG_PROGRAM):

