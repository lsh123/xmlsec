#
#
#
PROGRAMS	 = dsig1 dsig2 enc1 enc2

cc	 	 = gcc
CC	 	 = gcc
LD	 	 = gcc

CFLAGS		+= -g $(shell xmlsec-config --cflags)
LDFLAGS		+= -g
LIBS 		+= $(shell xmlsec-config --libs) 

all: $(PROGRAMS)

%: %.c 
	$(cc) $< $(LDFLAGS) $(CFLAGS) -o $@ $(PROGRAM) $(LIBRARY) $(LIBS)

clean:
	@rm -rf $(PROGRAMS)

