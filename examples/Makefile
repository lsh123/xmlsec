#
#
#
PROGRAMS	 = dsig1

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

