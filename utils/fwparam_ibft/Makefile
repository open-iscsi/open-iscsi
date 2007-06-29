OPTFLAGS ?= -O2 -g
WARNFLAGS ?= -Wall -Wstrict-prototypes
CFLAGS += $(OPTFLAGS) $(WARNFLAGS)
PROGRAMS = fwparam_ibft

all: $(PROGRAMS)

fwparam_ibft: fwparam_ibft.o
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(PROGRAMS) .depend

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
