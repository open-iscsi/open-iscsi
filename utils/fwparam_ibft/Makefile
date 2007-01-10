OPTFLAGS ?= -O2 -g
WARNFLAGS ?= -Wall -Wstrict-prototypes
CFLAGS += $(OPTFLAGS) $(WARNFLAGS)
PROGRAMS = fwparam_ibft

all: $(PROGRAMS)

fwparam_ibft: fwparam_ibft.c fwparam_ibft.h
	$(CC) $(CFLAGS) $^ -o $@
clean:
	rm -f *.o $(PROGRAMS)
