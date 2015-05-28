# This Makefile will work only with GNU make.

CFLAGS ?= -O2 -fno-inline -g
CFLAGS += $(WARNFLAGS) -Wall -Wstrict-prototypes

SYSDEPS_OBJS=sysdeps.o

all: $(SYSDEPS_OBJS)

clean:
	rm -f *.o .depend

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
