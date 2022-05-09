# This Makefile will work only with GNU make.

CFLAGS ?= -O2 -fno-inline -g
CFLAGS += $(WARNFLAGS) -Wall -Wstrict-prototypes

SYSDEPS_OBJS=sysdeps.o

all: $(SYSDEPS_OBJS)

clean:
	$(RM) *.o .depend

distclean: ;

.PHONY: all clean distclean depend

depend:
	$(CC) $(CFLAGS) -M `ls *.c` > .depend

-include .depend
