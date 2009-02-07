# This Makefile will work only with GNU make.

CFLAGS += $(OPTFLAGS) $(WARNFLAGS) -O2 -fno-inline -Wall -Wstrict-prototypes -g

SYSDEPS_OBJS=sysdeps.o

all: $(SYSDEPS_OBJS)

clean:
	rm -f *.o .depend

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
