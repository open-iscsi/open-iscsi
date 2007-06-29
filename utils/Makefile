# This Makefile will work only with GNU make.

CFLAGS += $(OPTFLAGS) -O2 -fno-inline -Wall -Wstrict-prototypes -g
PROGRAMS = iscsi-iname

all: $(PROGRAMS)

iscsi-iname: md5.o iscsi-iname.o
	$(CC) $(CFLAGS) $^ $(DBM_LIB) -o $@

clean:
	rm -f *.o $(PROGRAMS) .depend

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
