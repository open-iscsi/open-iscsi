CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -I../include -DNETLINK_ISCSI=10
PROGRAMS = iscsid iscsiadm

# sources shared between iscsid and iscsiadm
COMMON_SRCS = io.o auth.o login.o log.o md5.o sha1.o idbm.o

all: $(PROGRAMS)

iscsid: $(COMMON_SRCS) iscsid.o ipc.o netlink.o initiator.o actor.o queue.o
	$(CC) $^ -ldb -o $@

iscsiadm: $(COMMON_SRCS) strings.o discovery.o iscsiadm.o
	$(CC) $^ -ldb -o $@

clean:
	rm -f *.o $(PROGRAMS)
