AM_CFLAGS =	-I${top_srcdir}/src/unix		\
		-I${top_srcdir}/src/apps/dhcpc		\
		-I${top_srcdir}/src/apps/brcm-iscsi	\
		-I${top_srcdir}/../include		\
		-I${top_srcdir}/../usr

noinst_LIBRARIES = lib_iscsi_uip.a

lib_iscsi_uip_a_SOURCES = 	uip.c		\
				uip_arp.c	\
				psock.c		\
				timer.c		\
				uip-neighbor.c	\
				uip_eth.c	\
				ipv6_ndpc.c	\
				ipv6.c

lib_iscsi_uip_a_CFLAGS = 	-DBYTE_ORDER=@ENDIAN@ $(AM_CFLAGS)
