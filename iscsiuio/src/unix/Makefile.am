SUBDIRS= libs

AM_CFLAGS = -I${top_srcdir}/src/uip		\
	   -I${top_srcdir}/src/apps/brcm-iscsi	\
	   -I${top_srcdir}/src/apps/dhcpc	\
	   -I${top_srcdir}/src/unix/libs	\
	   -I${top_srcdir}/../include		\
	   -I${top_srcdir}/../usr

sbin_PROGRAMS = iscsiuio

iscsiuio_SOURCES =	build_date.c		\
			main.c			\
			clock-arch.c		\
			logger.c		\
			nic.c			\
			nic_id.c		\
			nic_vlan.c		\
			nic_nl.c		\
			nic_utils.c		\
			packet.c		\
			iscsid_ipc.c		\
			ping.c

iscsiuio_CFLAGS = 	$(AM_CFLAGS)		\
			$(LIBNL_CFLAGS)		\
			-DBYTE_ORDER=@ENDIAN@

iscsiuio_LDFLAGS= 	$(AM_LDADD)		\
			-ldl			\
			-rdynamic		\
			$(LIBNL_LIBS)		\
			-lpthread

iscsiuio_LDADD  = 	${top_srcdir}/src/uip/lib_iscsi_uip.a	\
			${top_srcdir}/src/apps/dhcpc/lib_apps_dhcpc.a\
			${top_srcdir}/src/apps/brcm-iscsi/lib_apps_brcm_iscsi.a \
			${top_srcdir}/src/unix/libs/lib_iscsiuio_hw_cnic.a

iscsiuio_YFLAGS = -d
