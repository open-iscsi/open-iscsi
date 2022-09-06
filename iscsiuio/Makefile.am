SUBDIRS= src

EXTRA_DIST = build_date

build_date:
	if [ -n "$$SOURCE_DATE_EPOCH" ] ; then \
		echo 'char *build_date = "'`LC_ALL=C.UTF-8 date --date=@$$SOURCE_DATE_EPOCH -u`'";' > build_date.c ; \
	else \
		echo 'char *build_date = "'`date`'";' > build_date.c ; \
	fi
	echo 'char *build_date;'> build_date.h

manprefix = /usr/share
mandir = ${manprefix}/man
logdir = /etc/logrotate.d

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am install-man install-log install-brcm

install-man: $(DESTDIR)$(mandir)/man8/iscsiuio.8

$(DESTDIR)$(mandir)/man8/iscsiuio.8: docs/iscsiuio.8
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8/
	$(INSTALL_DATA) $? $(DESTDIR)$(mandir)/man8/

install-log:
	$(INSTALL) -d $(DESTDIR)$(logdir)/
	$(INSTALL_DATA) iscsiuiolog $(DESTDIR)$(logdir)/

install-brcm:
	$(RM) $(DESTDIR)$(sbindir)/brcm_iscsiuio
	(cd $(DESTDIR)/$(sbindir); \
	 $(RM) brcm_iscsiuio; \
	 $(LN_S) iscsiuio brcm_iscsiuio)
