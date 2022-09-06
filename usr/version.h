#ifndef ISCSI_VERSION_DEF
#define ISCSI_VERSION_DEF

/*
 * iSCSI tools version.
 * This may not be the same value as the kernel versions because
 * some other maintainer could merge a patch without going through us
 *
 * Version string should be set by build system, or we have a problem
 */
#ifndef	ISCSI_VERSION_STR
#error ISCSI_VERSION_STR not set!
#endif
#define ISCSI_VERSION_FILE	"/sys/module/scsi_transport_iscsi/version"

#endif
