/*
 * Default initiator settings. These may not be the same as
 * in the RFC. See iscsi_proto.h for those.
 */
/* timeouts in seconds */
#define DEF_LOGIN_TIMEO		30
#define DEF_LOGOUT_TIMEO	15
#define DEF_NOOP_OUT_INTERVAL	5
#define DEF_NOOP_OUT_TIMEO	5
#define DEF_REPLACEMENT_TIMEO	120

#define DEF_ABORT_TIMEO		15
#define DEF_LU_RESET_TIMEO	30
#define DEF_TGT_RESET_TIMEO	30
#define DEF_HOST_RESET_TIMEO	60

/* q depths */
#define CMDS_MAX	128
#define QUEUE_DEPTH	32

/* system */
#define XMIT_THREAD_PRIORITY	-20

/* interface */
#define UNKNOWN_VALUE		"<empty>"
#define DEFAULT_IFACENAME	"default"
#define DEFAULT_NETDEV		"default"
#define DEFAULT_IPADDRESS	"default"
#define DEFAULT_HWADDRESS	"default"
#define DEFAULT_TRANSPORT	"tcp"

#define PORTAL_GROUP_TAG_UNKNOWN -1

/* default window size */
#define TCP_WINDOW_SIZE (512 * 1024)

/* default iSCSI port number */
#define ISCSI_DEFAULT_PORT 3260

/* data and segment lengths in bytes */
#define DEF_INI_FIRST_BURST_LEN		262144
#define DEF_INI_MAX_BURST_LEN		16776192
#define DEF_INI_MAX_RECV_SEG_LEN	262144
#define DEF_INI_DISC_MAX_RECV_SEG_LEN	32768

/* login retries */
#define DEF_INITIAL_LOGIN_RETRIES_MAX	4
