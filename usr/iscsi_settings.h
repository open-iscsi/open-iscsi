/*
 * Default initiator settings. These may not be the same as
 * in the RFC. See iscsi_proto.h for those.
 */
/* timeouts in seconds */
#define DEF_LOGIN_TIMEO		15
#define DEF_LOGOUT_TIMEO	15
#define DEF_NOOP_OUT_INTERVAL	10
#define DEF_NOOP_OUT_TIMEO	15
#define DEF_REPLACEMENT_TIMEO	120

/* data and segment lengths in bytes */
#define DEF_INI_FIRST_BURST_LEN		262144
#define DEF_INI_MAX_BURST_LEN		16776192
#define DEF_INI_MAX_RECV_SEG_LEN	131072
#define DEF_INI_DISC_MAX_RECV_SEG_LEN	32768
