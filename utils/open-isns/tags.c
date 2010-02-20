/*
 * Define all iSNS tags with their types, etc.
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "isns-proto.h"
#include "vendor.h"
#include "attrs.h"
#include "security.h"
#include "objects.h"
#include "util.h"

#define ISNS_MAX_BUILTIN_TAG	4096


static void	print_bitfield(unsigned long, char **, char *, size_t);
static int	parse_bitfield( char **, const char *, uint32_t *);
static const char *help_bitfield(char **);

#define DECLARE_VALIDATOR(name) \
static int		isns_##name##_validate(const isns_value_t *, const isns_policy_t *);
#define DECLARE_ACCESSORS(name) \
static int		isns_##name##_parse(isns_value_t *, const char *buf); \
static void		isns_##name##_print(const isns_value_t *, char *buf, size_t size); \
static const char *	isns_##name##_help(void)
#define USE_VALIDATOR(name) \
	.it_validate = isns_##name##_validate
#define USE_ACCESSORS(name) \
	.it_parse = isns_##name##_parse, \
	.it_print = isns_##name##_print, \
	.it_help = isns_##name##_help

DECLARE_VALIDATOR(entity_protocol);
DECLARE_ACCESSORS(entity_protocol);
DECLARE_ACCESSORS(tcpudp_port);
DECLARE_VALIDATOR(iscsi_node_type);
DECLARE_ACCESSORS(iscsi_node_type);
DECLARE_ACCESSORS(timestamp);
DECLARE_ACCESSORS(portal_secbitmap);
DECLARE_ACCESSORS(scn_bitmap);
DECLARE_ACCESSORS(dd_features);
DECLARE_ACCESSORS(policy_object_type);
DECLARE_ACCESSORS(policy_function);

static const char *isns_authmethod_help(void);

#define TAG(ID, name, type, args...) \
[ISNS_TAG_##ID] = { \
	.it_id		= ISNS_TAG_##ID,	\
	.it_name	= name, \
	.it_type	= &isns_attr_type_##type, \
	args \
}

static isns_tag_type_t	isns_tags[ISNS_MAX_BUILTIN_TAG] = {
TAG(DELIMITER,			"Delimiter",		nil),
TAG(ENTITY_IDENTIFIER,		"Entity identifier",	string),
TAG(ENTITY_PROTOCOL,		"Entity protocol",	uint32,
				USE_VALIDATOR(entity_protocol),
				USE_ACCESSORS(entity_protocol)),
TAG(MGMT_IP_ADDRESS,		"Mgmt IP address",	ipaddr),
TAG(TIMESTAMP,			"Timestamp",		uint64,
				USE_ACCESSORS(timestamp),
				.it_readonly = 1),
TAG(PROTOCOL_VERSION_RANGE,	"Protocol version range", range16),
TAG(REGISTRATION_PERIOD,	"Registration Period",	uint32),
TAG(ENTITY_INDEX,		"Entity index",		uint32,
				.it_readonly = 1),
TAG(ENTITY_NEXT_INDEX,		"Entity next index",	uint32,
				.it_readonly = 1),
TAG(PORTAL_IP_ADDRESS,		"Portal IP address",	ipaddr),
TAG(PORTAL_TCP_UDP_PORT,	"Portal TCP/UDP port",	uint32,
				USE_ACCESSORS(tcpudp_port)),
TAG(ESI_INTERVAL,		"ESI interval",		uint32),
TAG(ESI_PORT,			"ESI port",		uint32,
				USE_ACCESSORS(tcpudp_port)),
TAG(PORTAL_SYMBOLIC_NAME,	"Portal name",		string),
TAG(PORTAL_INDEX,		"Portal index",		uint32),
TAG(SCN_PORT,			"SCN port",		uint32,
				USE_ACCESSORS(tcpudp_port)),
TAG(PORTAL_SECURITY_BITMAP,	"Portal security bitmap", uint32,
				USE_ACCESSORS(portal_secbitmap)),
TAG(PORTAL_NEXT_INDEX,		"Portal next index",	uint32,
				.it_readonly = 1),

TAG(ISCSI_NAME,			"iSCSI name",		string),
TAG(ISCSI_NODE_TYPE,		"iSCSI node type",	uint32,
				USE_VALIDATOR(iscsi_node_type),
				USE_ACCESSORS(iscsi_node_type)),
TAG(ISCSI_ALIAS,		"iSCSI alias",		string),
TAG(ISCSI_SCN_BITMAP,		"iSCSI SCN bitmap",	uint32,
				USE_ACCESSORS(scn_bitmap)),
TAG(ISCSI_NODE_INDEX,		"iSCSI node index",	uint32,
				.it_readonly = 1),
TAG(WWNN_TOKEN,			"WWNN token",		uint64),
TAG(ISCSI_NODE_NEXT_INDEX,	"iSCSI node next index",uint32,
				.it_readonly = 1),
TAG(ISCSI_AUTHMETHOD,		"iSCSI auth method",	string,
				.it_help = isns_authmethod_help),

TAG(PG_ISCSI_NAME,		"Portal group name",	string),
TAG(PG_PORTAL_IP_ADDR,		"Portal group address",	ipaddr),
TAG(PG_PORTAL_TCP_UDP_PORT,	"Portal group port",	uint32,
				USE_ACCESSORS(tcpudp_port)),
TAG(PG_TAG,			"Portal group tag",	uint32),
TAG(PG_INDEX,			"Portal group index",	uint32,
				.it_readonly = 1),
TAG(PG_NEXT_INDEX,		"Portal group next index",uint32,
				.it_readonly = 1),

/* FC Port */
TAG(FC_PORT_NAME_WWPN,		"FC port name WWPN",	uint64),
TAG(PORT_ID,			"FC port ID",		uint32),
TAG(FC_PORT_TYPE,		"FC port type",		uint32),
TAG(SYMBOLIC_PORT_NAME,		"FC symbolic port name",string),
TAG(FABRIC_PORT_NAME,		"FC fabric port name",	uint64),
TAG(HARD_ADDRESS,		"FC hard",		uint32),
TAG(PORT_IP_ADDRESS,		"FC Port IP address",	ipaddr),
TAG(CLASS_OF_SERVICE,		"FC service class",	uint32),
TAG(FC4_TYPES,			"FC4 types",		opaque),
TAG(FC4_DESCRIPTOR,		"FC4 descriptor",	string),
TAG(FC4_FEATURES,		"FC4 features",		opaque),
TAG(IFCP_SCN_BITMAP,		"iFCP SCN bitmap",	uint32,
				USE_ACCESSORS(scn_bitmap)),
TAG(PORT_ROLE,			"FC port role",		uint32),
TAG(PERMANENT_PORT_NAME,	"FC permanent port name",uint64),
TAG(FC4_TYPE_CODE,		"FC4 type code",	uint32),

/* FC Node */
TAG(FC_NODE_NAME_WWNN,		"FC node name",		uint64),
TAG(SYMBOLIC_NODE_NAME,		"FC symbolic node name",string),
TAG(NODE_IP_ADDRESS,		"FC node IP address",	ipaddr),
TAG(NODE_IPA,			"FC node IPA",		uint64),
TAG(PROXY_ISCSI_NAME,		"FC node proxy iSCSI name",string),

/* Other FC tags to go here */

/* Discovery domain set */
TAG(DD_SET_ID,			"DD set ID",		uint32),
TAG(DD_SET_SYMBOLIC_NAME,	"DD set name",		string),
TAG(DD_SET_STATUS,		"DD set status",	uint32),
TAG(DD_SET_NEXT_ID,		"DD set next ID",	uint32,
				.it_readonly = 1),

/* Discovery domain */
TAG(DD_ID,			"DD ID",		uint32),
TAG(DD_SYMBOLIC_NAME,		"DD name",		string),
TAG(DD_MEMBER_ISCSI_INDEX,	"DD member iSCSI index",uint32,
				.it_multiple = 1),
TAG(DD_MEMBER_ISCSI_NAME,	"DD member iSCSI name",	string,
				.it_multiple = 1),
TAG(DD_MEMBER_FC_PORT_NAME,	"DD member FC WWPN",	string,
				.it_multiple = 1),
TAG(DD_MEMBER_PORTAL_INDEX,	"DD member portal index",uint32,
				.it_multiple = 1),
TAG(DD_MEMBER_PORTAL_IP_ADDR,	"DD member portal addr",ipaddr,
				.it_multiple = 1),
TAG(DD_MEMBER_PORTAL_TCP_UDP_PORT,"DD member portal port",uint32,
				USE_ACCESSORS(tcpudp_port),
				.it_multiple = 1),
TAG(DD_FEATURES,		"DD features",		uint32,
				USE_ACCESSORS(dd_features)),
TAG(DD_NEXT_ID,			"DD next ID",		uint32,
				.it_readonly = 1),
};

/*
 * End of RFC defined tags
 */
#undef TAG

/*
 * Open-iSNS vendor specific tags
 */
#define TAG(ID, name, type, args...) \
{ \
	.it_id		= OPENISNS_TAG_##ID,	\
	.it_name	= name, \
	.it_type	= &isns_attr_type_##type, \
	args \
}

static isns_tag_type_t	isns_vendor_tags[] = {
TAG(POLICY_SPI,		"Security Policy Index",	string),
TAG(POLICY_KEY,		"DSA security key",		opaque),
TAG(POLICY_ENTITY,	"Policy allowed entity name",	string),
TAG(POLICY_OBJECT_TYPE,	"Policy allowed object types",	uint32,
				USE_ACCESSORS(policy_object_type)),
TAG(POLICY_NODE_NAME,	"Policy allowed node name",	string,
				.it_multiple = 1),
TAG(POLICY_NODE_TYPE,	"Policy allowed node type",	uint32,
				USE_VALIDATOR(iscsi_node_type),
				USE_ACCESSORS(iscsi_node_type)),
TAG(POLICY_FUNCTIONS,	"Policy allowed functions",	uint32,
				USE_ACCESSORS(policy_function)),
TAG(POLICY_VISIBLE_DD,	"Visible Discovery Domain",	string,
				.it_multiple = 1),
TAG(POLICY_DEFAULT_DD,	"Default Discovery Domain",	string),

{ 0 }
};

/*
 * End of vendor-specific tags
 */

static isns_tag_type_t	isns_unknown_tag = {
	.it_id			= 0xffff,
	.it_name		= "unknown",
	.it_type		= &isns_attr_type_opaque,
};

/*
 * Map iSNS attribute tag to its data type
 */
const isns_tag_type_t *
isns_tag_type_by_id(uint32_t id)
{
	isns_tag_type_t	*tag;

	if (id < ISNS_MAX_BUILTIN_TAG) {
		tag = &isns_tags[id];
		if (tag->it_type == NULL) {
			*tag = isns_unknown_tag;
			tag->it_id = id;
		}
		return tag;
	}

	for (tag = isns_vendor_tags; tag->it_name; ++tag) {
		if (tag->it_id == id)
			return tag;
	}

	return &isns_unknown_tag;
}

/*
 * Specific validators/pretty printers
 */
int
isns_entity_protocol_validate(const isns_value_t *value, const isns_policy_t *policy)
{
	enum isns_entity_protocol protocol = value->iv_uint32;

	switch (protocol) {
	case ISNS_ENTITY_PROTOCOL_NONE:
	case ISNS_ENTITY_PROTOCOL_ISCSI:
	case ISNS_ENTITY_PROTOCOL_IFCP:
		return 1;
	}
	return 0;
}

int
isns_entity_protocol_parse(isns_value_t *value, const char *string)
{
	uint32_t	prot;

	if (!strcasecmp(string, "none"))
		prot = ISNS_ENTITY_PROTOCOL_NONE;
	else if (!strcasecmp(string, "iscsi"))
		prot = ISNS_ENTITY_PROTOCOL_ISCSI;
	else if (!strcasecmp(string, "ifcp"))
		prot = ISNS_ENTITY_PROTOCOL_IFCP;
	else
		return 0;
	value->iv_uint32 = prot;
	return 1;
}

void
isns_entity_protocol_print(const isns_value_t *value, char *buf, size_t size)
{
	enum isns_entity_protocol protocol = value->iv_uint32;
	const char *prot_name;

	switch (protocol) {
	case ISNS_ENTITY_PROTOCOL_NONE:
		prot_name = "None";
		break;

	case ISNS_ENTITY_PROTOCOL_ISCSI:
		prot_name = "iSCSI";
		break;

	case ISNS_ENTITY_PROTOCOL_IFCP:
		prot_name = "iFCP";
		break;

	default:
		prot_name = "Unknown";
	}
	snprintf(buf, size, "%s (%u)", prot_name, protocol);
}

const char *
isns_entity_protocol_help(void)
{
	return "one of None, iSCSI, iFCP";
}

/*
 * TCP/UDP port
 */
int
isns_tcpudp_port_parse(isns_value_t *value, const char *string)
{
	uint32_t	num;
	const char	*ep;

	num = strtoul(string, (char **) &ep, 0);
	if (ep && *ep) {
		if (!strcasecmp(ep, "/udp"))
			num |= ISNS_PORTAL_PORT_UDP_MASK;
		else
		if (!strcasecmp(ep, "/tcp"))
			/* nothing */;
		else {
			isns_error("Cannot parse port spec \"%s\"\n",
					string);
			return 0;
		}
	}
	value->iv_uint32 = num;
	return 1;
}

void
isns_tcpudp_port_print(const isns_value_t *value, char *buf, size_t size)
{
	uint32_t	portspec = value->iv_uint32, num;

	if (portspec == 0) {
		snprintf(buf, size, "[default]");
	} else {
		num = portspec & 0xffff;
		if (portspec & ISNS_PORTAL_PORT_UDP_MASK) {
			snprintf(buf, size, "%u/udp", num);
		} else {
			snprintf(buf, size, "%u/tcp", num);
		}
	}
}

const char *
isns_tcpudp_port_help(void)
{
	return "<port>/tcp, <port>/udp, or <port> (defaults to TCP)";
}

int
isns_timestamp_parse(isns_value_t *value, const char *string)
{
	isns_error("Timestamp parsing not implemented\n");
	return 0;
}

void
isns_timestamp_print(const isns_value_t *value, char *buf, size_t size)
{
	time_t	timestamp = value->iv_uint64;
	char	*str, *s;

	str = ctime(&timestamp);
	if ((s = strchr(str, '\n')) != NULL)
		*s = '\0';

	snprintf(buf, size, "%s", str);
}

const char *
isns_timestamp_help(void)
{
	return NULL;
}

/*
 * Helper macros to implement the off-the-shelf bitfield
 * accessors.
 */
#define IMPLEMENT_BITFIELD_ACCESSORS(name) \
int isns_##name##_parse(isns_value_t *value, const char *string) \
{								\
	return parse_bitfield(name##_bit_names, string,		\
			&value->iv_uint32);			\
}								\
								\
void								\
isns_##name##_print(const isns_value_t *value, char *buf, size_t size) \
{								\
	print_bitfield(value->iv_uint32, name##_bit_names,	\
			buf, size);				\
}								\
								\
const char *							\
isns_##name##_help(void)					\
{								\
	return help_bitfield(name##_bit_names);			\
}


static char *	iscsi_node_type_bit_names[32] = {
[ISNS_ISCSI_NODE_TYPE_TARGET] = "Target",
[ISNS_ISCSI_NODE_TYPE_INITIATOR] = "Initiator",
[ISNS_ISCSI_NODE_TYPE_CONTROL] = "Control",
};

int
isns_iscsi_node_type_validate(const isns_value_t *value, const isns_policy_t *policy)
{
	uint32_t	bits = value->iv_uint32, permitted;

	permitted = ISNS_ISCSI_INITIATOR_MASK |
			ISNS_ISCSI_TARGET_MASK |
			ISNS_ISCSI_CONTROL_MASK;
	if (bits & ~permitted)
		return 0;

	if (policy && !isns_policy_validate_node_type(policy, bits))
		return 0;

	return 1;
}

IMPLEMENT_BITFIELD_ACCESSORS(iscsi_node_type);

/*
 * Portal Security Bitmap
 */
static char *	portal_secbitmap_bit_names[32] = {
[ISNS_PORTAL_SEC_BITMAP_VALID] = "bitmap valid",
[ISNS_PORTAL_SEC_IPSEC_ENABLED] = "ipsec enabled",
[ISNS_PORTAL_SEC_MAIN_MODE_ENABLED] = "main mode enabled",
[ISNS_PORTAL_SEC_AGGR_MODE_ENABLED] = "aggressive mode enabled",
[ISNS_PORTAL_SEC_PFS_ENABLED] = "pfs enabled",
[ISNS_PORTAL_SEC_TRANSPORT_MODE_PREFERRED] = "transport mode preferred",
[ISNS_PORTAL_SEC_TUNNEL_MODE_PREFERRED] = "tunnel mode preferred",
};

IMPLEMENT_BITFIELD_ACCESSORS(portal_secbitmap);

/*
 * SCN bitmap
 */
static char *	scn_bitmap_bit_names[32] = {
[ISNS_SCN_DD_MEMBER_ADDED] = "DD/DDS member added",
[ISNS_SCN_DD_MEMBER_REMOVED] = "DD/DDS member removed",
[ISNS_SCN_OBJECT_UPDATED] = "object updated",
[ISNS_SCN_OBJECT_ADDED] = "object added",
[ISNS_SCN_OBJECT_REMOVED] = "object removed",
[ISNS_SCN_MANAGEMENT_REGISTRATION] = "management registration",
[ISNS_SCN_TARGET_AND_SELF_ONLY] = "target and self information only",
[ISNS_SCN_INITIATOR_AND_SELF_ONLY] = "initiator and self information only",
};

IMPLEMENT_BITFIELD_ACCESSORS(scn_bitmap);

/*
 * DD features bitmap
 */
static char *	dd_features_bit_names[32] = {
[ISNS_DD_BOOT_LIST_ENABLED] = "Boot list enabled",
};

IMPLEMENT_BITFIELD_ACCESSORS(dd_features);

/*
 * Policy: list of allowed functions
 */
static char *	policy_function_bit_names[32] = {
[ISNS_DEVICE_ATTRIBUTE_REGISTER]= "DevAttrReg",
[ISNS_DEVICE_ATTRIBUTE_QUERY]	= "DevAttrQry",
[ISNS_DEVICE_GET_NEXT]		= "DevGetNext",
[ISNS_DEVICE_DEREGISTER]	= "DevDereg",
[ISNS_SCN_REGISTER]		= "SCNReg",
[ISNS_SCN_DEREGISTER]		= "SCNDereg",
[ISNS_SCN_EVENT]		= "SCNEvent",
[ISNS_STATE_CHANGE_NOTIFICATION]= "SCN",
[ISNS_DD_REGISTER]		= "DDReg",
[ISNS_DD_DEREGISTER]		= "DDDereg",
[ISNS_DDS_REGISTER]		= "DDSReg",
[ISNS_DDS_DEREGISTER]		= "DDSDereg",
[ISNS_ENTITY_STATUS_INQUIRY]	= "ESI",
[ISNS_HEARTBEAT]		= "Heartbeat",
};

IMPLEMENT_BITFIELD_ACCESSORS(policy_function);

/*
 * Policy: list of allowed node types
 */
static char *	policy_object_type_bit_names[32] = {
[ISNS_OBJECT_TYPE_ENTITY]	= "entity",
[ISNS_OBJECT_TYPE_NODE]		= "iscsi-node",
[ISNS_OBJECT_TYPE_PORTAL]	= "portal",
[ISNS_OBJECT_TYPE_PG]		= "portal-group",
[ISNS_OBJECT_TYPE_DD]		= "dd",
[ISNS_OBJECT_TYPE_DDSET]	= "ddset",
[ISNS_OBJECT_TYPE_POLICY]	= "policy",
};

static int
isns_policy_object_type_parse(isns_value_t *vp, const char *buf)
{
	char	*copy, *s, *next;
	int	rv = 0;

	if (!strcasecmp(buf, "ALL")) {
		vp->iv_uint32 = ~0;
		return 1;
	}
	if (!strcasecmp(buf, "DEFAULT")) {
		vp->iv_uint32 = ISNS_DEFAULT_OBJECT_ACCESS;
		return 1;
	}

	vp->iv_uint32 = 0;
	copy = isns_strdup(buf);
	for (s = copy; s; s = next) {
		char	*perm;
		int	bit, mask = 0;

		while (1) {
			unsigned int n;

			n = strcspn(s, ",+;|");
			if (n) {
				next = s + n;
				if (*next)
					*next++ = '\0';
				break;
			}
			++n;
		}

		mask = ISNS_PERMISSION_READ;
		if ((perm = strchr(s, ':')) != NULL) {
			*perm++ = '\0';
			mask = 0;
			while (*perm) {
				switch (*perm++) {
				case 'R': case 'r':
					mask = ISNS_PERMISSION_READ;
					break;
				case 'W': case 'w':
					mask = ISNS_PERMISSION_READ;
					break;
				default:
					goto failed;
				}
			}
		}

		for (bit = 0; bit < 32; ++bit) {
			if (policy_object_type_bit_names[bit]
			 && !strcasecmp(policy_object_type_bit_names[bit], s))
				goto found;
		}
		goto failed;

found:		vp->iv_uint32 |= ISNS_ACCESS(bit, mask);
	}
	rv = 1;

failed:
	isns_free(copy);
	return rv;
}

static void
isns_policy_object_type_print(const isns_value_t *vp, char *buf, size_t size)
{
	unsigned int	i, pos = 0;
	uint32_t	mask;
	const char	*sepa = "";

	mask = vp->iv_uint32;
	if (mask == 0) {
		snprintf(buf, size, "<empty>");
		return;
	}

	for (i = 0; i < 32; ++i, mask >>= 2) {
		const char	*name;

		if (!(mask & 3))
			continue;

		name = policy_object_type_bit_names[i];
		if (name)
			snprintf(buf + pos, size - pos, "%s%s:%s%s", sepa, name,
				(mask & ISNS_PERMISSION_READ)? "r" : "",
				(mask & ISNS_PERMISSION_WRITE)? "w" : "");
		else
			snprintf(buf + pos, size - pos, "%sbit%u:%s%s",sepa,  i,
				(mask & ISNS_PERMISSION_READ)? "r" : "",
				(mask & ISNS_PERMISSION_WRITE)? "w" : "");
		sepa = ", ";
		pos = strlen(buf);
	}
}

static const char *
isns_policy_object_type_help(void)
{
	static char	buffer[256];
	unsigned int	i, n;
	char		*sepa = "";

	strcpy(buffer, "bitfield (type:perm): perm=R, W, or RW; type=");
	n = strlen(buffer);

	for (i = 0; i < 32; ++i) {
		if (policy_object_type_bit_names[i]) {
			snprintf(buffer + n, sizeof(buffer) - n,
					"%s%s", sepa,
					policy_object_type_bit_names[i]);
			sepa = ", ";
		}
	}
	return buffer;
}

/*
 * Help message for AuthMethod
 */
const char *
isns_authmethod_help(void)
{
	return "comma separated list, including of KRB5, SPKM1, SPKM2, SRP, CHAP, none";
}

/*
 * Helper functions to deal with bitfields
 */
static void
print_bitfield(unsigned long value, char **bit_names,
		char *buf, size_t size)
{
	unsigned int bit, mask;
	const char *sepa = "";
	char *buf_end;

	if (value == 0) {
		snprintf(buf, size, "<NIL>");
		return;
	}

	buf_end = buf + size;
	for (bit = 0, mask = 1; mask; ++bit, mask <<= 1) {
		char namebuf[16], *name;

		if (!(value & mask))
			continue;

		if ((name = bit_names[bit]) == NULL) {
			sprintf(namebuf, "bit%u", bit);
			name = namebuf;
		}

		snprintf(buf, buf_end - buf, "%s%s", sepa, name);
		buf += strlen(buf);
		sepa = ", ";
	}
}

static int
parse_bitfield(char **bit_names,
		const char *string,
		uint32_t *result)
{
	*result = 0;

	if (!strcasecmp(string, "ALL")) {
		unsigned int	bit;

		for (bit = 0; bit < 32; ++bit) {
			if (bit_names[bit])
				*result |= 1 << bit;
		}
		return 1;
	}

	if (!strcasecmp(string, "NONE"))
		return 1;

	while (*string) {
		unsigned int	n, bit, match = 0;

		n = strcspn(string, ",+;|");
		if (n == 0)
			goto next;

		for (bit = 0; bit < 32; ++bit) {
			if (!bit_names[bit])
				continue;
			if (!strncasecmp(bit_names[bit], string, n)) {
				*result |= 1 << bit;
				match++;
			}
		}
		if (!match)
			return 0;

next:
		string += n;
		string += strspn(string, ",+;|");
	}

	return 1;
}

static const char *
help_bitfield(char **bit_names)
{
	static char	buffer[1024];
	char		*pos, sepa = ':';
	unsigned int	bit;

	strcpy(buffer, "bitfield");
	pos = strchr(buffer, '\0');

	for (bit = 0; bit < 32; ++bit) {
		if (bit_names[bit] == NULL)
			continue;

		snprintf(pos, sizeof(buffer) - (pos - buffer),
				"%c %s", sepa, bit_names[bit]);

		pos += strlen(pos);
		sepa = ',';
	}
	return buffer;
}

