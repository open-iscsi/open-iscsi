/*
 * Test MS initiator registration.
 * The oddity about this is that the PG object precedes the
 * initiator object in the message.
 */

#include <getopt.h>
#include <unistd.h>

#include <isns.h>
#include <paths.h>
#include <util.h>
#include <message.h>

#define ADD(type, tag, value) \
	isns_attr_list_append_##type(attrs, ISNS_TAG_##tag, value)
#define STR(tag, value)		ADD(string, tag, value)
#define U32(tag, value)		ADD(uint32, tag, value)
#define NIL(tag)		isns_attr_list_append_nil(attrs, ISNS_TAG_##tag)
#define TARGET(name, alias, auth) \
	STR(ISCSI_NAME,		name); \
	U32(ISCSI_NODE_TYPE,	ISNS_ISCSI_TARGET_MASK); \
	STR(ISCSI_ALIAS,	alias); \
	STR(ISCSI_AUTHMETHOD,	auth)

int
main(int argc, char **argv)
{
	const char	*opt_configfile = ISNS_DEFAULT_ISNSADM_CONFIG;
	isns_client_t	*clnt;
	isns_attr_list_t *attrs;
	isns_simple_t	*reg;
	isns_portal_info_t portal_info;
	uint32_t	status;
	int		opt_replace = 1;
	int		c;

	while ((c = getopt(argc, argv, "c:d:n")) != -1) {
		switch (c) {
		case 'c':
			opt_configfile = optarg;
			break;

		case 'd':
			isns_enable_debugging(optarg);
			break;

		case 'n':
			opt_replace = 0;
			break;

		default:
			isns_fatal("Unknown option\n");
		}
	}

	isns_read_config(opt_configfile);

	isns_assign_string(&isns_config.ic_source_name,
			"iqn.1991-05.com.microsoft:orange");

	clnt = isns_create_default_client(NULL);

	reg = isns_simple_create(ISNS_SCN_DEREGISTER, clnt->ic_source, NULL);

	/* Message attributes */
	attrs = &reg->is_message_attrs;
	STR(ISCSI_NAME,		"iqn.1991-05.com.microsoft:orange");

	status = isns_client_call(clnt, &reg);
	if (status != ISNS_SUCCESS)
		isns_error("SCNDereg failed: %s\n", isns_strerror(status));
	isns_simple_free(reg);


	reg = isns_simple_create(ISNS_DEVICE_DEREGISTER, clnt->ic_source, NULL);

	attrs = &reg->is_operating_attrs;
	STR(ENTITY_IDENTIFIER,	"troopa.nki.nl");
	U32(ENTITY_PROTOCOL,	2);

	isns_portal_parse(&portal_info, "192.168.1.40:3229/tcp", NULL);
	isns_portal_to_attr_list(&portal_info,
			ISNS_TAG_PORTAL_IP_ADDRESS,
			ISNS_TAG_PORTAL_TCP_UDP_PORT,
			attrs);

	STR(ISCSI_NAME,		"iqn.1991-05.com.microsoft:orange");

	status = isns_client_call(clnt, &reg);
	if (status != ISNS_SUCCESS)
		isns_fatal("DevDereg failed: %s\n", isns_strerror(status));
	isns_simple_free(reg);

	reg = isns_simple_create(ISNS_DEVICE_ATTRIBUTE_REGISTER, clnt->ic_source, NULL);
	reg->is_replace = opt_replace;

	attrs = &reg->is_operating_attrs;
	STR(ENTITY_IDENTIFIER,	"troopa.nki.nl");
	U32(ENTITY_PROTOCOL,	2);

	isns_portal_parse(&portal_info, "192.168.1.40:3229/tcp", NULL);
	isns_portal_to_attr_list(&portal_info,
			ISNS_TAG_PORTAL_IP_ADDRESS,
			ISNS_TAG_PORTAL_TCP_UDP_PORT,
			attrs);

	U32(SCN_PORT,		3230);
	U32(ESI_PORT,		3230);

	U32(PG_TAG,		1);
	STR(PG_ISCSI_NAME,	"iqn.1991-05.com.microsoft:orange");

	STR(ISCSI_NAME,		"iqn.1991-05.com.microsoft:orange");
	U32(ISCSI_NODE_TYPE,	ISNS_ISCSI_INITIATOR_MASK);
	STR(ISCSI_ALIAS,	"<MS SW iSCSI Initiator>");

	status = isns_client_call(clnt, &reg);
	if (status != ISNS_SUCCESS)
		isns_fatal("DevAttrReg failed: %s\n", isns_strerror(status));
	isns_simple_free(reg);

	reg = isns_simple_create(ISNS_DEVICE_GET_NEXT, clnt->ic_source, NULL);
	attrs = &reg->is_message_attrs;
	NIL(ISCSI_NAME);

	attrs = &reg->is_operating_attrs;
	U32(ISCSI_NODE_TYPE,	ISNS_ISCSI_TARGET_MASK);
	NIL(ISCSI_NODE_TYPE);

	status = isns_client_call(clnt, &reg);
	if (status != ISNS_SUCCESS)
		isns_fatal("DevGetNext failed: %s\n", isns_strerror(status));
	isns_simple_free(reg);

	return 0;
}
