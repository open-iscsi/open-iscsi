/*
 * This tests another problem reported by Albert, where a
 * re-registration shortly before ESI expiry would fail
 * to resurrect the registration properly.
 *
 * Usage:
 *  pauw3 [options] timeout
 *
 * Where timeout is the delay until we try to re-register
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
	int		c, n, timeout;

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

	if (optind != argc - 1)
		isns_fatal("Need timeout argument\n");
	timeout = parse_timeout(argv[optind]);

	isns_read_config(opt_configfile);

	/*
	    ---DevAttrReg[REPLACE]---
	    Source:
	      0020  string      : iSCSI name = "iqn.2005-03.org.open-iscsi:blue"
	    Message attributes:
	      0001  string      : Entity identifier = "blue.pauw.homeunix.net"
	    Operating attributes:
	      0001  string      : Entity identifier = "blue.pauw.homeunix.net"
	      0002  uint32      : Entity protocol = iSCSI (2)
	      0010  ipaddr      : Portal IP address = 192.168.1.2
	      0011  uint32      : Portal TCP/UDP port = 33849/tcp
	      0014  uint32      : ESI port = 56288/tcp
	      0020  string      : iSCSI name = "iqn.2005-03.org.open-iscsi:blue"
	      0021  uint32      : iSCSI node type = Initiator
	      0022  string      : iSCSI alias = "blue.pauw.homeunix.net"

	      [...]
    	      response status 0x0003 (Invalid registration)

	   This would fail because we got confused about EID in
	   the replace case.
	 */
	isns_assign_string(&isns_config.ic_source_name,
			"iqn.2005-03.org.open-iscsi:blue");

	for (n = 0; n < 2; ++n) {
		clnt = isns_create_default_client(NULL);
		reg = isns_simple_create(ISNS_DEVICE_ATTRIBUTE_REGISTER,
				clnt->ic_source, NULL);
		reg->is_replace = opt_replace;

		/* Message attributes */
		attrs = &reg->is_message_attrs;
		STR(ENTITY_IDENTIFIER,	"blue.pauw.homeunix.net");

		/* Operating attributes */
		attrs = &reg->is_operating_attrs;

		STR(ENTITY_IDENTIFIER,	"blue.pauw.homeunix.net");
		U32(ENTITY_PROTOCOL,	2);

		isns_portal_parse(&portal_info, "192.168.1.2:33849/tcp", NULL);
		isns_portal_to_attr_list(&portal_info,
				ISNS_TAG_PORTAL_IP_ADDRESS,
				ISNS_TAG_PORTAL_TCP_UDP_PORT,
				attrs);

		U32(ESI_PORT,		56288);
		STR(ISCSI_NAME,		"iqn.2005-03.org.open-iscsi:blue");
		U32(ISCSI_NODE_TYPE,	ISNS_ISCSI_INITIATOR_MASK);
		STR(ISCSI_ALIAS,	"blue.pauw.homeunix.net");
		isns_simple_print(reg, isns_print_stdout);

		status = isns_client_call(clnt, &reg);

		if (status != ISNS_SUCCESS)
			isns_fatal("Unable to register object: %s\n",
					isns_strerror(status));

		printf("Successfully registered object\n");
		// isns_simple_print(reg, isns_print_stdout);
		isns_simple_free(reg);
		isns_client_destroy(clnt);

		if (n == 0) {
			printf("Sleeping for %d seconds\n", timeout);
			sleep(timeout);
		}
	}

	return 0;
}
