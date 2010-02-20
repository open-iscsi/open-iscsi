/*
 * Test case, captured from iscsi-target
 * registering itself.
 */
#include <getopt.h>
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
	int		c;

	while ((c = getopt(argc, argv, "c:d:")) != -1) {
		switch (c) {
		case 'c':
			opt_configfile = optarg;
			break;

		case 'd':
			isns_enable_debugging(optarg);
			break;

		default:
			isns_fatal("Unknown option\n");
		}
	}

	isns_read_config(opt_configfile);

	/*
	    ---DevAttrReg[REPLACE]---
	    Source:
	      0020  string      : iSCSI name = "iqn.2007-03.com.example:stgt.disk"
	    Message attributes:
	      0001  string      : Entity identifier = "blue.pauw.homeunix.net"
	    Operating attributes:
	      0001  string      : Entity identifier = "blue.pauw.homeunix.net"
	      0002  uint32      : Entity protocol = iSCSI (2)
	      0010  ipaddr      : Portal IP address = 192.168.1.2
	      0011  uint32      : Portal TCP/UDP port = 3260/tcp
	      0017  uint32      : SCN port = 42138/tcp
	      0020  string      : iSCSI name = "iqn.2007-03.com.example:stgt.disk"
	      0021  uint32      : iSCSI node type = Target
	 */
	isns_assign_string(&isns_config.ic_source_name,
			"iqn.2007-03.com.example:stgt.disk");

	clnt = isns_create_default_client(NULL);
	reg = isns_simple_create(ISNS_DEVICE_ATTRIBUTE_REGISTER,
			clnt->ic_source, NULL);
	reg->is_replace = 1;

	/* Message attributes */
	attrs = &reg->is_message_attrs;
	STR(ENTITY_IDENTIFIER,	"blue.pauw.homeunix.net");

	/* Operating attributes */
	attrs = &reg->is_operating_attrs;

	STR(ENTITY_IDENTIFIER,	"blue.pauw.homeunix.net");
	U32(ENTITY_PROTOCOL,	2);

	isns_portal_parse(&portal_info, "192.168.1.2:3260/tcp", NULL);
	isns_portal_to_attr_list(&portal_info,
			ISNS_TAG_PORTAL_IP_ADDRESS,
			ISNS_TAG_PORTAL_TCP_UDP_PORT,
			attrs);

	U32(SCN_PORT,		42138);
	STR(ISCSI_NAME,		"iqn.2007-03.com.example:stgt.disk");
	U32(ISCSI_NODE_TYPE,	ISNS_ISCSI_TARGET_MASK);
	isns_simple_print(reg, isns_print_stdout);

	status = isns_client_call(clnt, &reg);

	if (status != ISNS_SUCCESS)
		isns_fatal("Unable to register object: %s\n",
				isns_strerror(status));

	printf("Successfully registered object #1\n");
	// isns_simple_print(reg, isns_print_stdout);
	isns_simple_free(reg);
	isns_client_destroy(clnt);

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

	clnt = isns_create_default_client(NULL);
	reg = isns_simple_create(ISNS_DEVICE_ATTRIBUTE_REGISTER,
			clnt->ic_source, NULL);
	reg->is_replace = 1;

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

	printf("Successfully registered object #2\n");
	// isns_simple_print(reg, isns_print_stdout);
	isns_simple_free(reg);
	isns_client_destroy(clnt);

	return 0;
}

/*
    Creating file DB backend (/var/lib/isns)
    DB: loading all objects from /var/lib/isns
    Next ESI message in 3600 seconds
    Incoming PDU xid=0001 seq=0 len=232 func=DevAttrReg client first last
    Next message xid=0001
    Received message

    :: policy insecure function DevAttrReg (0001) permitted
    :: policy insecure source iqn.2005-03.org.open-iscsi:blue permitted
    :: policy insecure operation DevAttrReg on object 00000001 (Network 
Entity) permitted
    Replacing Network Entity (id 1)
    DB: removed object 2 (Portal)
    DB: removed object 4 (iSCSI Portal Group)
    DB: removed object 3 (iSCSI Storage Node)
    DB: removed object 1 (Network Entity)
    DB: destroying object 2 (Portal)
    DB: Purging object 2 (/var/lib/isns/00000002)
    DB: destroying object 1 (Network Entity)
    DB: Purging object 1 (/var/lib/isns/00000001)
    DB: destroying object 3 (iSCSI Storage Node)
    DB: Purging object 3 (/var/lib/isns/00000003)
    DB: destroying object 4 (iSCSI Portal Group)
    DB: Purging object 4 (/var/lib/isns/00000004)
    :: policy insecure entity ID blue.pauw.homeunix.net permitted
    :: policy insecure operation DevAttrReg on Network Entity object 
permitted
    DB: Storing object 5 -> /var/lib/isns/00000005
    DB: added object 5 (Network Entity) state 1
    DB: Storing object 5 -> /var/lib/isns/00000005
    isns_esi_callback(0x9dee788, 0x10)
    Deleting SCN registration for iqn.2007-03.com.example:stgt.disk
    isns_esi_callback(0x9deeae0, 0x10)
    isns_esi_callback(0x9deea30, 0x10)
    isns_esi_callback(0x9deec80, 0x10)
    SCN multicast <iSCSI Storage Node 3, removed>
    isns_scn_callback(0x9deec80, 0x10)
    isns_esi_callback(0x9def4b0, 0xc)
    Enable ESI monitoring for entity 5

 */
