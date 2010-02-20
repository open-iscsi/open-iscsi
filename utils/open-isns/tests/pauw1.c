/*
 * Test case, captured from a Wasabi Storage Builder
 * registering itself.
 */
#include <getopt.h>
#include <isns.h>
#include <paths.h>
#include <util.h>
#include <message.h>

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
	isns_assign_string(&isns_config.ic_source_name,
			"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0");

	clnt = isns_create_default_client(NULL);

	reg = isns_simple_create(ISNS_DEVICE_ATTRIBUTE_REGISTER,
			clnt->ic_source, NULL);

	attrs = &reg->is_operating_attrs;

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

	STR(ENTITY_IDENTIFIER,		"cyan.pauw.homeunix.net");
	U32(ENTITY_PROTOCOL,		2);
	U32(REGISTRATION_PERIOD,	31536000);

	TARGET("iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0",
	       "Test (10 GB)",
	       "None");
	TARGET("iqn.2000-05.com.wasabisystems.storagebuilder:cyan-1",
	       "160 GB disk (ntfs)",
	       "None");
	TARGET("iqn.2000-05.com.wasabisystems.storagebuilder:cyan-2",
	       "160 GB disk (ext3)",
	       "CHAP");
	TARGET("iqn.2000-05.com.wasabisystems.storagebuilder:cyan-3",
	       "Test (1 GB)",
	       "None");
	TARGET("iqn.2000-05.com.wasabisystems.storagebuilder:cyan-4",
	       "Test (40 GB)",
	       "CHAP");
	TARGET("iqn.2000-05.com.wasabisystems.storagebuilder:cyan-5",
	       "test",
	       "None");

	isns_portal_parse(&portal_info, "10.0.0.1:3260/tcp", NULL);
	isns_portal_to_attr_list(&portal_info,
			ISNS_TAG_PORTAL_IP_ADDRESS,
			ISNS_TAG_PORTAL_TCP_UDP_PORT,
			attrs);

	/* Mumbo jumbo encoding of portal groups */
	U32(PG_TAG,		1);
	STR(PG_ISCSI_NAME,	"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0");
	STR(PG_ISCSI_NAME,	"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-1");
	STR(PG_ISCSI_NAME,	"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-2");
	STR(PG_ISCSI_NAME,	"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-3");
	STR(PG_ISCSI_NAME,	"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-4");
	STR(PG_ISCSI_NAME,	"iqn.2000-05.com.wasabisystems.storagebuilder:cyan-5");

	/* Strictly speaking, a PGT not followed by any data is invalid.
	 *
	 * 5.6.5.1.
	 * When a Portal is registered, the Portal attributes MAY
	 * immediately be followed by a PGT attribute.	The PGT attribute
	 * SHALL be followed by the set of PG iSCSI Names representing
	 * nodes that will be associated to the Portal using the indicated
	 * PGT value.
	 */
	NIL(PG_TAG);

	isns_simple_print(reg, isns_print_stdout);

	status = isns_client_call(clnt, &reg);

	if (status != ISNS_SUCCESS)
		isns_fatal("Unable to register object: %s\n",
				isns_strerror(status));

	printf("Successfully registered object(s)\n");
	isns_simple_print(reg, isns_print_stdout);

	return 0;
}

/*
   Creating file DB backend (/var/lib/isns)
   DB: loading all objects from /var/lib/isns
   Next ESI message in 3600 seconds
   Incoming PDU xid=0001 seq=0 len=1208 func=DevAttrReg client first last
   Next message xid=0001
   Received message
   ---DevAttrReg---
   Source:
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0"
   Message attributes: <empty list>
   Operating attributes:
     0001  string      : Entity identifier = "cyan.pauw.homeunix.net"
     0002  uint32      : Entity protocol = iSCSI (2)
     0006  uint32      : Registration Period = 31536000
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0"
     0021  uint32      : iSCSI node type = Target
     0022  string      : iSCSI alias = "Test (10 GB)"
     002a  string      : iSCSI auth method = "None"
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-1"
     0021  uint32      : iSCSI node type = Target
     0022  string      : iSCSI alias = "160 GB disk (ntfs)"
     002a  string      : iSCSI auth method = "None"
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-2"
     0021  uint32      : iSCSI node type = Target
     0022  string      : iSCSI alias = "160 GB disk (ext3)"
     002a  string      : iSCSI auth method = "CHAP"
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-3"
     0021  uint32      : iSCSI node type = Target
     0022  string      : iSCSI alias = "Test (1 GB)"
     002a  string      : iSCSI auth method = "None"
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-4"
     0021  uint32      : iSCSI node type = Target
     0022  string      : iSCSI alias = "Test (40 GB)"
     002a  string      : iSCSI auth method = "CHAP"
     0020  string      : iSCSI name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-5"
     0021  uint32      : iSCSI node type = Target
     0022  string      : iSCSI alias = "test"
     002a  string      : iSCSI auth method = "None"
     0010  ipaddr      : Portal IP address = 10.0.0.1
     0011  uint32      : Portal TCP/UDP port = 3260/tcp
     0033  uint32      : Portal group tag = 1
     0030  string      : Portal group name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0"
     0030  string      : Portal group name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-1"
     0030  string      : Portal group name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-2"
     0030  string      : Portal group name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-3"
     0030  string      : Portal group name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-4"
     0030  string      : Portal group name = "iqn.2000-05.com.wasabisystems.storagebuilder:cyan-5"
     0033  nil         : Portal group tag = <empty>
   :: policy insecure function DevAttrReg (0001) permitted
   :: policy insecure source
iqn.2000-05.com.wasabisystems.storagebuilder:cyan-0 permitted
   :: policy insecure operation DevAttrReg on Network Entity object
permitted
   DB: Storing object 00000001 -> /var/lib/isns/00000001
   DB: added object 1 (Network Entity) state 1
Segmentation fault
 */
