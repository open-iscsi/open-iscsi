/*
 * isnsadm - helper utility
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "isns.h"
#include "util.h"
#include "vendor.h"
#include "attrs.h"
#include "security.h"
#include "objects.h"
#include "paths.h"
#include "config.h"

#define ISNS_DEFAULT_PORT_INITIATOR	860
#define ISNS_DEFAULT_PORT_TARGET	3260


enum {
	DO_REGISTER = 1024,
	DO_QUERY,
	DO_QUERY_EID,
	DO_LIST,
	DO_DEREGISTER,
	DO_DD_REGISTER,
	DO_DD_DEREGISTER,
	DO_ENROLL,
	DO_EDIT_POLICY,
	DO_DELETE_POLICY,
};

static struct option	options[] = {
      { "help",			no_argument,		NULL,	'h'		},
      {	"config",		required_argument,	NULL,	'c'		},
      {	"debug",		required_argument,	NULL,	'd'		},
      { "keyfile",		required_argument,	NULL,	'K',		},
      { "key",			required_argument,	NULL,	'k',		},
      {	"local",		no_argument,		NULL,	'l'		},
      {	"control",		no_argument,		NULL,	'C'		},
      {	"replace",		no_argument,		NULL,	'r'		},
      { "query",		no_argument,		NULL,	DO_QUERY	},
      { "query-eid",		no_argument,		NULL,	DO_QUERY_EID	},
      { "list",			no_argument,		NULL,	DO_LIST		},
      { "register",		no_argument,		NULL,	DO_REGISTER	},
      {	"deregister",		no_argument,		NULL,	DO_DEREGISTER	},
      { "dd-register",		no_argument,		NULL,	DO_DD_REGISTER	},
      {	"dd-deregister",	no_argument,		NULL,	DO_DD_DEREGISTER},

      { "enroll",		no_argument,		NULL,	DO_ENROLL	},
      { "edit-policy",		no_argument,		NULL,	DO_EDIT_POLICY	},
      { "delete-policy",	no_argument,		NULL,	DO_DELETE_POLICY },

      { "version",		no_argument,		NULL,	'V'		},
      { NULL }
};


static const char *	opt_configfile = ISNS_DEFAULT_ISNSADM_CONFIG;
static int		opt_af = AF_UNSPEC;
static int		opt_action = 0;
static int		opt_local = 0;
static int		opt_control = 0;
static int		opt_replace = 0;
static const char *	opt_keyfile = NULL;
static char *		opt_key = NULL;
static struct sockaddr_storage opt_myaddr;

static void	usage(int, const char *);

static int	register_objects(isns_client_t *, int, char **);
static int	query_objects(isns_client_t *, int, char **);
static int	query_entity_id(isns_client_t *, int, char **);
static int	list_objects(isns_client_t *, int, char **);
static int	deregister_objects(isns_client_t *, int, char **);
static int	register_domain(isns_client_t *, int, char **);
static int	deregister_domain(isns_client_t *, int, char **);
static int	enroll_client(isns_client_t *, int, char **);
static int	edit_policy(isns_client_t *, int, char **);

static isns_attr_t *	load_key_callback(const char *);
static isns_attr_t *	generate_key_callback(void);

int
main(int argc, char **argv)
{
	isns_client_t	*clnt;
	isns_security_t	*security = NULL;
	int		c, status;

	while ((c = getopt_long(argc, argv, "46Cc:d:hK:k:l", options, NULL)) != -1) {
		switch (c) {
		case '4':
			opt_af = AF_INET;
			break;

		case '6':
			opt_af = AF_INET6;
			break;

		case 'C':
			opt_control = 1;
			break;

		case 'c':
			opt_configfile = optarg;
			break;

		case 'd':
			isns_enable_debugging(optarg);
			break;

		case 'h':
			usage(0, NULL);
			break;

		case 'K':
			opt_keyfile = optarg;
			break;

		case 'k':
			opt_key = optarg;
			break;

		case 'l':
			opt_local = 1;
			break;

		case 'r':
			opt_replace = 1;
			break;

		case 'V':
			printf("Open-iSNS version %s\n"
			       "Copyright (C) 2007, Olaf Kirch <olaf.kirch@oracle.com>\n",
			       OPENISNS_VERSION_STRING);
			return 0;

		case DO_REGISTER:
		case DO_QUERY:
		case DO_QUERY_EID:
		case DO_LIST:
		case DO_DEREGISTER:
		case DO_DD_REGISTER:
		case DO_DD_DEREGISTER:
		case DO_ENROLL:
		case DO_EDIT_POLICY:
		case DO_DELETE_POLICY:
			if (opt_action)
				usage(1, "You cannot specify more than one mode\n");
			opt_action = c;
			break;

		default:
			usage(1, "Unknown option");
		}
	}
	
	isns_read_config(opt_configfile);

	if (!isns_config.ic_source_name)
		usage(1, "Please specify an iSNS source name");
	if (!isns_config.ic_server_name)
		usage(1, "Please specify an iSNS server name");
	if (!opt_action)
		usage(1, "Please specify an operating mode");

	if (opt_control) {
		if (!isns_config.ic_security)
			isns_fatal("Cannot use control mode, security disabled\n");
		security = isns_control_security_context(0);
		if (!security)
			isns_fatal("Unable to create control security context\n");

		/* Create a networked client, using isns.control as
		 * the source name */
		clnt = isns_create_client(security, isns_config.ic_control_name);
	} else if (opt_local) {
		/* Create a local client, using isns.control as
		 * the source name */
		clnt = isns_create_local_client(security,
				isns_config.ic_control_name);
	} else {
		/* Create a networked client, using the configured
		 * source name */
		clnt = isns_create_default_client(security);
	}

	if (clnt == NULL)
		return 1;

	/* We're an interactive app, and don't want to retry
	 * forever if the server refuses us. */
	isns_socket_set_disconnect_fatal(clnt->ic_socket);

	/* Get the IP address we use to talk to the iSNS server */
	if (opt_myaddr.ss_family == AF_UNSPEC && !opt_local) {
		if (!isns_socket_get_local_addr(clnt->ic_socket, &opt_myaddr))
			isns_fatal("Unable to obtain my IP address\n");
		isns_addr_set_port((struct sockaddr *) &opt_myaddr, 860);
	}

	argv += optind; argc -= optind;
	switch (opt_action) {
	case DO_REGISTER:
		status = register_objects(clnt, argc, argv);
		break;

	case DO_QUERY:
		status = query_objects(clnt, argc, argv);
		break;

	case DO_QUERY_EID:
		status = query_entity_id(clnt, argc, argv);
		break;

	case DO_LIST:
		status = list_objects(clnt, argc, argv);
		break;

	case DO_DEREGISTER:
		status = deregister_objects(clnt, argc, argv);
		break;

	case DO_DD_REGISTER:
		status = register_domain(clnt, argc, argv);
		break;

	case DO_DD_DEREGISTER:
		status = deregister_domain(clnt, argc, argv);
		break;


	case DO_ENROLL:
		status = enroll_client(clnt, argc, argv);
		break;

	case DO_EDIT_POLICY:
		status = edit_policy(clnt, argc, argv);
		break;

	// case DO_DELETE_POLICY:

	default:
		isns_fatal("Not yet implemented\n");
		status = 1; /* compiler food */
	}

	return status != ISNS_SUCCESS;
}

void
usage(int exval, const char *msg)
{
	if (msg)
		fprintf(stderr, "Error: %s\n", msg);
	fprintf(stderr,
	"Usage: isnsadm [options] --action ...\n"
	"  --config        Specify alternative config fille\n"
	"  --debug         Enable debugging (list of debug flags)\n"
	"  --keyfile       Where to store newly generated private key\n"
	"  --local         Use local Unix socket to talk to isnsd\n"
	"  --control       Assume control node identity for authentication\n"
	"  --replace       Use replace mode (--register only)\n"
	"\nThe following actions are supported:\n"
	"  --register      Register one or more objects\n"
	"  --deregister    Deregister an object (and children)\n"
	"  --query         Query iSNS server for objects\n"
	"  --list          List all objects of a given type\n"
	"  --enroll        Create a new policy object for a client\n"
	"  --edit-policy   Edit a policy object\n"
	"  --delete-policy Edit a policy object\n"
	"  --help          Display this message\n"
	"\nUse \"--query help\" to get help on e.g. the query action\n"
	);
	exit(exval);
}

int
parse_registration(char **argv, int argc, isns_object_list_t *objs, isns_object_t *key_obj)
{
	struct sockaddr_storage def_addr;
	isns_object_t	*entity = NULL, *last_portal = NULL, *last_node = NULL;
	const char	*def_port = NULL;
	int		i;

	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("Object registration:\n"
		       " isnsadm [-key attr=value] --register type,attr=value,... type,attr=value,...\n"
		       "Where type can be one of:\n"
		       "  entity         create/update network entity\n"
		       "  initiator      create iSCSI initiator storage node\n"
		       "  target         create iSCSI target storage node\n"
		       "  control        create control node\n"
		       "  portal         create portal\n"
		       "  pg             create portal group\n"
		       "\nThe following attributes are recognized:\n");

		isns_attr_list_parser_help(NULL);
		exit(0);
	}

	if (argc == 0)
		usage(1, "Missing object list\n");

	if (key_obj) {
		//isns_object_list_append(objs, key_obj);
		if (isns_object_is_entity(key_obj))
			entity = key_obj;
	}

	def_addr = opt_myaddr;

	for (i = 0; i < argc; ++i) {
		isns_attr_list_t attrlist = ISNS_ATTR_LIST_INIT;
		struct isns_attr_list_parser state;
		isns_object_t	*obj;
		char		*type, *name, *value, *next_attr;
		char		*attrs[128];
		unsigned int	nattrs = 0;

		name = argv[i];

		if ((next_attr = strchr(name, ',')) != NULL)
			*next_attr++ = '\0';

		while (next_attr && *next_attr) {
			if (nattrs > 128)
				isns_fatal("Too many attributes\n");

			/* Show mercy with fat fingered
			 * people,,,,who,cannot,,,type,properly */
			if (next_attr[0] != ',')
				attrs[nattrs++] = next_attr;
			if ((next_attr = strchr(next_attr, ',')) != NULL)
				*next_attr++ = '\0';
		}

		if ((value = strchr(name, '=')) != NULL)
			*value++ = '\0';

		type = name;
		if (!strcmp(name, "entity")) {
			if (entity == NULL) {
				isns_error("Cannot create entity object "
					"within this key object\n");
				return 0;
			}

			if (value != NULL)
				isns_object_set_string(entity,
						ISNS_TAG_ENTITY_IDENTIFIER,
						value);
			obj = isns_object_get(entity);
			goto handle_attributes;
		} else
		if (!strcmp(name, "node")
		 || !strcmp(name, "initiator")) {
			const char *node_name;

			node_name = isns_config.ic_source_name;
			if (value)
				node_name = value;

			obj = isns_create_storage_node(node_name,
					ISNS_ISCSI_INITIATOR_MASK,
					entity);
			last_node = obj;

			isns_addr_set_port((struct sockaddr *) &def_addr,
					ISNS_DEFAULT_PORT_INITIATOR);
			def_port = "iscsi";
		} else
		if (!strcmp(name, "target")) {
			const char *node_name;

			node_name = isns_config.ic_source_name;
			if (value)
				node_name = value;
			obj = isns_create_storage_node(node_name,
					ISNS_ISCSI_TARGET_MASK,
					entity);
			last_node = obj;

			isns_addr_set_port((struct sockaddr *) &def_addr,
					ISNS_DEFAULT_PORT_TARGET);
			def_port = "iscsi-target";
		} else
		if (!strcmp(name, "control")) {
			const char *node_name;

			node_name = isns_config.ic_control_name;
			if (value)
				node_name = value;
			obj = isns_create_storage_node(node_name,
					ISNS_ISCSI_CONTROL_MASK,
					entity);
			last_node = obj;

			def_port = NULL;
		} else
		if (!strcmp(name, "portal")) {
			isns_portal_info_t portal_info;

			if (value == NULL) {
				if (def_port == NULL)
					isns_fatal("portal must follow initiator or target\n");
				isns_portal_init(&portal_info,
						(struct sockaddr *) &def_addr,
						IPPROTO_TCP);
			} else
			if (!isns_portal_parse(&portal_info, value, def_port))
				isns_fatal("Unable to parse portal=%s\n", value);
			obj = isns_create_portal(&portal_info, entity);
			last_portal = obj;
		} else
		if (!strcmp(name, "pg")) {
			if (value)
				isns_fatal("Unexpected value for portal group\n");
			if (!last_portal || !last_node)
				isns_fatal("Portal group registration must follow portal and node\n");
			obj = isns_create_portal_group(last_portal, last_node, 10);
		} else {
			isns_error("Unknown object type \"%s\"\n", name);
			return 0;
		}

		if (obj == NULL) {
			isns_error("Failure to create %s object\n", name);
			return 0;
		}
		isns_object_list_append(objs, obj);

handle_attributes:
		isns_attr_list_parser_init(&state, obj->ie_template);
		state.default_port = def_port;

		if (!isns_parse_attrs(nattrs, attrs, &attrlist, &state)
		 || !isns_object_set_attrlist(obj, &attrlist)) {
			isns_error("Failure to set all %s attributes\n", name);
			isns_attr_list_destroy(&attrlist);
			return 0;
		}

		isns_attr_list_destroy(&attrlist);
		isns_object_release(obj);
	}

	return 1;
}

static int
__register_objects(isns_client_t *clnt,
		isns_object_t *key_obj,
		const isns_object_list_t *objects)
{
	isns_source_t	*source = NULL;
	isns_simple_t	*reg;
	uint32_t	status;
	unsigned int	i;

	for (i = 0; i < objects->iol_count && !source; ++i) {
		isns_object_t *obj = objects->iol_data[i];

		if (!isns_object_is_iscsi_node(obj))
			continue;
		source = isns_source_from_object(obj);
	}

	reg = isns_create_registration2(clnt, key_obj, source);
	isns_registration_set_replace(reg, opt_replace);

	/* Add all objects to be registered */
	for (i = 0; i < objects->iol_count; ++i)
		isns_registration_add_object(reg, objects->iol_data[i]);

	status = isns_client_call(clnt, &reg);
	isns_simple_free(reg);

	if (status == ISNS_SUCCESS)
		printf("Successfully registered object(s)\n");
	else
		isns_error("Failed to register object(s): %s\n",
				isns_strerror(status));

	if (source)
		isns_source_release(source);
	return status;
}

int
register_objects(isns_client_t *clnt,
		int argc, char **argv)
{
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	isns_object_t	*key_obj = NULL;
	uint32_t	status;

	if (opt_key != NULL) {
		isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
		struct isns_attr_list_parser state;

		isns_attr_list_parser_init(&state, NULL);

		if (!isns_parse_attrs(1, &opt_key, &key_attrs, &state)) {
			isns_error("Cannot parse registration key \"%s\"\n",
					opt_key);
			return 0;
		}

		key_obj = isns_create_object(isns_attr_list_parser_context(&state),
				&key_attrs, NULL);
		isns_attr_list_destroy(&key_attrs);

		if (!key_obj) {
			isns_error("Cannot create registration key object\n");
			return 0;
		}
	} else {
		/* If the user does not provide a key object, 
		 * create/update an entity.
		 */
		key_obj = isns_create_entity(ISNS_ENTITY_PROTOCOL_ISCSI, NULL);
	}

	if (!parse_registration(argv, argc, &objects, key_obj))
		isns_fatal("Unable to parse registration\n");

	status = __register_objects(clnt, key_obj, &objects);
	isns_object_list_destroy(&objects);

	isns_object_release(key_obj);
	return status;
}

/*
 * Parse the query string given by the user
 *
 * 5.6.5.2
 * The Message Key may contain key or non-key attributes or no
 * attributes at all.  If multiple attributes are used as the
 * Message Key, then they MUST all be from the same object type
 * (e.g., IP address and TCP/UDP Port are attributes of the
 * Portal object type).
 */
int
parse_query(char **argv, int argc, isns_attr_list_t *keys, isns_attr_list_t *query)
{
	struct isns_attr_list_parser state;

	isns_attr_list_parser_init(&state, NULL);
	state.nil_permitted = 1;

	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("Object query:\n"
		       " isnsadm --query attr=value attr=value ... ?query-attr ?query-attr ...\n"
		       "All key attributes must refer to a common object type.\n"
		       "Query attributes specify the attributes the server should return,"
		       "and can refer to any object type.\n"
		       "The following attributes are recognized:\n");
		isns_attr_list_parser_help(&state);
		exit(0);
	}

	if (argc == 0)
		isns_fatal("Missing query attributes\n");

	return isns_parse_query_attrs(argc, argv, keys, query, &state);
}

int
query_objects(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t query_key = ISNS_ATTR_LIST_INIT;
	isns_attr_list_t oper_attrs = ISNS_ATTR_LIST_INIT;
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	uint32_t	status;
	isns_simple_t	*qry;
	unsigned int	i;

	if (!parse_query(argv, argc, &query_key, &oper_attrs))
		isns_fatal("Unable to parse query\n");

	qry = isns_create_query(clnt, &query_key);
	isns_attr_list_destroy(&query_key);

	/* Add the list of attributes we request */
	for (i = 0; i < oper_attrs.ial_count; ++i)
		isns_query_request_attr(qry, oper_attrs.ial_data[i]);
	isns_attr_list_destroy(&oper_attrs);

	status = isns_client_call(clnt, &qry);
	if (status != ISNS_SUCCESS) {
		isns_error("Query failed: %s\n", isns_strerror(status));
		return status;
	}

	status = isns_query_response_get_objects(qry, &objects);
	if (status) {
		isns_error("Unable to extract object list from query response: %s\n",
				isns_strerror(status), status);
		return status;
	}

	isns_object_list_print(&objects, isns_print_stdout);
	isns_object_list_destroy(&objects);
	isns_simple_free(qry);

	return status;
}

int
query_entity_id(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t query_key = ISNS_ATTR_LIST_INIT;
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	uint32_t	status;
	isns_simple_t	*qry;
	const char	*eid;

	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("Query iSNS for own entity ID.\n"
		       "No arguments allowed\n");
		exit(0);
	}
	if (argc != 0)
		isns_fatal("EID query - no arguments accepted\n");

	isns_attr_list_append_string(&query_key,
			ISNS_TAG_ISCSI_NAME,
			isns_config.ic_source_name);
	qry = isns_create_query(clnt, &query_key);
	isns_attr_list_destroy(&query_key);

	isns_query_request_attr_tag(qry, ISNS_TAG_ENTITY_IDENTIFIER);

	status = isns_client_call(clnt, &qry);
	if (status != ISNS_SUCCESS) {
		isns_error("Query failed: %s\n", isns_strerror(status));
		return status;
	}

	status = isns_query_response_get_objects(qry, &objects);
	if (status) {
		isns_error("Unable to extract object list from query response: %s\n",
				isns_strerror(status), status);
		return status;
	}

	status = ISNS_NO_SUCH_ENTRY;
	if (objects.iol_count == 0) {
		isns_error("Node %s not registered with iSNS\n",
				isns_config.ic_source_name);
	} else
	if (!isns_object_get_string(objects.iol_data[0],
				ISNS_TAG_ENTITY_IDENTIFIER, &eid)) {
		isns_error("Query for %s returned an object without EID\n",
				isns_config.ic_source_name);
	} else {
		printf("%s\n", eid);
		status = ISNS_SUCCESS;
	}

	isns_object_list_destroy(&objects);
	isns_simple_free(qry);

	return status;
}

/*
 * Parse the list query string given by the user
 */
int
parse_list(int argc, char **argv, isns_object_template_t **type_p, isns_attr_list_t *keys)
{
	struct isns_attr_list_parser state;
	isns_object_template_t *query_type = NULL;
	char	*type_name;

	if (argc == 0)
		usage(1, "Missing object type");

	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("Object query:\n"
		       " isnsadm --list type attr=value attr=value ...\n"
		       "Possible value for <type>:\n"
		       " entities           - list all network entites\n"
		       " nodes              - list all storage nodes\n"
		       " portals            - list all portals\n"
		       " portal-groups      - list all portal groups\n"
		       " dds                - list all discovery domains\n"
		       " ddsets             - list all discovery domains sets\n"
		       " policies           - list all policies (privileged)\n"
		       "Additional attributes can be specified to scope the\n"
		       "search. They must match the specified object type.\n"
		       "\nThe following attributes are recognized:\n");
		isns_attr_list_parser_help(NULL);
		exit(0);
	}

	type_name = *argv++; --argc;
	if (!strcasecmp(type_name, "entities"))
		query_type = &isns_entity_template;
	else
	if (!strcasecmp(type_name, "nodes"))
		query_type = &isns_iscsi_node_template;
	else
	if (!strcasecmp(type_name, "portals"))
		query_type = &isns_portal_template;
	else
	if (!strcasecmp(type_name, "portal-groups"))
		query_type = &isns_iscsi_pg_template;
	else
	if (!strcasecmp(type_name, "dds"))
		query_type = &isns_dd_template;
	else
	if (!strcasecmp(type_name, "ddsets"))
		query_type = &isns_ddset_template;
	else
	if (!strcasecmp(type_name, "policies"))
		query_type = &isns_policy_template;
	else {
		isns_error("Unknown object type \"%s\"\n",
				type_name);
		return 0;
	}

	*type_p = query_type;

	isns_attr_list_parser_init(&state, query_type);
	state.nil_permitted = 1;

	return isns_parse_attrs(argc, argv, keys, &state);
}

int
list_objects(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t	query_keys = ISNS_ATTR_LIST_INIT;
	isns_object_template_t	*query_type = NULL;
	isns_simple_t		*simp;
	int			status, count = 0;

	if (!parse_list(argc, argv, &query_type, &query_keys))
		isns_fatal("Unable to parse parameters\n");

	simp = isns_create_getnext(clnt, query_type, &query_keys);
	while (1) {
		isns_object_t	*obj = NULL;
		isns_simple_t	*followup;

		status = isns_client_call(clnt, &simp);
		if (status)
			break;

		status = isns_getnext_response_get_object(simp, &obj);
		if (status)
			break;

		printf("Object %u:\n", count++);
		isns_object_print(obj, isns_print_stdout);
		isns_object_release(obj);

		followup = isns_create_getnext_followup(clnt,
				simp, &query_keys);
		isns_simple_free(simp);
		simp = followup;
	}

	if (status == ISNS_SOURCE_UNAUTHORIZED
	 && query_type == &isns_policy_template
	 && !opt_local)
		isns_warning("Please use --local trying to list policies\n");

	if (status != ISNS_NO_SUCH_ENTRY) {
		isns_error("GetNext call failed: %s\n",
				isns_strerror(status));
		return status;
	}
	return ISNS_SUCCESS;
}

/*
 * Parse the deregistration string given by the user
 *
 * 5.6.5.2
 * The Message Key may contain key or non-key attributes or no
 * attributes at all.  If multiple attributes are used as the
 * Message Key, then they MUST all be from the same object type
 * (e.g., IP address and TCP/UDP Port are attributes of the
 * Portal object type).
 */
int
parse_deregistration(char **argv, int argc, isns_attr_list_t *keys)
{
	struct isns_attr_list_parser state;

	isns_attr_list_parser_init(&state, NULL);
	state.multi_type_permitted = 1;
	state.nil_permitted = 1;

	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("Object deregistration:\n"
		       " isnsadm --deregister attr=value attr=value ...\n"
		       "All attributes must refer to a common object type.\n"
		       "\nThe following attributes are recognized:\n");
		isns_attr_list_parser_help(&state);
		exit(0);
	}

	return isns_parse_attrs(argc, argv, keys, &state);
}

int
deregister_objects(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t query_key = ISNS_ATTR_LIST_INIT;
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	isns_simple_t	*dereg;
	uint32_t	status;

	if (!parse_deregistration(argv, argc, &query_key))
		isns_fatal("Unable to parse unregistration\n");

	dereg = isns_create_deregistration(clnt, &query_key);
	isns_attr_list_destroy(&query_key);

	status = isns_client_call(clnt, &dereg);
	if (status != ISNS_SUCCESS) {
		isns_error("Deregistration failed: %s\n",
				isns_strerror(status));
		return status;
	}

#if 0
	status = isns_dereg_msg_response_get_objects(dereg, &objects);
	if (status) {
		isns_error("Unable to extract object list from deregistration response: %s\n",
				isns_strerror(status), status);
		goto done;
	}
	isns_object_list_print(&objects, isns_print_stdout);
#endif

	isns_object_list_destroy(&objects);
	isns_simple_free(dereg);

	return status;
}

/*
 * Handle discovery domain registration/deregistration
 */
int
parse_dd_registration(char **argv, int argc, isns_attr_list_t *keys)
{
	struct isns_attr_list_parser state;

	isns_attr_list_parser_init(&state, &isns_dd_template);
	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("Object query:\n"
		       " isnsadm --dd-register attr=value attr=value ...\n"
		       "You cannot specify more than one domain.\n"
		       "If you want to modify an existing domain, you must specify its ID.\n"
		       "The following attributes are recognized:\n");
		isns_attr_list_parser_help(&state);
		exit(0);
	}

	return isns_parse_attrs(argc, argv, keys, &state);
}

int
register_domain(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	isns_simple_t	*msg;
	uint32_t	status;

	if (!parse_dd_registration(argv, argc, &attrs))
		isns_fatal("Unable to parse DD registration\n");

	msg = isns_create_dd_registration(clnt, &attrs);
	isns_attr_list_destroy(&attrs);

	if (msg == NULL) {
		isns_error("Cannot create message\n");
		return ISNS_INTERNAL_ERROR;
	}

	status = isns_client_call(clnt, &msg);
	if (status != ISNS_SUCCESS) {
		isns_error("Registration failed: %s\n",
				isns_strerror(status));
		return status;
	}

	if (status == ISNS_SUCCESS) {
		printf("Registered DD:\n");
		isns_attr_list_print(
				isns_simple_get_attrs(msg),
				isns_print_stdout);
	}
	isns_simple_free(msg);

	return status;
}

int
parse_dd_deregistration(char **argv, int argc,
		uint32_t *dd_id, isns_attr_list_t *keys)
{
	struct isns_attr_list_parser state;

	isns_attr_list_parser_init(&state, &isns_dd_template);
	if (argc == 0 || (argc == 1 && !strcmp(argv[0], "help"))) {
		printf("DD deregistration:\n"
		       " isnsadm --dd-deregister dd-id attr=value attr=value ...\n"
		       "You cannot specify more than one domain.\n"
		       "The following attributes are recognized:\n");
		isns_attr_list_parser_help(&state);
		exit(0);
	}

	*dd_id = parse_count(argv[0]);

	return isns_parse_attrs(argc - 1, argv + 1, keys, &state);
}

int
deregister_domain(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	isns_simple_t	*msg;
	uint32_t	dd_id, status;

	if (!parse_dd_deregistration(argv, argc, &dd_id, &attrs))
		isns_fatal("Unable to parse DD registration\n");

	msg = isns_create_dd_deregistration(clnt, dd_id, &attrs);
	isns_attr_list_destroy(&attrs);

	if (msg == NULL) {
		isns_error("Cannot create message\n");
		return ISNS_INTERNAL_ERROR;
	}

	status = isns_client_call(clnt, &msg);
	if (status != ISNS_SUCCESS) {
		isns_error("Deregistration failed: %s\n",
				isns_strerror(status));
		return status;
	}

	isns_simple_free(msg);
	return status;
}

/*
 * Parse a policy
 */
int
parse_policy(int argc, char **argv, isns_attr_list_t *attrs,
		const char *help_title, const char *help_action)
{
	struct isns_attr_list_parser state;

	isns_attr_list_parser_init(&state, &isns_policy_template);
	state.nil_permitted = 0;
	state.load_key = load_key_callback;
	state.generate_key = generate_key_callback;

	if (argc == 1 && !strcmp(argv[0], "help")) {
		printf("%s:\n"
		       " isnsadm %s attr=value attr=value ...\n"
		       "Specifying a Security Policy Index is mandatory.\n"
		       "\nThe following attributes are recognized:\n",
		       help_title, help_action);
		isns_attr_list_parser_help(&state);
		exit(0);
	}

	return isns_parse_attrs(argc, argv, attrs, &state);
}

static int
__create_policy(isns_client_t *clnt, const isns_attr_list_t *attrs)
{
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	isns_object_t	*obj;
	int		status;

	obj = isns_create_object(&isns_policy_template, attrs, NULL);
	if (!obj)
		isns_fatal("Cannot create policy object\n");
	isns_object_list_append(&objects, obj);

	status = __register_objects(clnt, NULL, &objects);
	isns_object_list_destroy(&objects);
	return status;
}

/*
 * Enroll a new client
 */
int
enroll_client(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	const char	*client_name;
	int		status;

	if (argc == 0)
		usage(1, "Missing client name");

	client_name = *argv++; --argc;

	isns_attr_list_append_string(&attrs,
			OPENISNS_TAG_POLICY_SPI,
			client_name);
#if 0
	isns_attr_list_append_string(&attrs,
			OPENISNS_TAG_POLICY_SOURCE_NAME,
			client_name);
#endif

	if (!opt_keyfile) {
		static char 	namebuf[PATH_MAX];

		snprintf(namebuf, sizeof(namebuf), "%s.key", client_name);
		opt_keyfile = namebuf;
	}

	if (argc && !parse_policy(argc, argv, &attrs,
				"Enroll an iSNS client",
				"--enroll hostname"))
		isns_fatal("Cannot parse policy\n");

	/* If no key is given, generate one */
	if (!isns_attr_list_contains(&attrs, OPENISNS_TAG_POLICY_KEY)) {
		printf("No key given, generating one\n");
		isns_attr_list_append_attr(&attrs,
				generate_key_callback());
	}

	status = __create_policy(clnt, &attrs);
	isns_attr_list_destroy(&attrs);
	return status;
}


/*
 * Create a new policy
 */
int
edit_policy(isns_client_t *clnt, int argc, char **argv)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	int		status;

	if (!parse_policy(argc, argv, &attrs,
				"Edit an existing policy",
				"--edit-policy"))
		isns_fatal("Cannot parse policy\n");

	status = __create_policy(clnt, &attrs);
	isns_attr_list_destroy(&attrs);

	return status;
}

#ifdef WITH_SECURITY
static isns_attr_t *
__key_to_attr(EVP_PKEY *pkey)
{
	struct __isns_opaque key;
	isns_value_t	value;
	isns_attr_t	*attr = NULL;

	if (!isns_dsa_encode_public(pkey, &key.ptr, &key.len))
		goto out;

	/* Must pad key. This means we may end up encoding a few
	 * bytes of trash. Oh well. */
	key.len = ISNS_PAD(key.len);

	value = ISNS_VALUE_INIT(opaque, key);
	attr = isns_attr_alloc(OPENISNS_TAG_POLICY_KEY, NULL, &value);

	isns_free(key.ptr);

out:
	EVP_PKEY_free(pkey);
	return attr;
}

isns_attr_t *
generate_key_callback(void)
{
	EVP_PKEY	*pkey;

	if (opt_keyfile == NULL)
		isns_fatal("Key generation requires --keyfile option\n");

	if (!(pkey = isns_dsa_generate_key()))
		isns_fatal("Key generation failed\n");

	if (!isns_dsa_store_private(opt_keyfile, pkey))
		isns_fatal("Unable to write private key to %s\n",
				opt_keyfile);

	printf("Stored DSA private key in %s\n", opt_keyfile);
	return __key_to_attr(pkey);
}

isns_attr_t *
load_key_callback(const char *pathname)
{
	EVP_PKEY	*pkey;

	if (!(pkey = isns_dsa_load_public(pathname)))
		isns_fatal("Unable to load public key from file %s\n", pathname);

	return __key_to_attr(pkey);
}

#else /* WITH_SECURITY */
isns_attr_t *
generate_key_callback(void)
{
	isns_fatal("Authentication disabled in this build\n");
	return NULL;
}

isns_attr_t *
load_key_callback(const char *pathname)
{
	isns_fatal("Authentication disabled in this build\n");
	return NULL;
}

#endif
