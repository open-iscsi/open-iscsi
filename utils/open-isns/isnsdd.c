/*
 * isnsdd - the iSNS Discovery Daemon
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 *
 * The way isnsdd communicates with local services (initiator,
 * target) is via a set of files and signals. That sounds rather
 * awkward, but it's a lot simpler to add to these services
 * than another socket based communication mechanism I guess.
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef MTRACE
# include <mcheck.h>
#endif

#include <isns.h>
#include "security.h"
#include "util.h"
#include "isns-proto.h"
#include "paths.h"
#include "attrs.h"

enum {
	ROLE_INITIATOR = 1,
	ROLE_MONITOR = 2,
};

#define ISNSDD_REG_NAME		"isns"
#define ISNSDD_PGT_OFFSET	10000
#define MAX_RETRY_TIMEOUT	300

typedef struct isns_proxy isns_proxy_t;
struct isns_proxy {
	isns_list_t		ip_list;
	char *			ip_eid;
	isns_object_t *		ip_entity;
	isns_client_t *		ip_client;
	isns_object_list_t	ip_objects;
	time_t			ip_last_registration;
};

static const char *	opt_configfile = ISNS_DEFAULT_ISNSDD_CONFIG;
static int		opt_af = AF_INET6;
static int		opt_foreground = 0;
static int		opt_role = ROLE_INITIATOR;
static int		opt_scn_bits = ISNS_SCN_OBJECT_UPDATED_MASK |
				ISNS_SCN_OBJECT_ADDED_MASK |
				ISNS_SCN_OBJECT_REMOVED_MASK |
				ISNS_SCN_TARGET_AND_SELF_ONLY_MASK;
static unsigned int	opt_retry_timeout = 10;
static int		opt_esi = 1;

static isns_socket_t *	server_socket;
static ISNS_LIST_DECLARE(proxies);
static isns_object_list_t local_registry = ISNS_OBJECT_LIST_INIT;
static isns_object_list_t local_portals = ISNS_OBJECT_LIST_INIT;
static isns_object_list_t visible_nodes = ISNS_OBJECT_LIST_INIT;
static unsigned int	esi_interval;
static int		should_reexport;

static void		run_discovery(isns_server_t *srv);
static void		scn_callback(isns_db_t *, uint32_t,
				isns_object_template_t *,
				const char *, const char *);
static void		refresh_registration(void *);
static void		retry_registration(void *);
static void		load_exported_objects(void);
static void		store_imported_objects(void);
static void		usage(int, const char *);

static void		install_sighandler(int, void (*func)(int));
static void		sig_cleanup(int);
static void		sig_reread(int);

static struct option	options[] = {
      {	"config",		required_argument,	NULL,	'c'		},
      {	"debug",		required_argument,	NULL,	'd'		},
      { "foreground",		no_argument,		NULL,	'f'		},
      { "role",			required_argument,	NULL,	'r'		},
      { "no-esi",		no_argument,		NULL,	'E'		},
      { "help",			no_argument,		NULL,	'h'		},
      { "version",		no_argument,		NULL,	'V'		},
      { NULL }
};

int
main(int argc, char **argv)
{
	isns_server_t	*server;
	isns_source_t	*source;
	isns_db_t	*db;
	int		c;

#ifdef MTRACE
	mtrace();
#endif

	while ((c = getopt_long(argc, argv, "46c:d:Efhr:", options, NULL)) != -1) {
		switch (c) {
		case '4':
			opt_af = AF_INET;
			break;

		case '6':
			opt_af = AF_INET6;
			break;

		case 'c':
			opt_configfile = optarg;
			break;

		case 'd':
			isns_enable_debugging(optarg);
			break;

		case 'E':
			opt_esi = 0;
			break;

		case 'f':
			opt_foreground = 1;
			break;

		case 'h':
			usage(0, NULL);

		case 'r':
			if (!strcasecmp(optarg, "initiator"))
				opt_role = ROLE_INITIATOR;
			else
			if (!strcasecmp(optarg, "control")
			 || !strcasecmp(optarg, "monitor"))
				opt_role = ROLE_MONITOR;
			else {
				isns_error("Unknown role \"%s\"\n", optarg);
				usage(1, NULL);
			}
			break;

		case 'V':
			printf("Open-iSNS version %s\n"
			       "Copyright (C) 2007, Olaf Kirch <olaf.kirch@oracle.com>\n",
			       OPENISNS_VERSION_STRING);
			return 0;

		default:
			usage(1, "Unknown option");
		}
	}

	if (optind != argc)
		usage(1, NULL);

	/* If the config code derives the source name
	 * automatically, we want it to be distinct from
	 * any other source name (chosen by eg the iSCSI
	 * initiator). Adding a suffix of ":isns" is a
	 * somewhat lame attempt.
	 */
	isns_config.ic_source_suffix = "isns";

	isns_read_config(opt_configfile);

	if (!isns_config.ic_source_name)
		usage(1, "Please specify an iSNS source name");
	source = isns_source_create_iscsi(isns_config.ic_source_name);

	isns_write_pidfile(isns_config.ic_pidfile);

	if (!opt_foreground) {
		if (daemon(0, 0) < 0)
			isns_fatal("Unable to background server process\n");
		isns_log_background();
		isns_update_pidfile(isns_config.ic_pidfile);
	}

	install_sighandler(SIGTERM, sig_cleanup);
	install_sighandler(SIGINT, sig_cleanup);
	install_sighandler(SIGUSR2, sig_reread);

	/* Create a DB object that shadows our portal list. This is for ESI -
	 * when an ESI comes in, the library will look up the portal in this
	 * database, and update its mtime. By checking the mtime at regular
	 * intervals, we can verify whether the server's ESIs actually
	 * reach us.
	 */
	db = isns_db_open_shadow(&local_portals);

	server = isns_create_server(source, db, &isns_callback_service_ops);
	isns_server_set_scn_callback(server, scn_callback);

	run_discovery(server);
	return 0;
}

void
usage(int exval, const char *msg)
{
	if (msg)
		fprintf(stderr, "Error: %s\n", msg);
	fprintf(stderr,
	"Usage: isnsdd [options]\n\n"
	"  --role <role>   Specify role (one of initiator, control)\n"
	"  --config        Specify alternative config fille\n"
	"  --foreground    Do not put daemon in the background\n"
	"  --no-esi        Do not try to register an portals for ESI status inquiries\n"
	"  --debug         Enable debugging (list of debug flags)\n"
	"  --help          Print this message\n"
	);
	exit(exval);
}

void
install_sighandler(int signo, void (*func)(int))
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = func;
	sigaction(signo, &act, NULL);
}

void
sig_reread(int sig)
{
	should_reexport = 1;
}

void
sig_cleanup(int sig)
{
	isns_remove_pidfile(isns_config.ic_pidfile);
	exit(1);
}

/*
 * Proxy handling functions
 */
static isns_proxy_t *
isns_create_proxy(const char *eid)
{
	isns_proxy_t *proxy;

	proxy = calloc(1, sizeof(*proxy));
	isns_list_init(&proxy->ip_list);
	proxy->ip_eid = strdup(eid);
	return proxy;
}

static isns_proxy_t *
__isns_proxy_find(isns_list_t *head, const char *eid)
{
	isns_list_t	*pos, *next;

	isns_list_foreach(head, pos, next) {
		isns_proxy_t *proxy = isns_list_item(isns_proxy_t, ip_list, pos);

		if (!strcmp(proxy->ip_eid, eid))
			return proxy;
	}
	return NULL;
}

static isns_proxy_t *
isns_proxy_by_entity(const isns_object_t *entity)
{
	isns_list_t	*pos, *next;

	isns_list_foreach(&proxies, pos, next) {
		isns_proxy_t *proxy = isns_list_item(isns_proxy_t, ip_list, pos);

		if (proxy->ip_entity == entity)
			return proxy;
	}
	return NULL;
}

static void
isns_proxy_erase(isns_proxy_t *proxy)
{
	isns_object_list_destroy(&proxy->ip_objects);
	if (proxy->ip_client) {
		isns_client_destroy(proxy->ip_client);
		proxy->ip_client = NULL;
	}
	if (proxy->ip_entity) {
		isns_object_release(proxy->ip_entity);
		proxy->ip_entity = NULL;
	}
	isns_cancel_timer(refresh_registration, proxy);
}

static void
isns_proxy_free(isns_proxy_t *proxy)
{
	isns_proxy_erase(proxy);
	isns_list_del(&proxy->ip_list);
	free(&proxy->ip_eid);
	free(proxy);
}

/*
 * Force a re-registration of the whole object set.
 */
static void
force_reregistration(isns_proxy_t *proxy)
{
	isns_cancel_timer(refresh_registration, proxy);
	isns_add_oneshot_timer(0, retry_registration, proxy);
}

/*
 * Refresh the registration by calling DevAttrQry
 */
static void
refresh_registration(void *ptr)
{
	isns_proxy_t	*proxy = ptr;
	isns_client_t	*clnt = proxy->ip_client;
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	isns_attr_list_t query_key = ISNS_ATTR_LIST_INIT;
	isns_simple_t	*qry = NULL;
	uint32_t	status;

	isns_debug_state("Refreshing registration for %s\n", proxy->ip_eid);
	isns_attr_list_append_string(&query_key,
			ISNS_TAG_ENTITY_IDENTIFIER,
			proxy->ip_eid);

	qry = isns_create_query(clnt, &query_key);
	isns_attr_list_destroy(&query_key);

	/* We should have an async call mechanism. If the server
	 * is wedged, we'll block here, unable to service any other
	 * functions.
	 */
	status = isns_simple_call(clnt->ic_socket, &qry);
	if (status != ISNS_SUCCESS) {
		isns_error("Query failed: %s\n", isns_strerror(status));
		goto re_register;
	}

	status = isns_query_response_get_objects(qry, &objects);
	isns_simple_free(qry);

	if (status == ISNS_SUCCESS) {
		if (objects.iol_count != 0)
			return;
	} else {
		isns_error("Unable to parse query response\n");
	}

re_register:
	isns_warning("Lost registration, trying to re-register\n");
	force_reregistration(proxy);
}

/*
 * Check if all portals have seen ESI messages from the server
 */
static void
check_portal_registration(void *ptr)
{
	isns_object_list_t bad_portals = ISNS_OBJECT_LIST_INIT;
	unsigned int	i, need_reregister = 0, good_portals = 0;
	time_t		now;

	isns_debug_state("%s()\n", __FUNCTION__);
	now = time(NULL);
	for (i = 0; i < local_portals.iol_count; ++i) {
		isns_object_t *obj = local_portals.iol_data[i];
		isns_portal_info_t portal_info;
		isns_proxy_t	*proxy;
		time_t		last_modified;
		uint32_t	interval;

		if (!isns_object_get_uint32(obj, ISNS_TAG_ESI_INTERVAL, &interval))
			continue;

		last_modified = isns_object_last_modified(obj);
		if (last_modified + 2 * interval > now) {
			good_portals++;
			continue;
		}

		isns_portal_from_object(&portal_info,
				ISNS_TAG_PORTAL_IP_ADDRESS,
				ISNS_TAG_PORTAL_TCP_UDP_PORT,
				obj);

		isns_notice("Portal %s did not receive ESIs within %u seconds - "
			"server may have lost us.\n",
			isns_portal_string(&portal_info),
			now - last_modified);

		proxy = isns_proxy_by_entity(isns_object_get_entity(obj));
		if (!proxy)
			continue;

		/* If we haven't received ANY ESIs, ever, the portal
		 * may be using a non-routable IP */
		if (last_modified <= proxy->ip_last_registration)
			isns_object_list_append(&bad_portals, obj);

		force_reregistration(proxy);
		need_reregister++;
	}

	for (i = 0; i < bad_portals.iol_count; ++i)
		isns_object_list_remove(&local_portals, bad_portals.iol_data[i]);
	isns_object_list_destroy(&bad_portals);

	if (need_reregister && local_portals.iol_count == 0) {
		/* Force a re-registration from scratch.
		 * This time without ESI.
		 */
		isns_notice("Suspiciously little ESI traffic - server may be broken\n");
		isns_notice("Disabling ESI\n");
		opt_esi = 0;
	}
}

static void
setup_esi_watchdog(void)
{
	unsigned int	i;

	isns_cancel_timer(check_portal_registration, NULL);
	esi_interval = 0;

	for (i = 0; i < local_portals.iol_count; ++i) {
		isns_object_t	*obj = local_portals.iol_data[i];
		uint32_t	interval;

		/* should always succeed */
		if (isns_object_get_uint32(obj, ISNS_TAG_ESI_INTERVAL, &interval))
			continue;

		if (!esi_interval || interval < esi_interval)
			esi_interval = interval;
	}

	if (esi_interval) {
		isns_debug_state("Setting up timer to check for ESI reachability\n");
		isns_add_timer(esi_interval * 4 / 5,
				check_portal_registration,
				NULL);
	}
}

static void
load_exported_objects(void)
{
	isns_debug_state("Reading list of exported objects\n");
	isns_object_list_destroy(&local_registry);
	if (!isns_local_registry_load("!" ISNSDD_REG_NAME, 0, &local_registry)) {
		isns_warning("Unable to obtain locally registered objects\n");
		return;
	}
}

static void
store_imported_objects(void)
{
	if (!isns_local_registry_store(ISNSDD_REG_NAME, 0, &visible_nodes))
		isns_warning("Unable to store discovered objects\n");
}

/*
 * Given the DevAttrReg response, extract the entity ID we
 * have been assigned.
 */
static int
extract_entity_id(isns_proxy_t *proxy, isns_simple_t *resp)
{
	isns_object_list_t resp_objects = ISNS_OBJECT_LIST_INIT;
	isns_object_t	*entity = NULL;
	int		status;
	unsigned int	i;

	status = isns_query_response_get_objects(resp, &resp_objects);
	if (status) {
		isns_error("Unable to extract object list from "
			   "registration response: %s\n",
			   isns_strerror(status), status);
		goto out;
	}

	for (i = 0; i < resp_objects.iol_count; ++i) {
		isns_object_t	*obj = resp_objects.iol_data[i];
		uint32_t	interval;

		if (!isns_object_is_entity(obj))
			continue;

		if (entity) {
			isns_error("Server returns more than one entity "
				   "in registration response. What a weirdo.\n");
			continue;
		}
		entity = obj;

		if (!isns_object_get_uint32(obj,
					ISNS_TAG_REGISTRATION_PERIOD,
					&interval))
			continue;

		if (interval == 0) {
			isns_error("Server returns a registration period of 0\n");
			continue;
		}

		isns_debug_state("Setting up timer for registration refresh\n");
		isns_add_timer(interval / 2,
				refresh_registration,
				proxy);
	}

	for (i = 0; i < resp_objects.iol_count; ++i) {
		isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
		isns_object_t	*obj = resp_objects.iol_data[i];
		uint32_t	interval;

		if (!isns_object_is_portal(obj)
		 || !isns_object_get_uint32(obj, ISNS_TAG_ESI_INTERVAL, &interval))
			continue;
		 
		if (interval == 0) {
			isns_error("Server returns an ESI interval of 0\n");
			continue;
		}

		isns_object_get_key_attrs(obj, &key_attrs);
		if (!(obj = isns_object_list_lookup(&proxy->ip_objects, NULL, &key_attrs))) {
			isns_error("Server response includes a portal we never registered\n");
			continue;
		}

		isns_object_set_uint32(obj, ISNS_TAG_ESI_INTERVAL, interval);

		/* Server enabled ESI for this portal, so add it to
		 * the list of local portals we regularly check for
		 * incoming ESI messages. */
		isns_object_list_append(&local_portals, obj);
	}

	proxy->ip_last_registration = time(NULL);
out:
	isns_object_list_destroy(&resp_objects);
	return status;
}

static inline void
__add_release_object(isns_object_list_t *objects, isns_object_t *cur)
{
	if (cur == NULL)
		return;
	isns_object_list_append(objects, cur);
	isns_object_release(cur);
}

/*
 * Rebuild the list of proxies given the set of entities
 */
void
rebuild_proxy_list(isns_object_list_t *entities, isns_list_t *old_list)
{
	isns_proxy_t	*proxy;
	unsigned int	i;

	isns_list_move(old_list, &proxies);

	for (i = 0; i < entities->iol_count; ++i) {
		isns_object_t	*entity = entities->iol_data[i];
		isns_object_t	*node;
		const char	*eid;

		eid = isns_entity_name(entity);
		if (eid == NULL) {
			isns_error("Whoopee, entity without name\n");
			continue;
		}

		proxy = __isns_proxy_find(old_list, eid);
		if (proxy == NULL) {
			proxy = isns_create_proxy(eid);
		} else {
			isns_proxy_erase(proxy);
		}

		isns_object_list_append(&proxy->ip_objects, entity);
		isns_object_get_descendants(entity, NULL, &proxy->ip_objects);

		node = isns_object_list_lookup(&proxy->ip_objects,
				&isns_iscsi_node_template,
				NULL);
		if (node == NULL) {
			isns_warning("Service %s did not register any "
				     "storage nodes - skipped\n", eid);
			continue;
		}

		proxy->ip_client = isns_create_client(NULL,
				isns_storage_node_name(node));
		proxy->ip_entity = isns_object_get(entity);

		isns_list_del(&proxy->ip_list);
		isns_list_append(&proxies, &proxy->ip_list);
	}
}

/*
 * Unregister old proxies
 */
static void
unregister_entities(isns_list_t *list)
{
	while (!isns_list_empty(list)) {
		isns_proxy_t *proxy = isns_list_item(isns_proxy_t, ip_list, list->next);

		/* XXX send a DevDereg */
		isns_proxy_free(proxy);
	}
}

/*
 * The local registry creates fake entities to group objects
 * registered by the same service. We use this to perform
 * several registration calls, each with a different EID
 */
static int
register_entity(isns_proxy_t *proxy)
{
	isns_client_t	*clnt = proxy->ip_client;
	isns_simple_t	*call = NULL;
	int		status;

	call = isns_create_registration(clnt, proxy->ip_entity);
	isns_registration_set_replace(call, 1);
	isns_registration_add_object_list(call, &proxy->ip_objects);

	status = isns_simple_call(clnt->ic_socket, &call);
	if (status == ISNS_SUCCESS) {
		/* Extract the EID and registration period */
		extract_entity_id(proxy, call);
	}

	isns_simple_free(call);
	return status;
}

static int
register_exported_entities(void)
{
	int		status = ISNS_SUCCESS;
	isns_list_t	*pos, *next;

	isns_list_foreach(&proxies, pos, next) {
		isns_proxy_t *proxy = isns_list_item(isns_proxy_t, ip_list, pos);

		status = register_entity(proxy);
		if (status != ISNS_SUCCESS)
			break;
	}

	setup_esi_watchdog();
	return status;
}

static void
all_objects_set(isns_object_list_t *list, uint32_t tag, uint32_t value)
{
	unsigned int	i;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t *obj = list->iol_data[i];

		isns_object_set_uint32(obj, tag, value);
	}
}

static void
all_objects_unset(isns_object_list_t *list, uint32_t tag)
{
	unsigned int	i;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t *obj = list->iol_data[i];

		isns_object_delete_attr(obj, tag);
	}
}

static int
register_exported_objects(isns_client_t *clnt)
{
	isns_portal_info_t portal_info;
	isns_object_list_t entities = ISNS_OBJECT_LIST_INIT;
	isns_object_list_t portals = ISNS_OBJECT_LIST_INIT;
	isns_simple_t	*call = NULL;
	int		status, with_esi;
	unsigned int	i, my_port;
	isns_list_t	old_proxies;

	if (!isns_socket_get_portal_info(server_socket, &portal_info))
		isns_fatal("Unable to get portal info\n");
	my_port = isns_portal_tcpudp_port(&portal_info);

	/* Look up all entites and portals */
	isns_object_list_gang_lookup(&local_registry,
			&isns_entity_template, NULL,
			&entities);
	isns_object_list_gang_lookup(&local_registry,
			&isns_portal_template, NULL,
			&portals);

	isns_list_init(&old_proxies);
	rebuild_proxy_list(&entities, &old_proxies);
	unregister_entities(&old_proxies);

	/* Enable SCN on all portals we're about to register */
	all_objects_set(&portals, ISNS_TAG_SCN_PORT, my_port);

	/* Try ESI first. If the server doesn't support it, or doesn't
	 * have the resources to serve us, fall back to normal
	 * registration refresh. */
	if (opt_esi) {
		all_objects_set(&portals,
				ISNS_TAG_ESI_INTERVAL,
				isns_config.ic_esi_min_interval);
		all_objects_set(&portals,
				ISNS_TAG_ESI_PORT,
				my_port);
	}

	for (with_esi = opt_esi; 1; with_esi--) {
		status = register_exported_entities();

		/* At some point, we need to add these portals
		 * to the local_portals list so that ESI works
		 * properly.
		 * Right now, we extract the portals from the response
		 * and add those. The down side of this is that we no
		 * longer use the same object (pointer) to refer to the
		 * same thing. The up side is that the information returned
		 * by the server reflects the correct ESI interval.
		 */
		if (status == ISNS_SUCCESS)
			break;

		if (status != ISNS_ESI_NOT_AVAILABLE || with_esi == 0) {
			isns_error("Failed to register object(s): %s\n",
					isns_strerror(status));
			goto out;
		}

		/* Continue and retry without ESI */
		all_objects_unset(&portals, ISNS_TAG_ESI_INTERVAL);
		all_objects_unset(&portals, ISNS_TAG_ESI_PORT);
	}

	for (i = 0; i < local_registry.iol_count; ++i) {
		isns_object_t *obj = local_registry.iol_data[i];
		isns_source_t *source;
		int	status;

		if (!isns_object_is_iscsi_node(obj)
		 && !isns_object_is_fc_port(obj))
			continue;

		if (!(source = isns_source_from_object(obj)))
			continue;
		call = isns_create_scn_registration2(clnt, opt_scn_bits, source);
		status = isns_simple_call(clnt->ic_socket, &call);
		if (status != ISNS_SUCCESS) {
			isns_error("SCN registration for %s failed: %s\n",
					isns_storage_node_name(obj),
					isns_strerror(status));
		}
		isns_source_release(source);
	}

out:
	if (call)
		isns_simple_free(call);
	isns_object_list_destroy(&entities);
	isns_object_list_destroy(&portals);
	return status;
}

static void
retry_registration(void *ptr)
{
	isns_proxy_t *proxy = ptr;
	static unsigned int timeout = 0;
	int	status;

	status = register_exported_objects(proxy->ip_client);
	if (status) {
		if (timeout == 0)
			timeout = opt_retry_timeout;
		else if (timeout >= MAX_RETRY_TIMEOUT)
			timeout = MAX_RETRY_TIMEOUT;

		isns_debug_state("Retrying to register in %u seconds\n", timeout);
		isns_add_oneshot_timer(timeout, retry_registration, proxy);

		/* Exponential backoff */
		timeout <<= 1;
	}
}

/*
 * Get a list of all visible storage nodes
 */
static int
get_objects_from_query(isns_simple_t *resp)
{
	isns_object_list_t resp_objects = ISNS_OBJECT_LIST_INIT;
	unsigned int	i;
	int		status;

	status = isns_query_response_get_objects(resp, &resp_objects);
	if (status) {
		isns_error("Unable to extract object list from "
			   "query response: %s\n",
			   isns_strerror(status));
		return status;
	}

	isns_debug_state("Initial query returned %u object(s)\n", resp_objects.iol_count);
	for (i = 0; i < resp_objects.iol_count; ++i) {
		isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
		isns_object_t	*obj = resp_objects.iol_data[i];
		isns_object_t	*found;

		if (!isns_object_extract_keys(obj, &key_attrs))
			continue;

		/* Don't add an object twice, and don't add objects
		 * that *we* registered.
		 * This still leaves any default PGs created by the server,
		 * but we cannot help that (for now).
		 */
		found = isns_object_list_lookup(&visible_nodes, NULL, &key_attrs);
		if (!found)
			found = isns_object_list_lookup(&local_registry, NULL, &key_attrs);
		if (found) {
			isns_object_release(found);
		} else {
			isns_object_list_append(&visible_nodes, obj);
		}
		isns_attr_list_destroy(&key_attrs);
	}

	isns_object_list_destroy(&resp_objects);
	return status;
}

static int
query_storage_node(isns_source_t *source, const char *name)
{
	isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
	isns_simple_t	*call;
	uint32_t	tag;
	int		status;
	isns_client_t	*clnt;

	if (isns_source_type(source) != ISNS_TAG_ISCSI_NAME) {
		isns_error("FC source node - doesn't work yet\n");
		return ISNS_SUCCESS;
	}
	clnt = isns_create_client(NULL, isns_source_name(source));

	tag = isns_source_type(source);
	if (name) {
		isns_attr_list_append_string(&key_attrs, tag, name);
	} else {
		/* Query for visible nodes */
		isns_attr_list_append_nil(&key_attrs, tag);
	}

	call = isns_create_query2(clnt, &key_attrs, source);
	isns_attr_list_destroy(&key_attrs);

	isns_query_request_attr_tag(call, tag);
	switch (tag) {
	case ISNS_TAG_ISCSI_NAME:
		isns_query_request_attr_tag(call, ISNS_TAG_ISCSI_NODE_TYPE);
		isns_query_request_attr_tag(call, ISNS_TAG_ISCSI_ALIAS);
		isns_query_request_attr_tag(call, ISNS_TAG_ISCSI_NODE_INDEX);

		isns_query_request_attr_tag(call, ISNS_TAG_PORTAL_IP_ADDRESS);
		isns_query_request_attr_tag(call, ISNS_TAG_PORTAL_TCP_UDP_PORT);
		isns_query_request_attr_tag(call, ISNS_TAG_PORTAL_INDEX);

		isns_query_request_attr_tag(call, ISNS_TAG_PG_ISCSI_NAME);
		isns_query_request_attr_tag(call, ISNS_TAG_PG_PORTAL_IP_ADDR);
		isns_query_request_attr_tag(call, ISNS_TAG_PG_PORTAL_TCP_UDP_PORT);
		isns_query_request_attr_tag(call, ISNS_TAG_PG_TAG);
		isns_query_request_attr_tag(call, ISNS_TAG_PG_INDEX);
		break;

	default: ;
	}

	status = isns_simple_call(clnt->ic_socket, &call);
	if (status == ISNS_SUCCESS)
		status = get_objects_from_query(call);

	isns_simple_free(call);
	isns_client_destroy(clnt);
	return status;
}

/*
 * Query for visible iscsi nodes
 */
static int
query_visible(void)
{
	unsigned int i;

	for (i = 0; i < local_registry.iol_count; ++i) {
		isns_object_t	*obj = local_registry.iol_data[i];
		isns_source_t	*source;
		int		status;

		if (!isns_object_is_iscsi_node(obj)
		 && !isns_object_is_fc_port(obj))
			continue;

		if (isns_object_is_fc_port(obj)) {
			isns_error("FC source node - sorry, won't work yet\n");
			continue;
		}

		if (!(source = isns_source_from_object(obj)))
			continue;
		status = query_storage_node(source, NULL);
		if (status != ISNS_SUCCESS) {
			isns_warning("Unable to run query on behalf of %s: %s\n",
					isns_storage_node_name(obj),
					isns_strerror(status));
		}
		isns_source_release(source);
	}
	return ISNS_SUCCESS;
}

/*
 * Invoke the registered callout program
 */
static void
callout(const char *how, isns_object_t *obj, unsigned int bitmap)
{
	char	*argv[128];
	int	fargc, argc = 0;
	pid_t	pid;

	if (!isns_config.ic_scn_callout)
		return;

	argv[argc++] = isns_config.ic_scn_callout;
	argv[argc++] = (char *) how;
	fargc = argc;

	argc += isns_print_attrs(obj, argv + argc, 128 - argc);

	pid = fork();
	if (pid == 0) {
		execv(argv[0], argv);
		isns_fatal("Cannot execute %s: %m\n", argv[0]);
	}

	while (fargc < argc)
		isns_free(argv[fargc++]);

	if (pid < 0) {
		isns_error("fork: %m\n");
		return;
	}

	while (waitpid(pid, NULL, 0) < 0)
		;
}

/*
 * This is called when we receive a State Change Notification
 */
static void
scn_callback(isns_db_t *db, uint32_t bitmap,
		isns_object_template_t *node_type,
		const char *node_name,
		const char *dst_name)
{
	isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
	uint32_t	key_tag;
	isns_object_t	*node = NULL, *recipient = NULL;

	isns_notice("%s \"%s\" %s\n",
			isns_object_template_name(node_type),
			node_name, isns_event_string(bitmap));

	/* This is either an iSCSI node or a FC node - in
	   both cases the storage node name is the key attr */
	if (node_type == &isns_iscsi_node_template) {
		key_tag = ISNS_TAG_ISCSI_NAME;
	} else if (node_type == &isns_fc_node_template) {
		key_tag = ISNS_TAG_FC_PORT_NAME_WWPN;
	} else
		return;

	isns_attr_list_append_string(&key_attrs, key_tag, dst_name);
	recipient = isns_object_list_lookup(&local_registry, node_type, &key_attrs);
	if (recipient == NULL) {
		isns_error("Received SCN for unknown recipient \"%s\"\n",
				dst_name);
		goto out;
	}
	isns_attr_list_destroy(&key_attrs);

	isns_attr_list_append_string(&key_attrs, key_tag, node_name);
	node = isns_object_list_lookup(&visible_nodes, node_type, &key_attrs);

	if (bitmap & (ISNS_SCN_OBJECT_REMOVED_MASK|ISNS_SCN_DD_MEMBER_REMOVED_MASK)) {
		if (node) {
			isns_object_list_remove(&visible_nodes, node);
			/* FIXME: We also want to remove any PGs associated with
			 * this node. */
		}
		store_imported_objects();
		callout("remove", node, bitmap);
	} else
	if (bitmap & (ISNS_SCN_OBJECT_ADDED_MASK|ISNS_SCN_OBJECT_UPDATED_MASK|ISNS_SCN_DD_MEMBER_ADDED_MASK)) {
		const char	*how = "add";
		isns_source_t	*source;

		if (bitmap & ISNS_SCN_OBJECT_UPDATED_MASK)
			how = "update";
		if (!node) {
			node = isns_create_object(node_type, &key_attrs, NULL);
			if (!node)
				goto out;
			isns_object_list_append(&visible_nodes, node);
		}

		/* Query the server for information on this node */
		source = isns_source_from_object(recipient);
		query_storage_node(source, node_name);
		isns_source_release(source);

		store_imported_objects();
		callout(how, node, bitmap);

	}

out:
	if (node)
		isns_object_release(node);
	if (recipient)
		isns_object_release(recipient);
	isns_attr_list_destroy(&key_attrs);
}

/*
 * Server main loop
 */
void
run_discovery(isns_server_t *server)
{
	isns_client_t	*clnt;
	isns_security_t	*ctx = NULL;
	isns_message_t	*msg, *resp;

	/* Create the server socket */
	ctx = isns_default_security_context(0);
	server_socket = isns_create_server_socket(isns_config.ic_bind_address,
			NULL, opt_af, SOCK_DGRAM);
	if (server_socket == NULL)
		isns_fatal("Unable to create server socket\n");
	isns_socket_set_security_ctx(server_socket, ctx);

	/* Create the client socket */
	clnt = isns_create_default_client(NULL);
	if (clnt == NULL)
		isns_fatal("Cannot connect to server\n");

	/* Load all objects registered by local services */
	should_reexport = 1;

	while (1) {
		struct timeval timeout = { 0, 0 };
		time_t	now, then, next_timeout;
		unsigned int function;

		next_timeout = time(NULL) + 3600;

		/* Run timers */
		then = isns_run_timers();
		if (then && then < next_timeout)
			next_timeout = then;

		/* Determine how long we can sleep */
		now = time(NULL);
		if (next_timeout <= now)
			continue;
		timeout.tv_sec = next_timeout - now;

		if (should_reexport) {
			load_exported_objects();

			if (register_exported_objects(clnt))
				isns_error("Failed to register exported objects.\n");

			/* Prime the list of visible storage nodes */
			if (query_visible())
				isns_error("Unable to query list of visible nodes.\n");
			store_imported_objects();

			should_reexport = 0;
		}

		if ((msg = isns_recv_message(&timeout)) == NULL)
			continue;

		function = isns_message_function(msg);
		if (function != ISNS_STATE_CHANGE_NOTIFICATION
		 && function != ISNS_ENTITY_STATUS_INQUIRY) {
			isns_warning("Discarding unexpected %s message\n",
					isns_function_name(function));
			isns_message_release(msg);
			continue;
		}

		if ((resp = isns_process_message(server, msg)) != NULL) {
			isns_socket_t *sock = isns_message_socket(msg);

			isns_socket_send(sock, resp);
			isns_message_release(resp);
		}

		isns_message_release(msg);
	}
}
