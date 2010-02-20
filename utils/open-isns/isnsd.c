/*
 * isnsd - the iSNS Daemon
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#ifdef MTRACE
# include <mcheck.h>
#endif

#include <isns.h>
#include "security.h"
#include "util.h"
#include "paths.h"
#include "internal.h"

enum {
	MODE_NORMAL,
	MODE_DUMP_DB,
	MODE_INIT,
};

static const char *	opt_configfile = ISNS_DEFAULT_ISNSD_CONFIG;
static int		opt_af = AF_UNSPEC;
static int		opt_mode = MODE_NORMAL;
static int		opt_foreground = 0;

static char *		slp_url;

static int		init_server(void);
static void		run_server(isns_server_t *, isns_db_t *);
static void		usage(int, const char *);
static void		cleanup(int);

static struct option	options[] = {
      {	"config",		required_argument,	NULL,	'c'		},
      {	"debug",		required_argument,	NULL,	'd'		},
      { "foreground",		no_argument,		NULL,	'f'		},
      { "init",			no_argument,		NULL,	MODE_INIT	},
      { "dump-db",		no_argument,		NULL,	MODE_DUMP_DB	},
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

	while ((c = getopt_long(argc, argv, "46c:d:fh", options, NULL)) != -1) {
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

		case 'f':
			opt_foreground = 1;
			break;

		case MODE_DUMP_DB:
		case MODE_INIT:
			opt_mode = c;
			break;

		case 'h':
			usage(0, NULL);

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

	isns_read_config(opt_configfile);

	if (!isns_config.ic_source_name)
		usage(1, "Please specify an iSNS source name");
	source = isns_source_create_iscsi(isns_config.ic_source_name);

	if (opt_mode == MODE_INIT)
		return !init_server();

	if (opt_mode == MODE_NORMAL)
		isns_write_pidfile(isns_config.ic_pidfile);

	db = isns_db_open(isns_config.ic_database);
	if (db == NULL)
		isns_fatal("Unable to open database\n");

	if (opt_mode == MODE_DUMP_DB) {
		isns_db_print(db, isns_print_stdout);
		exit(0);
	}

	if (!opt_foreground) {
		if (daemon(0, 0) < 0)
			isns_fatal("Unable to background server process\n");
		isns_log_background();
		isns_update_pidfile(isns_config.ic_pidfile);
	}

	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);

	server = isns_create_server(source, db, &isns_default_service_ops);

	run_server(server, db);
	return 0;
}

void
usage(int exval, const char *msg)
{
	if (msg)
		fprintf(stderr, "Error: %s\n", msg);
	fprintf(stderr,
	"Usage: isnsd [options]\n\n"
	"  --config        Specify alternative config fille\n"
	"  --foreground    Do not put daemon in the background\n"
	"  --debug         Enable debugging (list of debug flags)\n"
	"  --init          Initialize the server (key generation etc)\n"
	"  --dump-db       Display the database contents and exit\n"
	"  --help          Print this message\n"
	);
	exit(exval);
}

void
cleanup(int sig)
{
	isns_remove_pidfile(isns_config.ic_pidfile);
	exit(1);
}

static void
slp_cleanup(void)
{
	char	*url = slp_url;

	slp_url = NULL;
	if (url) {
		isns_slp_unregister(url);
		isns_free(url);
	}
}

/*
 * Initialize server
 */
int
init_server(void)
{
	if (!isns_security_init())
		return 0;

	/* Anything else? */

	return 1;
}

/*
 * Server main loop
 */
void
run_server(isns_server_t *server, isns_db_t *db)
{
	isns_socket_t	*sock;
	isns_security_t	*ctx = NULL;
	isns_message_t	*msg, *resp;
	int status;

	if (isns_config.ic_security) {
		const char	*ksname;
		isns_keystore_t	*ks;

		ctx = isns_default_security_context(1);
		if (!(ksname = isns_config.ic_client_keystore))
			isns_fatal("config problem: no key store specified\n");
		if (!strcasecmp(ksname, "db:"))
			ks = isns_create_db_keystore(db);
		else
			ks = isns_create_keystore(ksname);
		if (ks == NULL)
			isns_fatal("Unable to create keystore %s\n", ksname);
		isns_security_set_keystore(ctx, ks);
	}

	status = isns_dd_load_all(db);
	if (status != ISNS_SUCCESS)
		isns_fatal("Problem loading Discovery Domains from database\n");

	if (isns_config.ic_control_socket) {
		sock = isns_create_server_socket(isns_config.ic_control_socket,
				NULL, AF_UNSPEC, SOCK_STREAM);
		if (sock == NULL)
			isns_fatal("Unable to create control socket\n");
		/*
		isns_socket_set_security_ctx(sock, ctx);
		   */
	}

	sock = isns_create_server_socket(isns_config.ic_bind_address,
			"isns", opt_af, SOCK_STREAM);
	if (sock == NULL)
		isns_fatal("Unable to create server socket\n");
	isns_socket_set_security_ctx(sock, ctx);

	if (isns_config.ic_slp_register) {
		slp_url = isns_slp_build_url(0);
		isns_slp_register(slp_url);

		atexit(slp_cleanup);
	}

	isns_esi_init(server);
	isns_scn_init(server);

	while (1) {
		struct timeval timeout = { 0, 0 };
		time_t	now, then, next_timeout = time(NULL) + 3600;

		/* Expire entities that haven't seen any activity
		 * for a while. */
		if (isns_config.ic_registration_period) {
			then = isns_db_expire(db);
			if (then && then < next_timeout)
				next_timeout = then;
		}

		/* Run any timers (eg for ESI) */
		then = isns_run_timers();
		if (then && then < next_timeout)
			next_timeout = then;

		/* There may be pending SCNs, push them out now */
		then = isns_scn_transmit_all();
		if (then && then < next_timeout)
			next_timeout = then;

		/* Purge any objects that have been marked for removal
		 * from the DB (deleting them, or moving them to limbo
		 * state). */
		isns_db_purge(db);

		/* Determine how long we can sleep before working
		 * the ESI queues and DB expiry again. */
		now = time(NULL);
		if (next_timeout <= now)
			continue;
		timeout.tv_sec = next_timeout - now;

		if ((msg = isns_recv_message(&timeout)) == NULL)
			continue;

		if ((resp = isns_process_message(server, msg)) != NULL) {
			isns_socket_t *sock = isns_message_socket(msg);

			isns_socket_send(sock, resp);
			isns_message_release(resp);
		}

		isns_message_release(msg);
	}
}
