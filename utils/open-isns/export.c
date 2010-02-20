/*
 * Helper functions to represent iSNS objects as text,
 * and/or to parse objects represented in textual form.
 * These functions can be used by command line utilities
 * such as isnsadm, as well as applications like iscsid
 * or stgtd when talking to the iSNS discovery daemon.
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "isns.h"
#include "util.h"
#include "vendor.h"
#include "attrs.h"
#include "security.h"
#include "objects.h"
#include "paths.h"

#define MAX_ALIASES		4

struct isns_tag_prefix {
	const char *		name;
	unsigned int		name_len;
	isns_object_template_t *context;
};

struct tag_name {
	const char *		name;
	uint32_t		tag;
	struct isns_tag_prefix *prefix;
	const char *		alias[MAX_ALIASES];
};

static struct isns_tag_prefix all_prefixes[__ISNS_OBJECT_TYPE_MAX] = {
[ISNS_OBJECT_TYPE_ENTITY] = { "entity-", 7, &isns_entity_template	},
[ISNS_OBJECT_TYPE_NODE]   = { "iscsi-",	 6, &isns_iscsi_node_template	},
[ISNS_OBJECT_TYPE_PORTAL] = { "portal-", 7, &isns_portal_template	},
[ISNS_OBJECT_TYPE_PG]     = { "pg-",	 3, &isns_iscsi_pg_template	},
[ISNS_OBJECT_TYPE_DD]     = { "dd-",	 3, &isns_dd_template		},
[ISNS_OBJECT_TYPE_POLICY] = { "policy-", 7, &isns_policy_template	},
};

static struct tag_name	all_attrs[] = {
{ "id",			ISNS_TAG_ENTITY_IDENTIFIER,
			.alias = { "eid", },
},
{ "prot",		ISNS_TAG_ENTITY_PROTOCOL },
{ "idx",		ISNS_TAG_ENTITY_INDEX },

{ "name",		ISNS_TAG_ISCSI_NAME },
{ "node-type",		ISNS_TAG_ISCSI_NODE_TYPE },
{ "alias",		ISNS_TAG_ISCSI_ALIAS },
{ "authmethod",		ISNS_TAG_ISCSI_AUTHMETHOD },
{ "idx",		ISNS_TAG_ISCSI_NODE_INDEX },

{ "addr",		ISNS_TAG_PORTAL_IP_ADDRESS },
{ "port",		ISNS_TAG_PORTAL_TCP_UDP_PORT },
{ "name",		ISNS_TAG_PORTAL_SYMBOLIC_NAME },
{ "esi-port",		ISNS_TAG_ESI_PORT },
{ "esi-interval",	ISNS_TAG_ESI_INTERVAL },
{ "scn-port",		ISNS_TAG_SCN_PORT },
{ "idx",		ISNS_TAG_PORTAL_INDEX },

{ "name",		ISNS_TAG_PG_ISCSI_NAME },
{ "addr",		ISNS_TAG_PG_PORTAL_IP_ADDR },
{ "port",		ISNS_TAG_PG_PORTAL_TCP_UDP_PORT },
{ "tag",		ISNS_TAG_PG_TAG },
{ "pgt",		ISNS_TAG_PG_TAG },
{ "idx",		ISNS_TAG_PG_INDEX },

{ "id",			ISNS_TAG_DD_ID },
{ "name",		ISNS_TAG_DD_SYMBOLIC_NAME },
{ "member-name",	ISNS_TAG_DD_MEMBER_ISCSI_NAME },
{ "member-iscsi-idx",	ISNS_TAG_DD_MEMBER_ISCSI_INDEX },
{ "member-fc-name",	ISNS_TAG_DD_MEMBER_FC_PORT_NAME },
{ "member-portal-idx",	ISNS_TAG_DD_MEMBER_PORTAL_INDEX },
{ "member-addr",	ISNS_TAG_DD_MEMBER_PORTAL_IP_ADDR  },
{ "member-port",	ISNS_TAG_DD_MEMBER_PORTAL_TCP_UDP_PORT  },
{ "features",		ISNS_TAG_DD_FEATURES },

{ "name",		OPENISNS_TAG_POLICY_SPI,
			.alias = { "spi" },
},
{ "key",		OPENISNS_TAG_POLICY_KEY },
{ "entity",		OPENISNS_TAG_POLICY_ENTITY },
{ "object-type",	OPENISNS_TAG_POLICY_OBJECT_TYPE },
{ "node-type",		OPENISNS_TAG_POLICY_NODE_TYPE },
{ "node-name",		OPENISNS_TAG_POLICY_NODE_NAME },
{ "functions",		OPENISNS_TAG_POLICY_FUNCTIONS },

{ NULL }
};

/*
 * Initialize tag array
 */
static void
init_tags(void)
{
	struct tag_name	*t;

	for (t = all_attrs; t->name; ++t) {
		isns_object_template_t *tmpl;

		tmpl = isns_object_template_for_tag(t->tag);
		if (tmpl == NULL)
			isns_fatal("Bug: cannot find object type for tag %s\n",
					t->name);
		t->prefix = &all_prefixes[tmpl->iot_handle];
	}
}

/*
 * Match prefix
 */
static struct isns_tag_prefix *
find_prefix(const char *name)
{
	struct isns_tag_prefix *p;
	unsigned int	i;

	for (i = 0, p = all_prefixes; i < __ISNS_OBJECT_TYPE_MAX; ++i, ++p) {
		if (p->name && !strncmp(name, p->name, p->name_len))
			return p;
	}
	return NULL;
}

/*
 * Look up the tag for a given attribute name.
 * By default, attr names come with a disambiguating
 * prefix that defines the object type the attribute applies
 * to, such as "entity-" or "portal-". Once a context has
 * been established (ie we know the object type subsequent
 * attributes apply to), specifying the prefix is optional.
 *
 * For instance, in a portal context, "addr=10.1.1.1 port=616 name=foo"
 * specifies three portal related attributes. Whereas in a portal
 * group context, the same string would specify three portal group
 * related attributes. To disambiguate, the first attribute in
 * this list should be prefixed by "portal-" or "pg-", respectively.
 */
static uint32_t
tag_by_name(const char *name, struct isns_attr_list_parser *st)
{
	const char	*orig_name = name;
	unsigned int	nmatch = 0, i;
	struct tag_name	*t, *match[8];
	struct isns_tag_prefix *specific = NULL;

	if (all_attrs[0].prefix == NULL)
		init_tags();

	specific = find_prefix(name);
	if (specific != NULL) {
		if (st->prefix
		 && st->prefix != specific
		 && !st->multi_type_permitted) {
			isns_error("Cannot mix attributes of different types\n");
			return 0;
		}
		name += specific->name_len;
		st->prefix = specific;
	}

	for (t = all_attrs; t->name; ++t) {
		if (specific && t->prefix != specific)
			continue;
		if (!st->multi_type_permitted
		 && st->prefix && t->prefix != st->prefix)
			continue;
		if (!strcmp(name, t->name))
			goto match;
		for (i = 0; i < MAX_ALIASES && t->alias[i]; ++i) {
			if (!strcmp(name, t->alias[i]))
				goto match;
		}
		continue;

match:
		if (nmatch < 8)
			match[nmatch++] = t;
	}

	if (nmatch > 1) {
		char		conflict[128];
		unsigned int	i;

		conflict[0] = '\0';
		for (i = 0; i < nmatch; ++i) {
			if (i)
				strcat(conflict, ", ");
			t = match[i];
			strcat(conflict, t->prefix->name);
			strcat(conflict, t->name);
		}
		isns_error("tag name \"%s\" not unique in this context "
				"(could be one of %s)\n",
				orig_name, conflict);
		return 0;
	}

	if (nmatch == 0) {
		isns_error("tag name \"%s\" not known in this context\n",
				orig_name);
		return 0;
	}

	st->prefix = match[0]->prefix;
	return match[0]->tag;
}

static const char *
name_by_tag(uint32_t tag, struct isns_attr_list_parser *st)
{
	struct tag_name *t;

	for (t = all_attrs; t->name; ++t) {
		if (st->prefix && t->prefix != st->prefix)
			continue;
		if (t->tag == tag)
			return t->name;
	}
	return NULL;
}

static int
parse_one_attr(const char *name, const char *value,
		isns_attr_list_t *attrs,
		struct isns_attr_list_parser *st)
{
	isns_attr_t	*attr;
	uint32_t	tag;

	/* Special case: "portal=<address:port>" is translated to
	 * addr=<address> port=<port>
	 * If no context has been set, assume portal context.
	 */
	if (!strcasecmp(name, "portal")) {
		isns_portal_info_t portal_info;
		uint32_t	addr_tag, port_tag;

		if (st->prefix == NULL) {
			addr_tag = tag_by_name("portal-addr", st);
			port_tag = tag_by_name("portal-port", st);
		} else {
			addr_tag = tag_by_name("addr", st);
			port_tag = tag_by_name("port", st);
		}

		if (!addr_tag || !port_tag) {
			isns_error("portal=... not supported in this context\n");
			return 0;
		}
		if (value == NULL) {
			isns_attr_list_append_nil(attrs, addr_tag);
			isns_attr_list_append_nil(attrs, port_tag);
			return 1;
		}
		if (!isns_portal_parse(&portal_info, value, st->default_port))
			return 0;
		isns_portal_to_attr_list(&portal_info, addr_tag, port_tag, attrs);
		return 1;
	}

	if (!(tag = tag_by_name(name, st)))
		return 0;

	/* Special handling for key objects */
	if (tag == OPENISNS_TAG_POLICY_KEY) {
		if (!value || !strcasecmp(value, "gen")) {
			if (st->generate_key == NULL) {
				isns_error("Key generation not supported in this context\n");
				return 0;
			}
			attr = st->generate_key();
		} else {
			if (st->load_key == NULL) {
				isns_error("Policy-key attribute not supported in this context\n");
				return 0;
			}
			attr = st->load_key(value);
		}
		goto append_attr;
	}

	if (value == NULL) {
		isns_attr_list_append_nil(attrs, tag);
		return 1;
	}

	attr = isns_attr_from_string(tag, value);
	if (!attr)
		return 0;

append_attr:
	isns_attr_list_append_attr(attrs, attr);
	return 1;
}

void
isns_attr_list_parser_init(struct isns_attr_list_parser *st,
				isns_object_template_t *tmpl)
{
	if (all_attrs[0].prefix == NULL)
		init_tags();

	memset(st, 0, sizeof(*st));
	if (tmpl)
		st->prefix = &all_prefixes[tmpl->iot_handle];
}

int
isns_attr_list_split(char *line, char **argv, unsigned int argc_max)
{
	char		*src = line;
	unsigned int	argc = 0, quoted = 0;

	if (!line)
		return 0;

	while (1) {
		char	*dst;

		while (isspace(*src))
			++src;
		if (!*src)
			break;

		argv[argc] = dst = src;
		while (*src) {
			char cc = *src++;

			if (cc == '"') {
				quoted = !quoted;
				continue;
			}
			if (!quoted && isspace(cc)) {
				*dst = '\0';
				break;
			}
			*dst++ = cc;
		}

		if (quoted) {
			isns_error("%s: Unterminated quoted string: \"%s\"\n",
					__FUNCTION__, argv[argc]);
			return -1;
		}
		argc++;
	}

	return argc;
}

int
isns_parse_attrs(unsigned int argc, char **argv,
		isns_attr_list_t *attrs,
		struct isns_attr_list_parser *st)
{
	unsigned int	i;

	for (i = 0; i < argc; ++i) {
		char		*name, *value;

		name = argv[i];
		if ((value = strchr(name, '=')) != NULL)
			*value++ = '\0';

		if (!value && !st->nil_permitted) {
			isns_error("Missing value for atribute %s\n", name);
			return 0;
		}

		if (!parse_one_attr(name, value, attrs, st)) {
			isns_error("Unable to parse %s=%s\n", name, value);
			return 0;
		}
	}

	return 1;
}

/*
 * Query strings may contain a mix of query keys (foo=bar),
 * and requested attributes (?foo). The former are used by
 * the server in its object search, whereas the latter instruct
 * it which attributes to return.
 */
int
isns_parse_query_attrs(unsigned int argc, char **argv,
		isns_attr_list_t *keys,
		isns_attr_list_t *requested_attrs,
		struct isns_attr_list_parser *st)
{
	struct isns_attr_list_parser query_state;
	unsigned int	i;

	query_state = *st;
	query_state.multi_type_permitted = 1;

	for (i = 0; i < argc; ++i) {
		char		*name, *value;

		name = argv[i];
		if ((value = strchr(name, '=')) != NULL)
			*value++ = '\0';

		if (name[0] == '?') {
			uint32_t tag;

			if (value) {
				isns_error("No value allowed for query attribute %s\n",
						name);
				return 0;
			}

			if ((tag = tag_by_name(name + 1, &query_state)) != 0) {
				isns_attr_list_append_nil(requested_attrs, tag);
				continue;
			}
		} else {
			if (!value && !st->nil_permitted) {
				isns_error("Missing value for atribute %s\n", name);
				return 0;
			}

			if (parse_one_attr(name, value, keys, st))
				continue;
		}

		isns_error("Unable to parse %s=%s\n", name, value);
		return 0;
	}

	return 1;
}

void
isns_attr_list_parser_help(struct isns_attr_list_parser *st)
{
	isns_object_template_t *tmpl, *current = NULL;
	struct tag_name	*t;

	if (all_attrs[0].prefix == NULL)
		init_tags();

	for (t = all_attrs; t->name; ++t) {
		const isns_tag_type_t *tag_type;
		char		namebuf[64];
		const char	*help;
		unsigned int	i;

		if (st && !st->multi_type_permitted
		 && st->prefix && t->prefix != st->prefix)
			continue;

		tmpl = t->prefix->context;
		if (tmpl != current) {
			printf("\nAttributes for object type %s; using prefix %s\n",
				tmpl->iot_name, t->prefix->name);
			current = tmpl;
		}

		snprintf(namebuf, sizeof(namebuf), "%s%s", t->prefix->name, t->name);
		printf("  %-20s   ", namebuf);

		tag_type = isns_tag_type_by_id(t->tag);
		if (tag_type == NULL) {
			printf("Unknown\n");
			continue;
		}
		printf("%s (%s", tag_type->it_name,
				tag_type->it_type->it_name);

		if (tag_type->it_readonly)
			printf("; readonly");
		if (tag_type->it_multiple)
			printf("; multiple instances");
		printf(")");

		help = NULL;
		if (t->tag == OPENISNS_TAG_POLICY_KEY) {
			help = "name of key file, or \"gen\" for key generation";
		} else
		if (tag_type->it_help)
			help = tag_type->it_help();

		if (help) {
			if (strlen(help) < 20)
				printf(" [%s]", help);
			else
				printf("\n%25s[%s]", "", help);
		}
		printf("\n");

		if (t->alias[0]) {
			printf("%25sAliases:", "");
			for (i = 0; i < MAX_ALIASES && t->alias[i]; ++i)
				printf(" %s", t->alias[i]);
			printf("\n");
		}
	}
}

isns_object_template_t *
isns_attr_list_parser_context(const struct isns_attr_list_parser *st)
{
	if (st->prefix)
		return st->prefix->context;
	return NULL;
}

int
isns_print_attrs(isns_object_t *obj, char **argv, unsigned int argsmax)
{
	struct isns_attr_list_parser st;
	unsigned int	i, argc = 0;

	isns_attr_list_parser_init(&st, obj->ie_template);

	for (i = 0; i < obj->ie_attrs.ial_count; ++i) {
		isns_attr_t *attr = obj->ie_attrs.ial_data[i];
		char		argbuf[512], value[512];
		const char	*name;

		name = name_by_tag(attr->ia_tag_id, &st);
		if (name == NULL)
			continue;
		if (argc + 1 >= argsmax)
			break;

		snprintf(argbuf, sizeof(argbuf), "%s%s=%s",
				st.prefix->name, name,
				isns_attr_print_value(attr, value, sizeof(value)));
		argv[argc++] = isns_strdup(argbuf);
	}

	argv[argc] = NULL;
	return argc;
}
