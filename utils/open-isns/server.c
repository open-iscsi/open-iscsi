/*
 * iSNS server side functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include "isns.h"
#include "util.h"
#include "security.h"
#include "message.h"

static int	isns_not_supported(isns_server_t *, isns_simple_t *, isns_simple_t **);

struct isns_service_ops		isns_default_service_ops = {
	.process_registration	  = isns_process_registration,
	.process_query		  = isns_process_query,
	.process_getnext	  = isns_process_getnext,
	.process_deregistration	  = isns_process_deregistration,
	.process_scn_registration = isns_process_scn_register,
	.process_scn_deregistration = isns_process_scn_deregistration,
	.process_scn_event	  = isns_not_supported,
	.process_dd_registration  = isns_process_dd_registration,
	.process_dd_deregistration= isns_process_dd_deregistration,
};

struct isns_service_ops		isns_callback_service_ops = {
	.process_esi		  = isns_process_esi,
	.process_scn		  = isns_process_scn,
};

/*
 * Create a server object
 */
isns_server_t *
isns_create_server(isns_source_t *source, isns_db_t *db,
			struct isns_service_ops *ops)
{
	isns_server_t	*srv;

	if (source == NULL) {
		isns_error("%s: source name not set\n", __FUNCTION__);
		return NULL;
	}

	srv = isns_calloc(1, sizeof(*srv));
	srv->is_source = isns_source_get(source);
	srv->is_db = db;
	srv->is_ops = ops;

	return srv;
}

void
isns_server_set_scn_callback(isns_server_t *srv, isns_scn_callback_fn_t *func)
{
	srv->is_scn_callback = func;
}

/*
 * Try to handle transactions safely.
 * This isn't perfect, because there's state outside the DB (for instance
 * the DD information)
 */
static int
isns_begin_write_operation(isns_server_t *srv, isns_simple_t *msg, int *status)
{
	isns_db_begin_transaction(srv->is_db);
	return 1;
}

static void
isns_end_write_operation(isns_server_t *srv, isns_simple_t *msg, int *status)
{
	if (*status == ISNS_SUCCESS)
		isns_db_commit(srv->is_db);
	else
		isns_db_rollback(srv->is_db);
}

static inline int
isns_begin_read_operation(isns_server_t *srv, isns_simple_t *msg, int *status)
{
	return 1;
}

static void
isns_end_read_operation(isns_server_t *srv, isns_simple_t *msg, int *status)
{
}

/*
 * Process an incoming message
 */
isns_message_t *
isns_process_message(isns_server_t *srv, isns_message_t *msg)
{
	struct isns_service_ops *ops = srv->is_ops;
	uint16_t	function = msg->im_header.i_function;
	int		status = ISNS_SUCCESS;
	isns_simple_t	*call = NULL, *reply = NULL;
	isns_message_t	*res_msg = NULL;
	isns_db_t	*db = srv->is_db;

	status = isns_simple_decode(msg, &call);
	if (status) {
		isns_debug_message("Failed to decode %s request: %s\n",
				isns_function_name(msg->im_header.i_function),
				isns_strerror(status));
		goto reply;
	}

	isns_simple_print(call, isns_debug_message);

	/* Set policy and privileges based on the
	 * sender's identity. */
	if (!(call->is_policy = isns_policy_bind(msg))) 
		goto err_unauthorized;

	if (!isns_policy_validate_function(call->is_policy, msg))
		goto err_unauthorized;

	/* Checks related to the message source.
	 * Note - some messages do not use a source.
	 */
	if (call->is_source) {
		/* Validate the message source. This checks whether the client
		 * is permitted to use this source node name.
		 * Beware - not all messages include a source.
		 */
		if (!isns_policy_validate_source(call->is_policy, call->is_source))
			goto err_unauthorized;

		/* This may fail if the source node isn't in the DB yet. */
		isns_source_set_node(call->is_source, db);

		/*
		 * 6.2.6.  Registration Period
		 *
		 * The registration SHALL be removed from the iSNS database
		 * if an iSNS Protocol message is not received from the
		 * iSNS client before the registration period has expired.
		 * Receipt of any iSNS Protocol message from the iSNS client
		 * automatically refreshes the Entity Registration Period and
		 * Entity Registration Timestamp.  To prevent a registration
		 * from expiring, the iSNS client should send an iSNS Protocol
		 * message to the iSNS server at intervals shorter than the
		 * registration period.  Such a message can be as simple as a
		 * query for one of its own attributes, using its associated
		 * iSCSI Name or FC Port Name WWPN as the Source attribute.
		 */
		/* Thusly, we update the timestamps of all entities
		 * registered by this source. */
		isns_entity_touch(call->is_source->is_entity);
	}

	/* Handle the requested function. If the function vector is
	 * NULL, silently discard the message. */
	switch (function) {
#define DO(rw, FUNCTION, __function) \
	case FUNCTION:						\
		if (!ops->__function)				\
			goto no_reply;				\
								\
		if (!isns_begin_##rw##_operation(srv, call, &status)) \
			break;					\
		status = ops->__function(srv, call, &reply);	\
		isns_end_##rw##_operation(srv, call, &status);	\
		break

	DO(write, ISNS_DEVICE_ATTRIBUTE_REGISTER, process_registration);
	DO(read,  ISNS_DEVICE_ATTRIBUTE_QUERY, process_query);
	DO(read,  ISNS_DEVICE_GET_NEXT, process_getnext);
	DO(write, ISNS_DEVICE_DEREGISTER, process_deregistration);
	DO(write, ISNS_DD_REGISTER, process_dd_registration);
	DO(write, ISNS_DD_DEREGISTER, process_dd_deregistration);
	DO(read,  ISNS_SCN_REGISTER, process_scn_registration);
	DO(read,  ISNS_SCN_DEREGISTER, process_scn_deregistration);
	DO(read,  ISNS_SCN_EVENT, process_scn_event);
	DO(read,  ISNS_STATE_CHANGE_NOTIFICATION, process_scn);
	DO(read,  ISNS_ENTITY_STATUS_INQUIRY, process_esi);
	DO(read,  ISNS_HEARTBEAT, process_heartbeat);
#undef DO

	default:
		isns_error("Function %s not supported\n",
				isns_function_name(function));
		status = ISNS_MESSAGE_NOT_SUPPORTED;
		break;
	}

reply:
	/* Commit any changes to the DB before we reply */
	if (db)
		isns_db_sync(db);

	/* Send out SCN notifications */
	isns_flush_events();

	if (reply != NULL) {
		reply->is_function |= 0x8000;
		isns_simple_print(reply, isns_debug_message);

		/* Encode the whole thing */
		status = isns_simple_encode_response(reply, msg, &res_msg);
	}

	/* No reply, or error when encoding it:
	 * just send the error, nothing else. */
	if (res_msg == NULL) {
		res_msg = isns_create_reply(msg);
		if (status == ISNS_SUCCESS)
			status = ISNS_INTERNAL_ERROR;
	}

	isns_debug_message("response status 0x%04x (%s)\n",
			status, isns_strerror(status));

	if (status != ISNS_SUCCESS)
		isns_message_set_error(res_msg, status);

no_reply:
	isns_simple_free(call);
	if (reply)
		isns_simple_free(reply);
	return res_msg;

err_unauthorized:
	status = ISNS_SOURCE_UNAUTHORIZED;
	goto reply;
}

int
isns_not_supported(isns_server_t *srv, isns_simple_t *call, isns_simple_t **replyp)
{
	return ISNS_MESSAGE_NOT_SUPPORTED;
}
