/*
 * iSCSI Administration library
 *
 * Copyright (C) 2008-2009 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2008-2009 Hans de Goede <hdegoede@redhat.com>
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#ifndef __LIBISCSI_H
#define __LIBISCSI_H

#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if __GNUC__ >= 4
#define PUBLIC __attribute__ ((visibility("default")))
#else
#define PUBLIC
#endif

/** \brief Maximum length for iSCSI values.
 *
 * Maximum length for iSCSI values such as hostnames and parameter values.
 */
#define LIBISCSI_VALUE_MAXLEN 256

/** \brief supported authentication methods
 *
 * This enum lists all supported authentication methods.
 */
enum PUBLIC libiscsi_auth_t;
enum libiscsi_auth_t {
	libiscsi_auth_none, /**< No authentication */
	libiscsi_auth_chap, /**< CHAP authentication */
};

/** \brief libiscsi context struct
 *
 * Note: even though libiscsi uses a context struct, the underlying open-iscsi
 * code does not, so libiscsi is not thread safe, not even when using one
 * context per thread!
 */
struct PUBLIC libiscsi_context;

/** \brief iSCSI node record
 * Struct holding data uniquely identifying an iSCSI node.
 * Note open-iscsi has some code in place for multiple connections in
 * one node record and thus multiple address / port combinations, but
 * this does not get used anywhere, so we keep things simple and assume
 * one connection.
 */
struct PUBLIC libiscsi_node;
struct libiscsi_node {
	char name[LIBISCSI_VALUE_MAXLEN]; /**< iSCSI iqn for the node. */
	int tpgt; /**< Portal group number. */
	char address[NI_MAXHOST]; /**< Portal hostname or IP-address. */
	int port; /** Portal port number. */
	char iface[LIBISCSI_VALUE_MAXLEN]; /**< Interface to connect through. */
};

/** \brief libiscsi CHAP authentication information struct
 *
 * Struct holding all data needed for CHAP login / authentication. Note that
 * \e reverse_username may be a 0 length string in which case only forward
 * authentication will be done.
 */
struct PUBLIC libiscsi_chap_auth_info;
struct libiscsi_chap_auth_info {
	char username[LIBISCSI_VALUE_MAXLEN]; /**< Username */
	char password[LIBISCSI_VALUE_MAXLEN]; /** Password */
	char reverse_username[LIBISCSI_VALUE_MAXLEN]; /**< Reverse Username */
	char reverse_password[LIBISCSI_VALUE_MAXLEN]; /**< Reverse Password */
};

/** \brief generic libiscsi authentication information struct
 *
 * Struct holding authentication information for discovery and login.
 */
struct PUBLIC libiscsi_auth_info;
struct libiscsi_auth_info {
	enum libiscsi_auth_t method; /**< Authentication method to use */
	/** Union holding method depend info */
	union {
		struct libiscsi_chap_auth_info chap; /**< Chap specific info */
	};
};

/** \brief Initialize libiscsi
 *
 * This function creates a libiscsi context and initializes it. This context
 * is need to use other libiscsi functions.
 *
 * \return	 A pointer to the created context, or NULL in case of an error.
 */
PUBLIC struct libiscsi_context *libiscsi_init(void);

/** \brief Cleanup libiscsi used resource
 *
 * This function cleanups any used resources and then destroys the passed
 * context. After this the passed in context may no longer be used!
 *
 * \param context	libiscsi context to operate on.
 */
PUBLIC void libiscsi_cleanup(struct libiscsi_context *context);

/** \brief Discover iSCSI nodes using sendtargets and add them to the node db.
 *
 * This function connects to the given address and port and then tries to
 * discover iSCSI nodes using the sendtargets protocol. Any found nodes are
 * added to the local iSCSI node database and are returned in a dynamically
 * allocated array.
 *
 * Note that the (optional) authentication info is for authenticating the
 * discovery, and is not for the found nodes! If the connection(s) to the
 * node(s) need authentication too, you can set the username / password for
 * those (which can be different!) using the libiscsi_node_set_auth() function.
 *
 * \param context		libiscsi context to operate on.
 * \param address		Hostname or IP-address to connect to.
 * \param port			Port to connect to, or 0 for the default port.
 * \param auth_info		Authentication information, or NULL.
 * \param nr_found		The number of found nodes will be returned
 *				through this pointer if not NULL.
 * \param found_nodes		The address of the dynamically allocated array
 *				of found nodes will be returned through this
 *				pointer if not NULL. The caller must free this
 *				array using free().
 * \return			0 on success, otherwise a standard error code
 *				(from errno.h).
 */
PUBLIC int libiscsi_discover_sendtargets(struct libiscsi_context *context,
					 const char *address, int port,
					 const struct libiscsi_auth_info
					 *auth_info, int *nr_found,
					 struct libiscsi_node **found_nodes);

/** \brief Read iSCSI node info from firmware and add them to the node db.
 *
 * This function discovers iSCSI nodes using firmware (ppc or ibft). Any found
 * nodes are added to the local iSCSI node database and are returned in a
 * dynamically allocated array.
 *
 * Note that unlike sendtargets discovery, this function will also read
 * authentication info and store that in the database too.
 *
 * Note this function currently is a stub which will always return -EINVAL
 * (IOW it is not yet implemented)
 *
 * \param context	libiscsi context to operate on.
 * \param nr_found	The number of found nodes will be returned
 *			through this pointer if not NULL.
 * \param found_nodes	The address of the dynamically allocated array
 *			of found nodes will be returned through this
 *			pointer if not NULL. The caller must free this
 *			array using free().
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_discover_firmware(struct libiscsi_context *context,
				      int *nr_found,
				      struct libiscsi_node **found_nodes);

/** \brief Check validity of the given authentication info.
 *
 * This function checks the validity of the given authentication info. For
 * example in case of CHAP, if the username and password are not empty.
 *
 * This function is mainly intended for use by language bindings.
 *
 * \param context	libiscsi context to operate on.
 * \param auth_info	Authentication information to check.
 * \return		0 on success, otherwise EINVAL.
 */
PUBLIC int libiscsi_verify_auth_info(struct libiscsi_context *context,
				     const struct libiscsi_auth_info
				     *auth_info);

/** \brief Set the authentication info for the given node.
 *
 * This function sets the authentication information for the node described by
 * the given node record. This will overwrite any existing authentication
 * information.
 *
 * This is the way to specify authentication information for nodes found
 * through sendtargets discovery.
 *
 * Note:
 * 1) This is a convince wrapper around libiscsi_node_set_parameter(),
 *    setting the node.session.auth.* parameters.
 * 2) For nodes found through firmware discovery the authentication information
 *    has already been set from the firmware.
 * 3) \e auth_info may be NULL in which case any existing authinfo will be
 *    cleared.
 *
 * \param context	libiscsi context to operate on.
 * \param node		iSCSI node to set auth information of
 * \param auth_info	Authentication information, or NULL.
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_node_set_auth(struct libiscsi_context *context,
				  const struct libiscsi_node *node,
				  const struct libiscsi_auth_info
				  *auth_info);

/** \brief Get the authentication info for the given node.
 *
 * This function gets the authentication information for the node described by
 * the given node record.
 *
 * \param context	libiscsi context to operate on.
 * \param node		iSCSI node to set auth information of
 * \param auth_info	Pointer to a libiscsi_auth_info struct where
 *			the retrieved information will be stored.
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_node_get_auth(struct libiscsi_context *context,
				  const struct libiscsi_node *node,
				  struct libiscsi_auth_info *auth_info);

/** \brief Login to an iSCSI node.
 *
 * Login to the iSCSI node described by the given node record.
 *
 * \param context	libiscsi context to operate on.
 * \param node		iSCSI node to login to.
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_node_login(struct libiscsi_context *context,
			       const struct libiscsi_node *node);

/** \brief Logout of an iSCSI node.
 *
 * Logout of the iSCSI node described by the given node record.
 *
 * \param context	libiscsi context to operate on.
 * \param node		iSCSI node to logout from.
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_node_logout(struct libiscsi_context *context,
				const struct libiscsi_node *node);

/** \brief Set an iSCSI parameter for the given node
 *
 * Set the given nodes iSCSI parameter named by \e parameter to value \e value.
 *
 * \param context	libiscsi context to operate on.
 * \param node		iSCSI node to change a parameter from.
 * \param parameter	Name of the parameter to set.
 * \param value		Value to set the parameter too.
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_node_set_parameter(struct libiscsi_context *context,
				       const struct libiscsi_node *node,
				       const char *parameter,
				       const char *value);

/** \brief Get the value of an iSCSI parameter for the given node
 *
 * Get the value of the given nodes iSCSI parameter named by \e parameter.
 *
 * \param context	libiscsi context to operate on.
 * \param node		iSCSI node to change a parameter from.
 * \param parameter	Name of the parameter to get.
 * \param value		The retrieved value is stored here, this buffer must be
 *			at least LIBISCSI_VALUE_MAXLEN bytes large.
 * \return		0 on success, otherwise a standard error code
 *			(from errno.h).
 */
PUBLIC int libiscsi_node_get_parameter(struct libiscsi_context *context,
				       const struct libiscsi_node *node,
				       const char *parameter,
				       char *value);

/** \brief Get human readable string describing the last libiscsi error.
 *
 * This function can be called to get a human readable error string when a
 * libiscsi function has returned an error. This function uses a single buffer
 * per context, thus the result is only valid as long as no other libiscsi
 * calls are made on the same context after the failing function call.
 *
 * \param context	libiscsi context to operate on.
 *
 * \return human readable string describing the last libiscsi error.
 */
PUBLIC const char *libiscsi_get_error_string(struct libiscsi_context *context);

/************************** Utility functions *******************************/

/** \brief libiscsi network config struct
 *
 * libiscsi network config struct.
 */
struct PUBLIC libiscsi_network_config;
struct libiscsi_network_config {
	int dhcp; /**< Using DHCP? (boolean). */
	char iface_name[LIBISCSI_VALUE_MAXLEN]; /**< Interface name. */
	char mac_address[LIBISCSI_VALUE_MAXLEN]; /**< MAC address. */
	char ip_address[LIBISCSI_VALUE_MAXLEN]; /**< IP address. */
	char netmask[LIBISCSI_VALUE_MAXLEN]; /**< Netmask. */
	char gateway[LIBISCSI_VALUE_MAXLEN]; /**< IP of Default gateway. */
	char primary_dns[LIBISCSI_VALUE_MAXLEN]; /**< IP of the Primary DNS. */
	char secondary_dns[LIBISCSI_VALUE_MAXLEN]; /**< Secondary DNS. */
};

/** \brief Get network configuration information from iscsi firmware
 *
 * Function can be called to get the network configuration information
 * (like dhcp, ip, netmask, default gateway, etc.) from the firmware of a
 * network adapter with iscsi boot firmware.
 *
 * Note that not all fields of the returned struct are necessarily filled,
 * unset fields contain a 0 length string.
 *
 * \param config	pointer to a libiscsi_network_config struct to fill.
 *
 * \return		0 on success, ENODEV when no iscsi firmware was found.
 */
PUBLIC int libiscsi_get_firmware_network_config(struct libiscsi_network_config
						*config);

/** \brief Get the initiator name (iqn) from the iscsi firmware
 *
 * Get the initiator name (iqn) from the iscsi firmware.
 *
 * \param initiatorname The initiator name is stored here, this buffer must be
 *			at least LIBISCSI_VALUE_MAXLEN bytes large.
 * \return		0 on success, ENODEV when no iscsi firmware was found.
 */
PUBLIC int libiscsi_get_firmware_initiator_name(char *initiatorname);

#undef PUBLIC

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif
