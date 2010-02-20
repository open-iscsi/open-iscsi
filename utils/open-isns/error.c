/*
 * iSNS error strings etc.
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include "isns.h"

const char *
isns_strerror(enum isns_status status)
{
	switch (status) {
	case ISNS_SUCCESS:
		return "Success";
	case ISNS_UNKNOWN_ERROR:
		return "Unknown error";
	case ISNS_MESSAGE_FORMAT_ERROR:
		return "Message format error";
	case ISNS_INVALID_REGISTRATION:
		return "Invalid registration";
	case ISNS_INVALID_QUERY:
		return "Invalid query";
	case ISNS_SOURCE_UNKNOWN:
		return "Source unknown";
	case ISNS_SOURCE_ABSENT:
		return "Source absent";
	case ISNS_SOURCE_UNAUTHORIZED:
		return "Source unauthorized";
	case ISNS_NO_SUCH_ENTRY:
		return "No such entry";
	case ISNS_VERSION_NOT_SUPPORTED:
		return "Version not supported";
	case ISNS_INTERNAL_ERROR:
		return "Internal error";
	case ISNS_BUSY:
		return "Busy";
	case ISNS_OPTION_NOT_UNDERSTOOD:
		return "Option not understood";
	case ISNS_INVALID_UPDATE:
		return "Invalid update";
	case ISNS_MESSAGE_NOT_SUPPORTED:
		return "Message not supported";
	case ISNS_SCN_EVENT_REJECTED:
		return "SCN event rejected";
	case ISNS_SCN_REGISTRATION_REJECTED:
		return "SCN registration rejected";
	case ISNS_ATTRIBUTE_NOT_IMPLEMENTED:
		return "Attribute not implemented";
	case ISNS_FC_DOMAIN_ID_NOT_AVAILABLE:
		return "FC domain id not available";
	case ISNS_FC_DOMAIN_ID_NOT_ALLOCATED:
		return "FC domain id not allocated";
	case ISNS_ESI_NOT_AVAILABLE:
		return "ESI not available";
	case ISNS_INVALID_DEREGISTRATION:
		return "Invalid deregistration";
	case ISNS_REGISTRATION_FEATURE_NOT_SUPPORTED:
		return "Registration feature not supported";
	default:
		break;
	}

	return "Unknown iSNS status code";
}

