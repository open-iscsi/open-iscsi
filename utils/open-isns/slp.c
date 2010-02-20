/*
 * SLP registration and query of iSNS
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include "config.h"
#include <stdlib.h>
#ifdef HAVE_SLP_H
# include <slp.h>
#endif

#include "isns.h"
#include "util.h"
#include "internal.h"

#define ISNS_SLP_SERVICE_NAME	"iscsi:sms"
/*
 * RFC 4018 says we would use scope initiator-scope-list.
 * But don't we want targets to find the iSNS server, too?
 */
#define ISNS_SLP_SCOPE		"initiator-scope-list"

#ifdef WITH_SLP

struct isns_slp_url_state {
	SLPError	slp_err;
	char *		slp_url;
};

static void
isns_slp_report(SLPHandle handle, SLPError err, void *cookie)
{
	*(SLPError *) cookie = err;
}

/*
 * Register a service with SLP
 */ 
int
isns_slp_register(const char *url)
{
	SLPError	err, callbackerr; 
	SLPHandle	handle = NULL; 

	err = SLPOpen("en", SLP_FALSE, &handle); 
	if(err != SLP_OK) { 
		isns_error("Unable to obtain SLP handle (err %d)\n", err);
		return 0;
	} 

	err = SLPReg(handle, url, SLP_LIFETIME_MAXIMUM,
			ISNS_SLP_SCOPE,
			"(description=iSNS Server),(protocols=isns)",
			SLP_TRUE,
			isns_slp_report, &callbackerr);

	SLPClose(handle);

	if (err == SLP_OK)
		err = callbackerr;
	if (err != SLP_OK) {
		isns_error("Failed to register with SLP (err %d)\n", err);
		return 0;
	}

	return 1;
}

/*
 * DeRegister a service
 */ 
int
isns_slp_unregister(const char *url)
{
	SLPError	err, callbackerr; 
	SLPHandle	handle = NULL; 

	isns_debug_general("SLP: Unregistering \"%s\"\n", url);

	err = SLPOpen("en", SLP_FALSE, &handle); 
	if(err != SLP_OK) { 
		isns_error("Unable to obtain SLP handle (err %d)\n", err);
		return 0;
	} 

	err = SLPDereg(handle, url, isns_slp_report, &callbackerr);

	SLPClose(handle);

	if (err == SLP_OK)
		err = callbackerr;
	if (err != SLP_OK) {
		isns_error("Failed to deregister with SLP (err %d)\n", err);
		return 0;
	}

	return 1;
}

/*
 * Find an iSNS server through SLP
 */
static SLPBoolean
isns_slp_url_callback(SLPHandle handle,
		const char *url, unsigned short lifetime,
		SLPError err, void *cookie) 
{
	struct isns_slp_url_state *sp = cookie;
	SLPSrvURL	*parsed_url = NULL;
	int		want_more = SLP_TRUE;
	char		buffer[1024];

	if (err != SLP_OK && err != SLP_LAST_CALL)
		return SLP_FALSE;

	if (!url)
		goto out;

	isns_debug_general("SLP: Found URL \"%s\"\n", url);
	err = SLPParseSrvURL(url, &parsed_url);
	if (err != SLP_OK) {
		isns_error("Error parsing SLP service URL \"%s\"\n", url);
		goto out;
	}

	if (parsed_url->s_pcNetFamily
	 && parsed_url->s_pcNetFamily[0]
	 && strcasecmp(parsed_url->s_pcNetFamily, "ip")) {
		isns_error("Ignoring SLP service URL \"%s\"\n", url);
		goto out;
	}

	if (parsed_url->s_iPort) {
		snprintf(buffer, sizeof(buffer), "%s:%u",
				parsed_url->s_pcHost,
				parsed_url->s_iPort);
		isns_assign_string(&sp->slp_url, buffer);
	} else {
		isns_assign_string(&sp->slp_url,
				parsed_url->s_pcHost);
	}
	want_more = SLP_FALSE;

out:
	if (parsed_url)
		SLPFree(parsed_url);
	sp->slp_err = SLP_OK;

	return want_more;
}

/*
 * Locate the iSNS server using SLP.
 * This is not really an instantaneous process. Maybe we could
 * speed this up by using a cache.
 */
char *
isns_slp_find(void)
{
	static struct isns_slp_url_state state;
	SLPHandle	handle = NULL; 
	SLPError	err; 

	if (state.slp_url)
		return state.slp_url;

	isns_debug_general("Using SLP to locate iSNS server\n");

	err = SLPOpen("en", SLP_FALSE, &handle); 
	if(err != SLP_OK) { 
		isns_error("Unable to obtain SLP handle (err %d)\n", err);
		return NULL;
	} 

	err = SLPFindSrvs(handle, ISNS_SLP_SERVICE_NAME,
			NULL, "(protocols=isns)",
			isns_slp_url_callback, &state);

	SLPClose(handle);

	if (err == SLP_OK)
		err = state.slp_err;
	if (err != SLP_OK) {
		isns_error("Failed to find service in SLP (err %d)\n", err);
		return NULL;
	}

	if (state.slp_url == NULL) {
		isns_error("Service %s not registered with SLP\n",
				ISNS_SLP_SERVICE_NAME);
		return NULL;

	}

	isns_debug_general("Using iSNS server at %s\n", state.slp_url);
	return state.slp_url;
}

#else /* WITH_SLP */

int
isns_slp_register(const char *url)
{
	isns_error("SLP support disabled in this build\n");
	return 0;
}

int
isns_slp_unregister(const char *url)
{
	isns_error("SLP support disabled in this build\n");
	return 0;
}

char *
isns_slp_find(void)
{
	isns_error("SLP support disabled in this build\n");
	return NULL;
}

#endif /* WITH_SLP */

char *
isns_slp_build_url(uint16_t port)
{
	char	buffer[1024];

	if (port)
		snprintf(buffer, sizeof(buffer),
			"service:%s://%s:%u",
			ISNS_SLP_SERVICE_NAME,
			isns_config.ic_host_name, port);
	else
		snprintf(buffer, sizeof(buffer),
			"service:%s://%s",
			ISNS_SLP_SERVICE_NAME,
			isns_config.ic_host_name);
	return isns_strdup(buffer);
}

