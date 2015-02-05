#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "httpd.h"

#include "../config.h"
#include "common.h"
#include "debug.h"
#include "httpd_thread.h"

/** Main request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
void
thread_httpd(void *args)
{
	void	**params;
	httpd	*webserver;
	request	*r;
	
	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	free(params); /* XXX We must release this ourselves. */
	
	if (httpdReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		debug(LOG_DEBUG, "Calling httpdProcessRequest() for %s", r->clientAddr);
		httpdProcessRequest(webserver, r);
		debug(LOG_DEBUG, "Returned from httpdProcessRequest() for %s", r->clientAddr);
	}
	else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	}
	debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
	httpdEndRequest(r);
}
