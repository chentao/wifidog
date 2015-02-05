#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"

#include "util.h"
#include "cJSON.h"

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oExternalInterface,
	oGatewayID,
	oGatewayInterface,
	oGatewayAddress,
	oGatewayPort,
	oAuthServer,
	oAuthServHostname,
	oAuthServSSLAvailable,
	oAuthServSSLPort,
	oAuthServHTTPPort,
	oAuthServPath,
	oAuthServLoginScriptPathFragment,
	oAuthServPortalScriptPathFragment,
	oAuthServMsgScriptPathFragment,
	oAuthServPingScriptPathFragment,
	oAuthServAuthScriptPathFragment,
	oHTTPDMaxConn,
	oHTTPDName,
	oHTTPDRealm,
	oHTTPDUsername,
	oHTTPDPassword,
	oClientTimeout,
	oCheckInterval,
	oWdctlSocket,
	oSyslogFacility,
	oFirewallRule,
	oFirewallRuleSet,
	oTrustedMACList,
	oHtmlMessageFile,
	oProxyPort,
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "daemon",             	oDaemon },
	{ "debuglevel",         	oDebugLevel },
	{ "externalinterface",  	oExternalInterface },
	{ "gatewayid",          	oGatewayID },
	{ "gatewayinterface",   	oGatewayInterface },
	{ "gatewayaddress",     	oGatewayAddress },
	{ "gatewayport",        	oGatewayPort },
	{ "authserver",         	oAuthServer },
	{ "httpdmaxconn",       	oHTTPDMaxConn },
	{ "httpdname",          	oHTTPDName },
	{ "httpdrealm",			oHTTPDRealm },
	{ "httpdusername",		oHTTPDUsername },
	{ "httpdpassword",		oHTTPDPassword },
	{ "clienttimeout",      	oClientTimeout },
	{ "checkinterval",      	oCheckInterval },
	{ "syslogfacility", 		oSyslogFacility },
	{ "wdctlsocket",		oWdctlSocket },
	{ "hostname",			oAuthServHostname },
	{ "sslavailable",		oAuthServSSLAvailable },
	{ "sslport",			oAuthServSSLPort },
	{ "httpport",			oAuthServHTTPPort },
	{ "path",			oAuthServPath },
	{ "loginscriptpathfragment",	oAuthServLoginScriptPathFragment },
	{ "portalscriptpathfragment",	oAuthServPortalScriptPathFragment },
	{ "msgscriptpathfragment",	oAuthServMsgScriptPathFragment },
	{ "pingscriptpathfragment",	oAuthServPingScriptPathFragment },
	{ "authscriptpathfragment",	oAuthServAuthScriptPathFragment },
	{ "firewallruleset",		oFirewallRuleSet },
	{ "firewallrule",		oFirewallRule },
	{ "trustedmaclist",		oTrustedMACList },
	{ "htmlmessagefile",		oHtmlMessageFile },
	{ "proxyport",			oProxyPort },
	{ NULL,				oBadOption },
};

static void config_notnull(const void *parm, const char *parmname);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static int _parse_firewall_rule(const char *ruleset, char *leftover);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);

static OpCodes config_parse_token(const char *cp, const char *filename, int linenum);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
	return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	debug(LOG_DEBUG, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));
	config.htmlmsgfile = safe_strdup(DEFAULT_HTMLMSGFILE);
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
	config.external_interface = NULL;
	config.gw_id = DEFAULT_GATEWAYID;
	config.gw_interface = NULL;
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.auth_servers = NULL;
	config.httpdname = NULL;
	config.httpdrealm = DEFAULT_HTTPDNAME;
	config.httpdusername = NULL;
	config.httpdpassword = NULL;
	config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.daemon = -1;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.wdctl_sock = safe_strdup(DEFAULT_WDCTL_SOCK);
	config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.rulesets = NULL;
	config.trustedmaclist = NULL;
	config.proxy_port = 0;

    config.device_id = NULL;
    config.account = NULL;
    config.active_date = NULL;
    config.platform_servers = NULL;
    config.portal_servers = NULL;
    config.white_urls = NULL;
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
	if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", 
			filename, linenum, cp);
	return oBadOption;
}

/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE *file, const char *filename, int *linenum)
{
	char		*host = NULL,
			*path = NULL,
			*loginscriptpathfragment = NULL,
			*portalscriptpathfragment = NULL,
			*msgscriptpathfragment = NULL,
			*pingscriptpathfragment = NULL,
			*authscriptpathfragment = NULL,
			line[MAX_BUF],
			*p1,
			*p2;
	int		http_port,
			ssl_port,
			ssl_available,
			opcode;
	t_auth_serv	*new,
			*tmp;

	/* Defaults */
	path = safe_strdup(DEFAULT_AUTHSERVPATH);
	loginscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
	portalscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
	msgscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
	pingscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
	authscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
	http_port = DEFAULT_AUTHSERVPORT;
	ssl_port = DEFAULT_AUTHSERVSSLPORT;
	ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;


	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* trim all blanks at the end of the line */
		for (p2 = (p2 != NULL? p2 - 1: &line[MAX_BUF - 2]);
		     isblank(*p2) && p2 > p1; p2--) {
			*p2 = '\0';
		}
		
		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;
			
			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);
			
			switch (opcode) {
				case oAuthServHostname:
					host = safe_strdup(p2);
					break;
				case oAuthServPath:
					free(path);
					path = safe_strdup(p2);
					break;
				case oAuthServLoginScriptPathFragment:
					free(loginscriptpathfragment);
					loginscriptpathfragment = safe_strdup(p2);
					break;					
				case oAuthServPortalScriptPathFragment:
					free(portalscriptpathfragment);
					portalscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServMsgScriptPathFragment:
					free(msgscriptpathfragment);
					msgscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServPingScriptPathFragment:
					free(pingscriptpathfragment);
					pingscriptpathfragment = safe_strdup(p2);
					break;					
				case oAuthServAuthScriptPathFragment:
					free(authscriptpathfragment);
					authscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServSSLPort:
					ssl_port = atoi(p2);
					break;
				case oAuthServHTTPPort:
					http_port = atoi(p2);
					break;
				case oAuthServSSLAvailable:
					ssl_available = parse_boolean_value(p2);
					if (ssl_available < 0)
						ssl_available = 0;
					break;
				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	/* only proceed if we have an host and a path */
	if (host == NULL)
		return;
	
	debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the auth server list",
			host, http_port, ssl_port, path);

	/* Allocate memory */
	new = safe_malloc(sizeof(t_auth_serv));
	
	/* Fill in struct */
	memset(new, 0, sizeof(t_auth_serv)); /*< Fill all with NULL */
	new->authserv_hostname = host;
	new->authserv_use_ssl = ssl_available;
	new->authserv_path = path;
	new->authserv_login_script_path_fragment = loginscriptpathfragment;
	new->authserv_portal_script_path_fragment = portalscriptpathfragment;
	new->authserv_msg_script_path_fragment = msgscriptpathfragment;    
	new->authserv_ping_script_path_fragment = pingscriptpathfragment;  
	new->authserv_auth_script_path_fragment = authscriptpathfragment;  
	new->authserv_http_port = http_port;
	new->authserv_ssl_port = ssl_port;
	
	/* If it's the first, add to config, else append to last server */
	if (config.auth_servers == NULL) {
		config.auth_servers = new;
	} else {
		for (tmp = config.auth_servers; tmp->next != NULL;
				tmp = tmp->next);
		tmp->next = new;
	}
	
	debug(LOG_DEBUG, "Auth server added");
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *ruleset, FILE *file, const char *filename, int *linenum)
{
	char		line[MAX_BUF],
			*p1,
			*p2;
	int		opcode;

	debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;
			
			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);
			
			switch (opcode) {
				case oFirewallRule:
					_parse_firewall_rule(ruleset, p2);
					break;

				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(const char *ruleset, char *leftover)
{
	int i;
	t_firewall_target target = TARGET_REJECT; /**< firewall target */
	int all_nums = 1; /**< If 0, port contained non-numerics */
	int finished = 0; /**< reached end of line */
	char *token = NULL; /**< First word */
	char *port = NULL; /**< port to open/block */
	char *protocol = NULL; /**< protocol to block, tcp/udp/icmp */
	char *mask = NULL; /**< Netmask */
	char *other_kw = NULL; /**< other key word */
	t_firewall_ruleset *tmpr;
	t_firewall_ruleset *tmpr2;
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;

	debug(LOG_DEBUG, "leftover: %s", leftover);

	/* lower case */
	for (i = 0; *(leftover + i) != '\0'
			&& (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++);
	
	token = leftover;
	TO_NEXT_WORD(leftover, finished);
	
	/* Parse token */
	if (!strcasecmp(token, "block") || finished) {
		target = TARGET_REJECT;
	} else if (!strcasecmp(token, "drop")) {
		target = TARGET_DROP;
	} else if (!strcasecmp(token, "allow")) {
		target = TARGET_ACCEPT;
	} else if (!strcasecmp(token, "log")) {
		target = TARGET_LOG;
	} else if (!strcasecmp(token, "ulog")) {
		target = TARGET_ULOG;
	} else {
		debug(LOG_ERR, "Invalid rule type %s, expecting "
				"\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
		return -1;
	}

	/* Parse the remainder */
	/* Get the protocol */
	if (strncmp(leftover, "tcp", 3) == 0
			|| strncmp(leftover, "udp", 3) == 0
			|| strncmp(leftover, "icmp", 4) == 0) {
		protocol = leftover;
		TO_NEXT_WORD(leftover, finished);
	}

	/* should be exactly "port" */
	if (strncmp(leftover, "port", 4) == 0) {
		TO_NEXT_WORD(leftover, finished);
		/* Get port now */
		port = leftover;
		TO_NEXT_WORD(leftover, finished);
		for (i = 0; *(port + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(port + i)))
				all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid port %s", port);
			return -3; /*< Fail */
		}
	}

	/* Now, further stuff is optional */
	if (!finished) {
		/* should be exactly "to" */
		other_kw = leftover;
		TO_NEXT_WORD(leftover, finished);
		if (strcmp(other_kw, "to") || finished) {
			debug(LOG_ERR, "Invalid or unexpected keyword %s, "
					"expecting \"to\"", other_kw);
			return -4; /*< Fail */
		}

		/* Get port now */
		mask = leftover;
		TO_NEXT_WORD(leftover, finished);
		all_nums = 1;
		for (i = 0; *(mask + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(mask + i)) && (*(mask + i) != '.')
					&& (*(mask + i) != '/'))
				all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid mask %s", mask);
			return -3; /*< Fail */
		}
	}

	/* Generate rule record */
	tmp = safe_malloc(sizeof(t_firewall_rule));
	memset((void *)tmp, 0, sizeof(t_firewall_rule));
	tmp->target = target;
	if (protocol != NULL)
		tmp->protocol = safe_strdup(protocol);
	if (port != NULL)
		tmp->port = safe_strdup(port);
	if (mask == NULL)
		tmp->mask = safe_strdup("0.0.0.0/0");
	else
		tmp->mask = safe_strdup(mask);

	debug(LOG_DEBUG, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);
	
	/* Append the rule record */
	if (config.rulesets == NULL) {
		config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
		memset(config.rulesets, 0, sizeof(t_firewall_ruleset));
		config.rulesets->name = safe_strdup(ruleset);
		tmpr = config.rulesets;
	} else {
		tmpr2 = tmpr = config.rulesets;
		while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
			tmpr2 = tmpr;
			tmpr = tmpr->next;
		}
		if (tmpr == NULL) {
			/* Rule did not exist */
			tmpr = safe_malloc(sizeof(t_firewall_ruleset));
			memset(tmpr, 0, sizeof(t_firewall_ruleset));
			tmpr->name = safe_strdup(ruleset);
			tmpr2->next = tmpr;
		}
	}

	/* At this point, tmpr == current ruleset */
	if (tmpr->rules == NULL) {
		/* No rules... */
		tmpr->rules = tmp;
	} else {
		tmp2 = tmpr->rules;
		while (tmp2->next != NULL)
			tmp2 = tmp2->next;
		tmp2->next = tmp;
	}
	
	return 1;
}

t_firewall_rule *
get_ruleset(const char *ruleset)
{
	t_firewall_ruleset	*tmp;

	for (tmp = config.rulesets; tmp != NULL
			&& strcmp(tmp->name, ruleset) != 0; tmp = tmp->next);

	if (tmp == NULL)
		return NULL;

	return(tmp->rules);
}

/**
@param filename Full path of the configuration file to be read 
*/
void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value, len;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Could not open configuration file '%s', "
				"exiting...", filename);
		exit(1);
	}

	while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = line;

		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, ' '))) {
			p1[0] = '\0';
		} else if ((p1 = strchr(s, '\t'))) {
			p1[0] = '\0';
		}

		if (p1) {
			p1++;

			// Trim leading spaces
			len = strlen(p1);
			while (*p1 && len) {
				if (*p1 == ' ')
					p1++;
				else
					break;
				len = strlen(p1);
			}


			if ((p2 = strchr(p1, ' '))) {
				p2[0] = '\0';
			} else if ((p2 = strstr(p1, "\r\n"))) {
				p2[0] = '\0';
			} else if ((p2 = strchr(p1, '\n'))) {
				p2[0] = '\0';
			}
		}

		if (p1 && p1[0] != '\0') {
			/* Strip trailing spaces */

			if ((strncmp(s, "#", 1)) != 0) {
				debug(LOG_DEBUG, "Parsing token: %s, "
						"value: %s", s, p1);
				opcode = config_parse_token(s, filename, linenum);

				switch(opcode) {
				case oDaemon:
					if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
						config.daemon = value;
					}
					break;
				case oExternalInterface:
					config.external_interface = safe_strdup(p1);
					break;
				case oGatewayID:
					config.gw_id = safe_strdup(p1);
					break;
				case oGatewayInterface:
					config.gw_interface = safe_strdup(p1);
					break;
				case oGatewayAddress:
					config.gw_address = safe_strdup(p1);
					break;
				case oGatewayPort:
					sscanf(p1, "%d", &config.gw_port);
					break;
				case oAuthServer:
					parse_auth_server(fd, filename,
							&linenum);
					break;
				case oFirewallRuleSet:
					parse_firewall_ruleset(p1, fd, filename, &linenum);
					break;
				case oTrustedMACList:
					parse_trusted_mac_list(p1);
					break;
				case oHTTPDName:
					config.httpdname = safe_strdup(p1);
					break;
				case oHTTPDMaxConn:
					sscanf(p1, "%d", &config.httpdmaxconn);
					break;
				case oHTTPDRealm:
					config.httpdrealm = safe_strdup(p1);
					break;
				case oHTTPDUsername:
					config.httpdusername = safe_strdup(p1);
					break;
				case oHTTPDPassword:
					config.httpdpassword = safe_strdup(p1);
					break;
				case oBadOption:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				case oCheckInterval:
					sscanf(p1, "%d", &config.checkinterval);
					break;
				case oWdctlSocket:
					free(config.wdctl_sock);
					config.wdctl_sock = safe_strdup(p1);
					break;
				case oClientTimeout:
					sscanf(p1, "%d", &config.clienttimeout);
					break;
				case oSyslogFacility:
					sscanf(p1, "%d", &config.syslog_facility);
					break;
				case oHtmlMessageFile:
					config.htmlmsgfile = safe_strdup(p1);
					break;
				case oProxyPort:
					sscanf(p1, "%d", &config.proxy_port);
					break;

				}
			}
		}
	}

	if (config.httpdusername && !config.httpdpassword) {
		debug(LOG_ERR, "HTTPDUserName requires a HTTPDPassword to be set.");
		exit(-1);
	}

	fclose(fd);
}

void smartwifi_config_save(const char *buf)
{
    FILE *f = NULL;

    if(NULL == (f = fopen(SMARTWIFI_CONFIGFILE, "w"))) {
        debug(LOG_ERR, "Fail open file to write: %s", SMARTWIFI_CONFIGFILE);
        return;
    }

    if(fwrite(buf, 1, strlen(buf), f) != strlen(buf)) {
        debug(LOG_ERR, "Fail write file: %s", SMARTWIFI_CONFIGFILE);
        fclose(f);
        return;
    }

    fclose(f);
    return;
}

int smartwifi_config_parse(const char *buf)
{
    int i;
    cJSON *root = NULL;
    cJSON *obj_services = NULL; /*for services*/
    cJSON *obj_servers = NULL;  /*for servers*/
    cJSON *obj2 = NULL;
    cJSON *item = NULL;
    cJSON *arr = NULL;

    t_platform_serv *new_platform, *tmp_platform;
    t_auth_serv     *new_auth, *tmp_auth;
    t_portal_serv   *new_portal, *tmp_portal;

    if(NULL == (root = cJSON_Parse(buf))) {
        return -1;
    }
    if(NULL == (obj_services = cJSON_GetObjectItem(root, "services"))) {
        cJSON_Delete(root);
        return -1;
    }

    if(NULL == (item = cJSON_GetObjectItem(obj_services, "account"))) {
        cJSON_Delete(root);
        return -1;
    }
    if(config.account) free(config.account);
    config.account = safe_strdup(item->valuestring);

    if(NULL == (item = cJSON_GetObjectItem(obj_services, "device_id"))) {
        cJSON_Delete(root);
        return -1;
    }
    if(config.device_id) free(config.device_id);
    config.device_id = safe_strdup(item->valuestring);


    if(NULL == (item = cJSON_GetObjectItem(obj_services, "active_date"))) {
        cJSON_Delete(root);
        return -1;
    }
    if(config.active_date) free(config.active_date);
    config.active_date = safe_strdup(item->valuestring);

    if(NULL == (obj_servers = cJSON_GetObjectItem(obj_services, "servers"))) {
        cJSON_Delete(root);
        return -1;
    }

    /*** platforms ***/
    if(NULL == (arr = cJSON_GetObjectItem(obj_servers, "platforms"))) {
        cJSON_Delete(root);
        return -1;
    }
    for(i = 0; i < cJSON_GetArraySize(arr); i++) {
        if(NULL != (obj2 = cJSON_GetArrayItem(arr, i)) && obj2->type == cJSON_Object) {
            new_platform = safe_malloc(sizeof(t_platform_serv));
            memset(new_platform, 0, sizeof(t_platform_serv));

            if(NULL != (item = cJSON_GetObjectItem(obj2, "hostname"))) {
                new_platform->platformserv_hostname = safe_strdup(item->valuestring);
            } else {
                free(new_platform);
                continue;
            }
            new_platform->platformserv_path = safe_strdup(DEFAULT_AUTHSERVPATH);
            if(NULL != (item = cJSON_GetObjectItem(obj2, "path"))) {
                new_platform->platformserv_path = safe_strdup(item->valuestring);
            }
            new_platform->platformserv_use_ssl = DEFAULT_AUTHSERVSSLAVAILABLE;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "ssl_available"))) {
                new_platform->platformserv_use_ssl = parse_boolean_value(item->valuestring);
                if(new_platform->platformserv_use_ssl < 0)
                    new_platform->platformserv_use_ssl = 0;
            }
            new_platform->platformserv_ssl_port = DEFAULT_AUTHSERVSSLPORT;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "ssl_port"))) {
                new_platform->platformserv_ssl_port = atoi(item->valuestring);   
            }
            new_platform->platformserv_http_port = DEFAULT_AUTHSERVPORT;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "http_port"))) {
                new_platform->platformserv_http_port = atoi(item->valuestring);   
            }
            if(config.platform_servers == NULL) {
                config.platform_servers = new_platform;
            } else {
                for(tmp_platform = config.platform_servers; tmp_platform->next != NULL; tmp_platform = tmp_platform->next);
                tmp_platform->next = new_platform;
            }
            debug(LOG_DEBUG, "Platform server added");
        }
    }

    /*** auths ***/
    if(NULL == (arr = cJSON_GetObjectItem(obj_servers, "auths"))) {
        cJSON_Delete(root);
        return -1;
    }
    for(i = 0; i < cJSON_GetArraySize(arr); i++) {
        if(NULL != (obj2 = cJSON_GetArrayItem(arr, i)) && obj2->type == cJSON_Object) {
            new_auth = safe_malloc(sizeof(t_auth_serv));
            memset(new_auth, 0, sizeof(t_auth_serv));

            if(NULL != (item = cJSON_GetObjectItem(obj2, "hostname"))) {
                new_auth->authserv_hostname = safe_strdup(item->valuestring);
            } else {
                free(new_auth);
                continue;
            }
            new_auth->authserv_path = safe_strdup(DEFAULT_AUTHSERVPATH);
            if(NULL != (item = cJSON_GetObjectItem(obj2, "path"))) {
                new_auth->authserv_path = safe_strdup(item->valuestring);
            }
            new_auth->authserv_use_ssl = DEFAULT_AUTHSERVSSLAVAILABLE;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "ssl_available"))) {
                new_auth->authserv_use_ssl = parse_boolean_value(item->valuestring);
                if(new_auth->authserv_use_ssl< 0)
                    new_auth->authserv_use_ssl = 0;
            }
            new_auth->authserv_ssl_port = DEFAULT_AUTHSERVSSLPORT;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "ssl_port"))) {
                new_auth->authserv_ssl_port = atoi(item->valuestring);   
            }
            new_auth->authserv_http_port = DEFAULT_AUTHSERVPORT;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "http_port"))) {
                new_auth->authserv_http_port = atoi(item->valuestring);   
            }

            new_auth->authserv_login_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
            new_auth->authserv_portal_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
            new_auth->authserv_msg_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
            new_auth->authserv_ping_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
            new_auth->authserv_auth_script_path_fragment = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);

            if(config.auth_servers == NULL) {
                config.auth_servers = new_auth;
            } else {
                for(tmp_auth = config.auth_servers; tmp_auth->next != NULL; tmp_auth = tmp_auth->next);
                tmp_auth->next = new_auth;
            }
            debug(LOG_DEBUG, "Auth server added");
        }
    }

    /*** portals ***/
    if(NULL == (arr = cJSON_GetObjectItem(obj_servers, "portals"))) {
        cJSON_Delete(root);
        return -1;
    }
    for(i = 0; i < cJSON_GetArraySize(arr); i++) {
        if(NULL != (obj2 = cJSON_GetArrayItem(arr, i)) && obj2->type == cJSON_Object) {
            new_portal = safe_malloc(sizeof(t_portal_serv));
            memset(new_portal, 0, sizeof(t_portal_serv));

            if(NULL != (item = cJSON_GetObjectItem(obj2, "hostname"))) {
                new_portal->portalserv_hostname = safe_strdup(item->valuestring);
            } else {
                free(new_portal);
                continue;
            }
            new_portal->portalserv_path = safe_strdup(DEFAULT_AUTHSERVPATH);
            if(NULL != (item = cJSON_GetObjectItem(obj2, "path"))) {
                new_portal->portalserv_path = safe_strdup(item->valuestring);
            }
            new_portal->portalserv_use_ssl = DEFAULT_AUTHSERVSSLAVAILABLE;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "ssl_available"))) {
                new_portal->portalserv_use_ssl = parse_boolean_value(item->valuestring);
                if(new_portal->portalserv_use_ssl < 0)
                    new_portal->portalserv_use_ssl = 0;
            }
            new_portal->portalserv_ssl_port = DEFAULT_AUTHSERVSSLPORT;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "ssl_port"))) {
                new_portal->portalserv_ssl_port = atoi(item->valuestring);   
            }
            new_portal->portalserv_http_port = DEFAULT_AUTHSERVPORT;
            if(NULL != (item = cJSON_GetObjectItem(obj2, "http_port"))) {
                new_portal->portalserv_http_port = atoi(item->valuestring);   
            }
            if(config.portal_servers == NULL) {
                config.portal_servers = new_portal;
            } else {
                for(tmp_portal = config.portal_servers; tmp_portal->next != NULL; tmp_portal = tmp_portal->next);
                tmp_portal->next = new_portal;
            }
            debug(LOG_DEBUG, "Portal server added");
        }
    }

    cJSON_Delete(root);
    return 0;
}

int smartwifi_config_read(const char *filename, int (*parse_cb)(const char *buf))
{
    FILE *fp;
    int ret;
    struct stat sb;
    char *buf = NULL;
    char  buf_static[8192] = {0};
    char *buf_dyn = NULL;
    size_t n, offset;

    if(-1 == stat(filename, &sb)) {
        debug(LOG_ERR, "Fail in stat(%s).", filename);
        return -1;
    }

    if(sb.st_size < sizeof(buf_static)) {
        buf = buf_static;
    } else {
        buf_dyn = (char *)safe_malloc(sb.st_size + 1);
        memset(buf_dyn, 0, sb.st_size + 1);
        buf = buf_dyn;
    }

    if(NULL == (fp = fopen(filename, "r"))) {
        debug(LOG_ERR, "Fail open %s.", filename);
        if(buf == buf_dyn)
            free(buf_dyn);
        return -1;
    }

    offset = 0;
    while(0 != (n = fread(buf + offset, 1, sb.st_size - offset, fp)))
    {
        offset += n;
        if(0 != feof(fp))
            break;
    }

    if(0 != ferror(fp)) {
        debug(LOG_ERR, "ferror in read %s", filename);
        if(buf == buf_dyn)
            free(buf_dyn);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    ret = parse_cb(buf);

    if(buf == buf_dyn)
        free(buf_dyn);

    return ret;
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "yes") == 0) {
		return 1;
	}
	if (strcasecmp(line, "no") == 0) {
		return 0;
	}
	if (strcmp(line, "1") == 0) {
		return 1;
	}
	if (strcmp(line, "0") == 0) {
		return 0;
	}

	return -1;
}

void parse_trusted_mac_list(const char *ptr) {
	char *ptrcopy = NULL;
	char *possiblemac = NULL;
	char *mac = NULL;
	t_trusted_mac *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	mac = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", "))) {
		if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
			/* Copy mac to the list */

			debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

			if (config.trustedmaclist == NULL) {
				config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
				config.trustedmaclist->mac = safe_strdup(mac);
				config.trustedmaclist->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config.trustedmaclist; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_trusted_mac));
				p = p->next;
				p->mac = safe_strdup(mac);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(mac);

}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");
	config_notnull(config.platform_servers, "PlatformServer");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv *
get_auth_server(void)
{

	/* This is as good as atomic */
	return config.auth_servers;
}

t_portal_serv * get_portal_server(void)
{
    return config.portal_servers;
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv *bad_server)
{
	t_auth_serv	*tmp;

	if (config.auth_servers == bad_server && bad_server->next != NULL) {
		/* Go to the last */
		for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next);
		/* Set bad server as last */
		tmp->next = bad_server;
		/* Remove bad server from start of list */
		config.auth_servers = bad_server->next;
		/* Set the next pointe to NULL in the last element */
		bad_server->next = NULL;
	}

}

int smartwifi_urls_parse(const char *buf)
{
    int i;
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *arr = NULL;

    t_white_url *new, *tmp;

    if(NULL == (root = cJSON_Parse(buf))) {
        debug(LOG_ERR, "Error parse json");
        return -1;
    }

    if(NULL == (arr = cJSON_GetObjectItem(root, "white_urls")) || cJSON_Array != arr->type) {
        cJSON_Delete(root);
        return -1;
    }

    for(i = 0; i < cJSON_GetArraySize(arr); i++) {
        if(NULL != (item = cJSON_GetArrayItem(arr, i))) {
            new = safe_malloc(sizeof(t_white_url));
            memset(new, 0, sizeof(t_white_url));
            new->url = safe_strdup(item->valuestring);

            if(config.white_urls == NULL) {
                config.white_urls = new;
            } else {
                for(tmp = config.white_urls; tmp->next != NULL; tmp = tmp->next);
                tmp->next = new;
            }
            debug(LOG_DEBUG, "White url added: %s", new->url);
        }
    }

    cJSON_Delete(root);
    return 0;
}
