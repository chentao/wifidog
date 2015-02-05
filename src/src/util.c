#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#if defined(__NetBSD__)
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <util.h>
#endif

#ifdef __linux__
#include <netinet/in.h>
#include <net/if.h>
#endif

#include <string.h>
#include <pthread.h>
#include <netdb.h>

#include "common.h"
#include "client_list.h"
#include "safe.h"
#include "util.h"
#include "conf.h"
#include "debug.h"

#include "../config.h"

#include "uci.h"
#include "ucix.h"

static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Defined in ping_thread.c */
extern time_t started_time;

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;
extern	pthread_mutex_t	config_mutex;

/* Defined in commandline.c */
extern pid_t restart_orig_pid;

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;

long served_this_session = 0;

char *get_first_ssid()
{
    char *value = NULL;
    char *ssid = NULL;
    struct uci_element *e = NULL;
    struct uci_package *uci_wireless = NULL;
    struct uci_context *ctx = uci_alloc_context();
    if(!ctx) {
        return NULL;
    }

    uci_load(ctx, "wireless", &uci_wireless);
    if(!uci_wireless) {
        uci_free_context(ctx);
        return NULL;
    }

    uci_foreach_element(&uci_wireless->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        if(0 == strcmp(s->type, "wifi-iface")) {
            value = uci_lookup_option_string(ctx, s, "ssid");
            if(value)
                ssid = safe_strdup(value);
            break;
        }
    }

    uci_free_context(ctx);
    return ssid;
}

char *get_wan_proto()
{
    const char *value = NULL;
    char *proto = NULL;
    struct uci_context *uci_ctx;

    if(NULL != (uci_ctx = ucix_init("network"))) {
        value = ucix_get_option(uci_ctx, "network", "wan", "proto");
        if(value)
            proto = safe_strdup(value);

        ucix_cleanup(uci_ctx);
    }

    return proto;
}

char *get_wan_interface()
{
    char *proto = get_wan_proto();
    struct uci_context *ctx;
    char *value = NULL;
    char *ifname = NULL;

    if(strcmp(proto, "pppoe") == 0) {
        free(proto);
        return safe_strdup("pppoe-wan");
    } else {
        if(NULL != (ctx = ucix_init("network"))) {
            value = ucix_get_option(ctx, "network", "wan", "ifname");
            if(value)
                ifname = safe_strdup(value);

            ucix_cleanup(ctx);
        }
    }
    return ifname;
}

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(const char *cmd_line, int quiet)
{
        int pid,
            status,
            rc;

        const char *new_argv[4];
        new_argv[0] = "/bin/sh";
        new_argv[1] = "-c";
        new_argv[2] = cmd_line;
        new_argv[3] = NULL;

        pid = safe_fork();
        if (pid == 0) {    /* for the child process:         */
                /* We don't want to see any errors if quiet flag is on */
                if (quiet) close(2);
                if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
                        debug(LOG_ERR, "execvp(): %s", strerror(errno));
                } else {
                        debug(LOG_ERR, "execvp() failed");
                }
                exit(1);
        }

        /* for the parent:      */
	debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
	rc = waitpid(pid, &status, 0);
	debug(LOG_DEBUG, "Process PID %d exited", rc);

        return (WEXITSTATUS(status));
}

	struct in_addr *
wd_gethostbyname(const char *name)
{
	struct in_addr *addr = NULL;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    struct sockaddr_in *p_sin_addr;
    int ret;

	/* XXX Calling function is reponsible for free() */

	addr = safe_malloc(sizeof(*addr));

#if 0
	LOCK_GHBN();

	he = gethostbyname(name);

	if (he == NULL) {
		free(addr);
		UNLOCK_GHBN();
		return NULL;
	}

#endif

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    ret = getaddrinfo(name, NULL, &hints, &result);
    if(ret != 0) {
        debug(LOG_ERR, "Resolving name failed: %s", name);
		free(addr);
        return NULL;
    }
	mark_online();
    for(rp = result; rp != NULL; rp = rp->ai_next) {
        p_sin_addr = (struct sockaddr_in *)rp->ai_addr;
        addr->s_addr = p_sin_addr->sin_addr.s_addr;
        break; /*only get the first addr*/
    }
    freeaddrinfo(result);

#if 0
	//in_addr_temp = (struct in_addr *)he->h_addr_list[0];
	//addr->s_addr = in_addr_temp->s_addr;
	addr->s_addr = 0x3;

	UNLOCK_GHBN();
#endif

	return addr;
}

	char *
get_iface_ip(const char *ifname)
{
#if defined(__linux__)
	struct ifreq if_data;
	struct in_addr in;
	char *ip_str;
	int sockd;
	u_int32_t ip;

	/* Create a socket */
	if ((sockd = socket (AF_INET, SOCK_PACKET, htons(0x8086))) < 0) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
		return NULL;
	}

	/* Get IP of internal interface */
	strcpy (if_data.ifr_name, ifname);

	/* Get the IP address */
	if (ioctl (sockd, SIOCGIFADDR, &if_data) < 0) {
		debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
		return NULL;
	}
	memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
	in.s_addr = ip;

	ip_str = inet_ntoa(in);
	close(sockd);
	return safe_strdup(ip_str);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	char *str = NULL;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	/* XXX arbitrarily pick the first IPv4 address */
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_INET)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no IPv4 address assigned");
		goto out;
	}
	str = safe_strdup(inet_ntoa(
				((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
out:
	freeifaddrs(ifap);
	return str;
#else
	return safe_strdup("0.0.0.0");
#endif
}

	char *
get_iface_mac(const char *ifname)
{
#if defined(__linux__)
	int r, s;
	struct ifreq ifr;
	char *hwaddr, mac[13];

	strcpy(ifr.ifr_name, ifname);

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
		return NULL;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
		close(s);
		return NULL;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	close(s);
	snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X", 
			hwaddr[0] & 0xFF,
			hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF,
			hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF,
			hwaddr[5] & 0xFF
		);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[13], *str = NULL;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no link-layer address assigned");
		goto out;
	}
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	hwaddr = LLADDR(sdl);
	snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
			hwaddr[0] & 0xFF, hwaddr[1] & 0xFF,
			hwaddr[2] & 0xFF, hwaddr[3] & 0xFF,
			hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

	str = safe_strdup(mac);
out:
	freeifaddrs(ifap);
	return str;
#else
	return NULL;
#endif
}

	char *
get_ext_iface(void)
{
#ifdef __linux__
	FILE *input;
	char *device, *gw;
	int i = 1;
	int keep_detecting = 1;
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	device = (char *)malloc(16);
	gw = (char *)malloc(16);
	debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
	while(keep_detecting) {
		input = fopen("/proc/net/route", "r");
		while (!feof(input)) {
			/* XXX scanf(3) is unsafe, risks overrun */
			if ((fscanf(input, "%s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw) == 2) && strcmp(gw, "00000000") == 0) {
				free(gw);
				debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after try %d", device, i);
				return device;
			}
		}
		fclose(input);
		debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d", i, NUM_EXT_INTERFACE_DETECT_RETRY);
		/* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
		timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
		timeout.tv_nsec = 0;
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);	
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
		//for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
		if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i>NUM_EXT_INTERFACE_DETECT_RETRY) {
			keep_detecting = 0;
		}
		i++;
	}
	debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
	exit(1);
	free(device);
	free(gw);
#endif
	return NULL;
	}

	void mark_online() {
		int before;
		int after;

		before = is_online();
		time(&last_online_time);
		after = is_online();

		if (before != after) {
			debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
		}

	}

	void mark_offline() {
		int before;
		int after;

		before = is_online();
		time(&last_offline_time);
		after = is_online();

		if (before != after) {
			debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
		}

		/* If we're offline it definately means the auth server is offline */
		mark_auth_offline();

	}

	int is_online() {
		if (last_online_time == 0 || (last_offline_time - last_online_time) >= (config_get_config()->checkinterval * 2) ) {
			/* We're probably offline */
			return (0);
		}
		else {
			/* We're probably online */
			return (1);
		}
	}

	void mark_auth_online() {
		int before;
		int after;

		before = is_auth_online();
		time(&last_auth_online_time);
		after = is_auth_online();

		if (before != after) {
            leave_escape_mode();
			debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
		}

		/* If auth server is online it means we're definately online */
		mark_online();

	}

	void mark_auth_offline() {
		int before;
		int after;

		before = is_auth_online();
		time(&last_auth_offline_time);
		after = is_auth_online();

		if (before != after) {
            enter_escape_mode();
			debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
		}
	}

	int is_auth_online() {
		if (!is_online()) {
			/* If we're not online auth is definately not online :) */
			return (0);
		}
		else if (last_auth_online_time == 0 || (last_auth_offline_time - last_auth_online_time) >= (config_get_config()->checkinterval * 2) ) {
			/* Auth is  probably offline */
			return (0);
		}
		else {
			/* Auth is probably online */
			return (1);
		}
	}

	/*
	 * @return A string containing human-readable status text. MUST BE free()d by caller
	 */
	char * get_status_text() {
		char buffer[STATUS_BUF_SIZ];
		ssize_t len;
		s_config *config;
		t_auth_serv *auth_server;
		t_client	*first;
		int		count;
		unsigned long int uptime = 0;
		unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
		t_trusted_mac *p;

		len = 0;
		snprintf(buffer, (sizeof(buffer) - len), "SmartWiFi status\n\n");
		len = strlen(buffer);

		uptime = time(NULL) - started_time;
		days    = uptime / (24 * 60 * 60);
		uptime -= days * (24 * 60 * 60);
		hours   = uptime / (60 * 60);
		uptime -= hours * (60 * 60);
		minutes = uptime / 60;
		uptime -= minutes * 60;
		seconds = uptime;

		snprintf((buffer + len), (sizeof(buffer) - len), "Version: " VERSION "\n");
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "Has been restarted: ");
		len = strlen(buffer);
		if (restart_orig_pid) {
			snprintf((buffer + len), (sizeof(buffer) - len), "yes (from PID %d)\n", restart_orig_pid);
			len = strlen(buffer);
		}
		else {
			snprintf((buffer + len), (sizeof(buffer) - len), "no\n");
			len = strlen(buffer);
		}

		snprintf((buffer + len), (sizeof(buffer) - len), "Internet Connectivity: %s\n", (is_online() ? "yes" : "no"));
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "Auth server reachable: %s\n", (is_auth_online() ? "yes" : "no"));
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "Clients served this session: %lu\n\n", served_this_session);
		len = strlen(buffer);

		LOCK_CLIENT_LIST();

		first = client_get_first_client();

		if (first == NULL) {
			count = 0;
		} else {
			count = 1;
			while (first->next != NULL) {
				first = first->next;
				count++;
			}
		}

		snprintf((buffer + len), (sizeof(buffer) - len), "%d clients "
				"connected.\n", count);
		len = strlen(buffer);

		first = client_get_first_client();

		count = 0;
		while (first != NULL) {
			snprintf((buffer + len), (sizeof(buffer) - len), "\nClient %d\n", count);
			len = strlen(buffer);

			snprintf((buffer + len), (sizeof(buffer) - len), "  IP: %s MAC: %s\n", first->ip, first->mac);
			len = strlen(buffer);

			snprintf((buffer + len), (sizeof(buffer) - len), "  Token: %s\n", first->token);
			len = strlen(buffer);

			snprintf((buffer + len), (sizeof(buffer) - len), "  Downloaded: %llu\n  Uploaded: %llu\n" , first->counters.incoming, first->counters.outgoing);
			len = strlen(buffer);

			count++;
			first = first->next;
		}

		UNLOCK_CLIENT_LIST();

		config = config_get_config();

		if (config->trustedmaclist != NULL) {
			snprintf((buffer + len), (sizeof(buffer) - len), "\nTrusted MAC addresses:\n");
			len = strlen(buffer);

			for (p = config->trustedmaclist; p != NULL; p = p->next) {
				snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", p->mac);
				len = strlen(buffer);
			}
		}

		snprintf((buffer + len), (sizeof(buffer) - len), "\nAuthentication servers:\n");
		len = strlen(buffer);

		LOCK_CONFIG();

		for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
			snprintf((buffer + len), (sizeof(buffer) - len), "  Host: %s (%s)\n", auth_server->authserv_hostname, auth_server->last_ip);
			len = strlen(buffer);
		}

		UNLOCK_CONFIG();

		return safe_strdup(buffer);
	}
