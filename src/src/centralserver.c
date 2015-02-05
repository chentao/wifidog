#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "firewall.h"
#include "http_parser.h"
#include "../config.h"
#include "task.h"

extern pthread_mutex_t	config_mutex;
extern pthread_mutex_t	task_list_mutex;

/** Initiates a transaction with the auth server, either to authenticate or to
 * update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/
t_authcode
auth_server_request(t_authresponse *authresponse, const char *request_type, const char *ip, const char *mac, const char *token, unsigned long long int incoming, unsigned long long int outgoing)
{
	int sockfd;
	ssize_t	numbytes;
	size_t totalbytes;
	char buf[MAX_BUF];
	char *tmp;
        char *safe_token;
	int done, nfds;
	fd_set			readfds;
	struct timeval		timeout;
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server();
	
	/* Blanket default is error. */
	authresponse->authcode = AUTH_ERROR;
	
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/* Could not connect to any auth server */
		return (AUTH_ERROR);
	}

	/**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
	memset(buf, 0, sizeof(buf));
        safe_token=httpdUrlEncode(token);
	snprintf(buf, (sizeof(buf) - 1),
		"GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&gw_id=%s HTTP/1.0\r\n"
		"User-Agent: SmartWiFi %s\r\n"
		"Host: %s\r\n"
		"\r\n",
		auth_server->authserv_path,
		auth_server->authserv_auth_script_path_fragment,
		request_type,
		ip,
		mac,
		safe_token,
		incoming,
		outgoing,
                config_get_config()->gw_id,
		VERSION,
		auth_server->authserv_hostname
	);

        free(safe_token);

	debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
	send(sockfd, buf, strlen(buf), 0);

	debug(LOG_DEBUG, "Reading response");
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return (AUTH_ERROR);
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);
	
	if ((tmp = strstr(buf, "Auth: "))) {
		if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
			debug(LOG_INFO, "Auth server returned authentication code %d", authresponse->authcode);
			return(authresponse->authcode);
		} else {
			debug(LOG_WARNING, "Auth server did not return expected authentication code");
			return(AUTH_ERROR);
		}
	}
	else {
		return(AUTH_ERROR);
	}

	/* XXX Never reached because of the above if()/else pair. */
	return(AUTH_ERROR);
}

int register_response_body_callback(http_parser *parser, const char *at, size_t length)
{
    int ret;
	LOCK_CONFIG();
    ret = smartwifi_config_parse(at);
    UNLOCK_CONFIG();

    if(ret == 0) {
        smartwifi_config_save(at);
    }

    return ret;
}

t_authcode auth_server_register(t_authresponse *authresponse, const char *dev_id, const char *mac)
{
    int sockfd;
    ssize_t numbytes;
    size_t totalbytes;
    char buf[MAX_BUF];
    char *tmp; char *safe_dev_id;
    int done, nfds;
    fd_set readfds;
    struct timeval timeout;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();

    http_parser_settings settings;
    http_parser *parser = NULL;
    ssize_t nparsed;

    authresponse->authcode = AUTH_ERROR;

    sockfd = connect_auth_server();
    if(sockfd == -1) {
        return AUTH_ERROR;
    }

    memset(buf, 0, sizeof(buf));
    safe_dev_id = httpdUrlEncode(dev_id);
    snprintf(buf, sizeof(buf) - 1,
            "GET %s%sdev_id=%s&mac=%s&stage=active HTTP/1.0\r\n"
            "User-Agent: SmartWiFi %s\r\n"
            "Host: %s\r\n"
            "\r\n",
            auth_server->authserv_path,
            "register?",
            safe_dev_id,
            mac,
            VERSION,
            auth_server->authserv_hostname
    );

    free(safe_dev_id);

    debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
    send(sockfd, buf, strlen(buf), 0);

    debug(LOG_DEBUG, "Reading respons");
    numbytes = totalbytes = 0;
    done = 0;

    do {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);
        
        if(nfds > 0) {
            numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
            if(numbytes < 0) {
                debug(LOG_ERR, "An error occurred while reading form auth server: %s", strerror(errno));
                close(sockfd);
                return AUTH_ERROR;
            }
            else if(numbytes == 0) {
                done = 1;
            }
            else {
                totalbytes += numbytes;
                debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
            }
        }
        else if(nfds == 0) {
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            close(sockfd);
            return AUTH_ERROR;
        }
        else if(nfds < 0) {
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            close(sockfd);
            return AUTH_ERROR;
        }
    } while (!done);

    close(sockfd);

    buf[totalbytes] = '\0';
    debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);

    settings.on_body = register_response_body_callback;
    parser = safe_malloc(sizeof(http_parser));
    http_parser_init(parser, HTTP_RESPONSE);

    nparsed = http_parser_execute(parser, &settings, buf, totalbytes);

    if(parser->upgrade) {
        debug(LOG_INFO, "Parse register response body success. upgrade.");
        authresponse->authcode = AUTH_ALLOWED;
    } else if(nparsed != totalbytes) {
        debug(LOG_ERR, "Fail parse register response body.");
        authresponse->authcode = AUTH_ERROR;
    } else {
        debug(LOG_INFO, "Parse register response body success.");
        authresponse->authcode = AUTH_ALLOWED;
    }

    return authresponse->authcode;
}

int taskrequest_response_body_callback(http_parser *parser, const char *at, size_t length)
{
    int ret;
	LOCK_TASK_LIST();
    ret = task_response_parse(at);
    UNLOCK_TASK_LIST();

    return ret;
}

int taskresult_response_body_callback(http_parser *parser, const char *at, size_t length)
{
	if (NULL != strstr(at, "OK")) {
        return 0;
    } else {
        return -1;
    }
}

t_authcode auth_server_taskresult(t_authresponse *authresponse, const char *dev_id, const char *task_id, const char *result, const char *message)
{
    int sockfd;
    ssize_t numbytes;
    size_t totalbytes;
    char buf[MAX_BUF];
    char *tmp; char *safe_dev_id;
    int done, nfds;
    fd_set readfds;
    struct timeval timeout;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();

    http_parser_settings settings;
    http_parser *parser = NULL;
    ssize_t nparsed;

    authresponse->authcode = AUTH_ERROR;

    sockfd = connect_auth_server();
    if(sockfd == -1) {
        return AUTH_ERROR;
    }

    memset(buf, 0, sizeof(buf));
    safe_dev_id = httpdUrlEncode(dev_id);
    snprintf(buf, sizeof(buf) - 1,
            "GET %s%sdev_id=%s&task_id=%s&result=%s&message=%s HTTP/1.0\r\n"
            "User-Agent: SmartWiFi %s\r\n"
            "Host: %s\r\n"
            "\r\n",
            auth_server->authserv_path,
            "taskresult?",
            safe_dev_id,
            task_id,
            result,
            message!=NULL?message:"",
            VERSION,
            auth_server->authserv_hostname
    );

    free(safe_dev_id);

    debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
    send(sockfd, buf, strlen(buf), 0);

    debug(LOG_DEBUG, "Reading respons");
    numbytes = totalbytes = 0;
    done = 0;

    do {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);
        
        if(nfds > 0) {
            numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
            if(numbytes < 0) {
                debug(LOG_ERR, "An error occurred while reading form auth server: %s", strerror(errno));
                close(sockfd);
                return AUTH_ERROR;
            }
            else if(numbytes == 0) {
                done = 1;
            }
            else {
                totalbytes += numbytes;
                debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
            }
        }
        else if(nfds == 0) {
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            close(sockfd);
            return AUTH_ERROR;
        }
        else if(nfds < 0) {
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            close(sockfd);
            return AUTH_ERROR;
        }
    } while (!done);

    close(sockfd);

    buf[totalbytes] = '\0';
    debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);

    settings.on_body = taskresult_response_body_callback;
    parser = safe_malloc(sizeof(http_parser));
    http_parser_init(parser, HTTP_RESPONSE);

    nparsed = http_parser_execute(parser, &settings, buf, totalbytes);

    if(parser->upgrade) {
        debug(LOG_INFO, "Parse taskresult response body success. upgrade.");
        authresponse->authcode = AUTH_ALLOWED;  /*OK*/
    } else if(nparsed != totalbytes) {
        debug(LOG_ERR, "Fail parse taskresult response body.");
        authresponse->authcode = AUTH_ERROR;    /*FAIL*/
    } else {
        debug(LOG_INFO, "Parse taskresult response body success.");
        authresponse->authcode = AUTH_ALLOWED;  /*OK*/
    }
    free(parser);

    return authresponse->authcode;
}

t_authcode auth_server_taskrequest(t_authresponse *authresponse, const char *dev_id)
{
    int sockfd;
    ssize_t numbytes;
    size_t totalbytes;
    char buf[MAX_BUF];
    char *tmp; char *safe_dev_id;
    int done, nfds;
    fd_set readfds;
    struct timeval timeout;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();

    http_parser_settings settings;
    http_parser *parser = NULL;
    ssize_t nparsed;

    authresponse->authcode = AUTH_ERROR;

    sockfd = connect_auth_server();
    if(sockfd == -1) {
        return AUTH_ERROR;
    }

    memset(buf, 0, sizeof(buf));
    safe_dev_id = httpdUrlEncode(dev_id);
    snprintf(buf, sizeof(buf) - 1,
            "GET %s%sdev_id=%s HTTP/1.0\r\n"
            "User-Agent: SmartWiFi %s\r\n"
            "Host: %s\r\n"
            "\r\n",
            auth_server->authserv_path,
            "taskrequest?",
            safe_dev_id,
            VERSION,
            auth_server->authserv_hostname
    );

    free(safe_dev_id);

    debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
    send(sockfd, buf, strlen(buf), 0);

    debug(LOG_DEBUG, "Reading respons");
    numbytes = totalbytes = 0;
    done = 0;

    do {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);
        
        if(nfds > 0) {
            numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
            if(numbytes < 0) {
                debug(LOG_ERR, "An error occurred while reading form auth server: %s", strerror(errno));
                close(sockfd);
                return AUTH_ERROR;
            }
            else if(numbytes == 0) {
                done = 1;
            }
            else {
                totalbytes += numbytes;
                debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
            }
        }
        else if(nfds == 0) {
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            close(sockfd);
            return AUTH_ERROR;
        }
        else if(nfds < 0) {
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            close(sockfd);
            return AUTH_ERROR;
        }
    } while (!done);

    close(sockfd);

    buf[totalbytes] = '\0';
    debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);

    settings.on_body = taskrequest_response_body_callback;
    parser = safe_malloc(sizeof(http_parser));
    http_parser_init(parser, HTTP_RESPONSE);

    nparsed = http_parser_execute(parser, &settings, buf, totalbytes);

    if(parser->upgrade) {
        debug(LOG_INFO, "Parse taskrequest response body success. upgrade.");
        authresponse->authcode = AUTH_ALLOWED;
    } else if(nparsed != totalbytes) {
        debug(LOG_ERR, "Fail parse taskrequest response body.");
        authresponse->authcode = AUTH_ERROR;
    } else {
        debug(LOG_INFO, "Parse taskrequest response body success.");
        authresponse->authcode = AUTH_ALLOWED;
    }
    free(parser);

    return authresponse->authcode;
}

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int connect_auth_server() {
	int sockfd;

	LOCK_CONFIG();
	sockfd = _connect_auth_server(0);
	UNLOCK_CONFIG();

	if (sockfd == -1) {
		debug(LOG_ERR, "Failed to connect to any of the auth servers");
		mark_auth_offline();
	}
	else {
		debug(LOG_DEBUG, "Connected to auth server");
		mark_auth_online();
	}
	return (sockfd);
}

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int _connect_auth_server(int level) {
	s_config *config = config_get_config();
	t_auth_serv *auth_server = NULL;
	struct in_addr *h_addr;
	int num_servers = 0;
	char * hostname = NULL;
	char * popular_servers[] = {
		  "www.baidu.com",
		  "www.qq.com",
		  NULL
	};
	char ** popularserver;
	char * ip;
	struct sockaddr_in their_addr;
	int sockfd;

    char * hostname2 = NULL; 
	struct in_addr *h_addr2;
	char * ip2;

	/* XXX level starts out at 0 and gets incremented by every iterations. */
	level++;

	/*
	 * Let's calculate the number of servers we have
	 */
	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
		num_servers++;
	}
	debug(LOG_DEBUG, "Level %d: Calculated %d auth servers in list", level, num_servers);

	if (level > num_servers) {
		/*
		 * We've called ourselves too many times
		 * This means we've cycled through all the servers in the server list
		 * at least once and none are accessible
		 */
		return (-1);
	}

	/*
	 * Let's resolve the hostname of the top server to an IP address
	 */
	auth_server = config->auth_servers;
	hostname = auth_server->authserv_hostname;
	debug(LOG_DEBUG, "Level %d: Resolving auth server [%s]", level, hostname);
	h_addr = wd_gethostbyname(hostname);
	if (!h_addr) {
		/*
		 * DNS resolving it failed
		 *
		 * Can we resolve any of the popular servers ?
		 */
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] failed", level, hostname);

		for (popularserver = popular_servers; *popularserver; popularserver++) {
			debug(LOG_DEBUG, "Level %d: Resolving popular server [%s]", level, *popularserver);
			h_addr = wd_gethostbyname(*popularserver);
			if (h_addr) {
				debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] succeeded = [%s]", level, *popularserver, inet_ntoa(*h_addr));
				break;
			}
			else {
				debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] failed", level, *popularserver);
			}
		}

		/* 
		 * If we got any h_addr buffer for one of the popular servers, in other
		 * words, if one of the popular servers resolved, we'll assume the DNS
		 * works, otherwise we'll deal with net connection or DNS failure.
		 */
		if (h_addr) {
			free (h_addr);
			/*
			 * Yes
			 *
			 * The auth server's DNS server is probably dead. Try the next auth server
			 */
			debug(LOG_DEBUG, "Level %d: Marking auth server [%s] as bad and trying next if possible", level, hostname);
			if (auth_server->last_ip) {
				free(auth_server->last_ip);
				auth_server->last_ip = NULL;
			}
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level);
		}
		else {
			/*
			 * No
			 *
			 * It's probably safe to assume that the internet connection is malfunctioning
			 * and nothing we can do will make it work
			 */
			mark_offline();
			debug(LOG_DEBUG, "Level %d: Failed to resolve auth server and all popular servers. "
					"The internet connection is probably down", level);
			return(-1);
		}
	}
	else {
		/*
		 * DNS resolving was successful
		 */
		ip = safe_strdup(inet_ntoa(*h_addr));
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

		if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
			/*
			 * But the IP address is different from the last one we knew
			 * Update it
			 */
			debug(LOG_DEBUG, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
			if (auth_server->last_ip) free(auth_server->last_ip);
			auth_server->last_ip = ip;

            if(config->platform_servers) {
                hostname2 = config->platform_servers->platformserv_hostname;
                h_addr2 = wd_gethostbyname(hostname2);
                if(h_addr2) {
                    ip2 = safe_strdup(inet_ntoa(*h_addr2));
                    if(config->platform_servers->last_ip) free(config->platform_servers->last_ip);
                    config->platform_servers->last_ip = ip2;
                    free(h_addr2);
                }
            }

            if(config->portal_servers) {
                hostname2 = config->portal_servers->portalserv_hostname;
                h_addr2 = wd_gethostbyname(hostname2);
                if(h_addr2) {
                    ip2 = safe_strdup(inet_ntoa(*h_addr2));
                    if(config->portal_servers->last_ip) free(config->portal_servers->last_ip);
                    config->portal_servers->last_ip = ip2;
                    free(h_addr2);
                }
            }

			/* Update firewall rules */
			fw_clear_authservers();
			fw_set_authservers();
		}
		else {
			/*
			 * IP is the same as last time
			 */
			free(ip);
		}

		/*
		 * Connect to it
		 */
		debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(auth_server->authserv_http_port);
		their_addr.sin_addr = *h_addr;
		memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
		free (h_addr);

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
			return(-1);
		}

		if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
			/*
			 * Failed to connect
			 * Mark the server as bad and try the next one
			 */
			debug(LOG_DEBUG, "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible", level, hostname, auth_server->authserv_http_port, strerror(errno));
			close(sockfd);
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level); /* Yay recursion! */
		}
		else {
			/*
			 * We have successfully connected
			 */
			debug(LOG_DEBUG, "Level %d: Successfully connected to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
			return sockfd;
		}
	}
}
