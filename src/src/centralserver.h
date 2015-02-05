#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

#include "auth.h"

/** @brief Ask the central server to login a client */
#define REQUEST_TYPE_LOGIN     "login"
/** @brief Notify the the central server of a client logout */
#define REQUEST_TYPE_LOGOUT    "logout"
/** @brief Update the central server's traffic counters */
#define REQUEST_TYPE_COUNTERS  "counters"

/** @brief Sent when the user's token is denied by the central server */
#define GATEWAY_MESSAGE_DENIED     "denied"
/** @brief Sent when the user's token is accepted, but user is on probation  */
#define GATEWAY_MESSAGE_ACTIVATE_ACCOUNT     "activate"
/** @brief  Sent when the user's token is denied by the central server because the probation period is over */
#define GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED     "failed_validation"
/** @brief Sent after the user performed a manual log-out on the gateway  */
#define GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT     "logged-out"

/** @brief Initiates a transaction with the auth server */
t_authcode auth_server_request(t_authresponse *authresponse,
			const char *request_type,
			const char *ip,
			const char *mac,
			const char *token,
			unsigned long long int incoming,
			unsigned long long int outgoing);

t_authcode auth_server_taskresult(t_authresponse *authresponse, const char *dev_id, const char *task_id, const char *result, const char *message);

/** @brief Tries really hard to connect to an auth server.  Returns a connected file descriptor or -1 on error */
int connect_auth_server();

/** @brief Helper function called by connect_auth_server() to do the actual work including recursion - DO NOT CALL DIRECTLY */
int _connect_auth_server(int level);

#endif /* _CENTRALSERVER_H_ */
