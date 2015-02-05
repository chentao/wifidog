#ifndef _FIREWALL_H_
#define _FIREWALL_H_

int icmp_fd;

/** Used by fw_iptables.c */
typedef enum _t_fw_marks {
    FW_MARK_PROBATION = 1, /**< @brief The client is in probation period and must be authenticated 
			    @todo: VERIFY THAT THIS IS ACCURATE*/
    FW_MARK_KNOWN = 2,  /**< @brief The client is known to the firewall */ 
    FW_MARK_LOCKED = 254 /**< @brief The client has been locked out */
} t_fw_marks;

/** @brief Initialize the firewall */
int fw_init(void);

/** @brief Clears the authservers list */
void fw_clear_authservers(void);

/** @brief Sets the authservers list */
void fw_set_authservers(void);

/** @brief Destroy the firewall */
int fw_destroy(void);

int fw_allow_to_ip(const char *ip);

/** @brief Allow a user through the firewall*/
int fw_allow(const char *ip, const char *mac, int profile);

/** @brief Deny a client access through the firewall*/
int fw_deny(const char *ip, const char *mac, int profile);

/** @brief Refreshes the entire client list */
void fw_sync_with_authserver(void);

/** @brief Get an IP's MAC address from the ARP cache.*/
char *arp_get(const char *req_ip);

/** @brief ICMP Ping an IP */
void icmp_ping(const char *host);

/** @brief cheap random */
unsigned short rand16(void);

#endif /* _FIREWALL_H_ */
