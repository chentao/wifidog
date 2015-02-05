/**************************************************************************//**
*
*                  版权所有 (C), 1999-2013, 中太数据通信公司
*
* @file tc_thread.c
* @brief
* @version 初稿
* @author luosy
* @date 2015年01月23日
* @note history:
*     @note    date:      2015年01月23日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/


/*
 * 包含头文件
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "syslog.h"
#include "tc_thread.h"
#include "debug.h"

/*
 * 宏定义
 */
#define CMD_REDIRECT_VIRTUAL_ETH    "ifb0"
#define CMD_REDIRECT_BRLAN    "br-lan"
#define CMD_MAX_RATE_IN_MBIT        1000
#define MAX_CHARACTOR_ONE_LINE  (256)
#define MAX_STR_LEN     (512)
#define TC_CONFIG_PATH  "/etc/tc.conf"
/*
 * 外部变量说明
 */

/*
 * 外部函数原型说明
 */

/*
 * 全局变量
 */
static struct tc_config_info g_tc_conf = {0};
/*
 * 模块级变量
 */

/*
 * 接口声明
 */

static void show_config();

/**************************************************************************//**
* function: config_has_modified
* @brief  检查配置文件是否被修改
* @param  char *file_name,
* @return
* @retval  int
*
* @note history:
*     @note    date:      2015年01月23日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
static int config_has_modified(char *file_name)
{
    int         ret;
    struct stat file_stat;

    if(NULL == file_name) {
        debug(LOG_ERR, "TC config file not exist\n");
        return -1;
    }

    if ( -1 == (ret = lstat(file_name, &file_stat))) {
        debug(LOG_ERR, "lstat err\n");
        return -1;
    }

    if (file_stat.st_mtim.tv_sec)

    if(file_stat.st_mtim.tv_sec != g_tc_conf.last_modify_time){
        g_tc_conf.last_modify_time = file_stat.st_mtim.tv_sec;
        return 1;
    }

    return 0;
}

/**************************************************************************//**
* function: update_tc_conf_from_file
* @brief  从配置文件获取配置数据
* @param  char * pwname,
* @return
* @retval int
*
* @note history:
*     @note    date:      2015年01月23日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
int update_tc_conf_from_file(char *file_name)
{
    int i = 0;
    int j = 0;
    FILE * fp;
    int ret = 0;
    char * pStr = NULL;/*某行字符串的指针*/
    char str[MAX_CHARACTOR_ONE_LINE] = {0};
    struct in_addr addrtmp = {0};

    if(NULL == (fp = fopen(file_name,"r"))) {
        return (-1);
    }

    /* 保存上次配置用于清除配置信息 */
    memcpy(&(g_tc_conf.old_cfg), &(g_tc_conf.new_cfg), sizeof(g_tc_conf.old_cfg));

    memset(&(g_tc_conf.new_cfg), 0, sizeof(g_tc_conf.new_cfg));
    /* 获取配置类型 */
    while (0 != fgets(str, MAX_CHARACTOR_ONE_LINE, fp)) {
        if ('#' == str[0]) {
            continue;
        }

        if (NULL == (pStr = strtok(str, ":"))) {
            continue;
        }

        if (0 != strcmp(pStr, "tc type")) {
            continue;
        }

        if (NULL == (pStr = strtok(NULL, ":"))) {
            g_tc_conf.new_cfg.tc_type = 0;
        }
        g_tc_conf.new_cfg.tc_type = atoi(pStr);

        break;
    }

    switch (g_tc_conf.new_cfg.tc_type) {
    /* 获取固定ip限速 */
    case TC_TYPE_FIXED:
    {
        while (0 != fgets(str, MAX_CHARACTOR_ONE_LINE, fp)) {
            if ('#' == str[0]) {
                continue;
            }

            if (NULL == (pStr = strtok(str, ":"))) {
                continue;
            }
            if (0 == strcmp(pStr, "upload")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.fixed[i].up_value = 0;
                }
                g_tc_conf.new_cfg.fixed[i].up_value = atoi(pStr);

                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.fixed[i].up_begin_ip = 0;
                }
                if (0 == inet_aton(pStr, &addrtmp)) {
                    g_tc_conf.new_cfg.fixed[i].up_begin_ip = 0;
                }
                g_tc_conf.new_cfg.fixed[i].up_begin_ip = addrtmp.s_addr;

                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.fixed[i].up_end_ip = 0;
                }
                if (0 == inet_aton(pStr, &addrtmp)) {
                    g_tc_conf.new_cfg.fixed[i].up_end_ip = 0;
                }
                g_tc_conf.new_cfg.fixed[i].up_end_ip = addrtmp.s_addr;
                ++ i;
            } else if (0 == strcmp(pStr, "download")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.fixed[i].dn_value = 0;
                }
                g_tc_conf.new_cfg.fixed[i].dn_value = atoi(pStr);

                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.fixed[i].dn_begin_ip = 0;
                }
                if (0 == inet_aton(pStr, &addrtmp)) {
                    g_tc_conf.new_cfg.fixed[i].dn_begin_ip = 0;
                }
                g_tc_conf.new_cfg.fixed[i].dn_begin_ip = addrtmp.s_addr;

                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.fixed[i].dn_end_ip = 0;
                }
                if (0 == inet_aton(pStr, &addrtmp)) {
                    g_tc_conf.new_cfg.fixed[i].dn_end_ip = 0;
                }
                g_tc_conf.new_cfg.fixed[i].dn_end_ip = addrtmp.s_addr;
                ++ i;
            }
        }

        break;
    }

    case TC_TYPE_DYNAMIC:
    {
        /* 获取动态带宽调整参数 */
        while (0 != fgets(str, MAX_CHARACTOR_ONE_LINE, fp)) {
            if ('#' == str[0]) {
                continue;
            }

            if (NULL == (pStr = strtok(str, ":"))) {
                continue;
            }

            if (0 == strcmp(pStr, "max upload(mbit)")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.up_max = 0;
                }
                g_tc_conf.new_cfg.dynamic.up_max = atoi(pStr);
            } else if (0 == strcmp(pStr, "max download(mbit)")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.dn_max = 0;
                }
                g_tc_conf.new_cfg.dynamic.dn_max = atoi(pStr);
            } else if (0 == strcmp(pStr, "per ip upload(kbit)")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.up_per_ip = 0;
                }
                g_tc_conf.new_cfg.dynamic.up_per_ip = atoi(pStr);
            } else if (0 == strcmp(pStr, "per ip download(kbit)")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.dn_per_ip = 0;
                }
                g_tc_conf.new_cfg.dynamic.dn_per_ip = atoi(pStr);
            } else if (0 == strcmp(pStr, "up ceil(kbit)")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.upceil_per_ip = 0;
                }
                g_tc_conf.new_cfg.dynamic.upceil_per_ip = atoi(pStr);
            } else if (0 == strcmp(pStr, "down ceil(kbit)")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.dnceil_per_ip = 0;
                }
                g_tc_conf.new_cfg.dynamic.dnceil_per_ip = atoi(pStr);
            } else if (0 == strcmp(pStr, "iprange")) {
                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.begin_ip = 0;
                }
                if (0 == inet_aton(pStr, &addrtmp)) {
                    g_tc_conf.new_cfg.dynamic.begin_ip = 0;
                }
                g_tc_conf.new_cfg.dynamic.begin_ip = addrtmp.s_addr;

                if(NULL == (pStr = strtok(NULL, ":"))) {
                    g_tc_conf.new_cfg.dynamic.end_ip = 0;
                }
                if (0 == inet_aton(pStr, &addrtmp)) {
                    g_tc_conf.new_cfg.dynamic.end_ip = 0;
                }
                g_tc_conf.new_cfg.dynamic.end_ip = addrtmp.s_addr;
            }
        }

        if (0 == g_tc_conf.new_cfg.dynamic.upceil_per_ip) {
            g_tc_conf.new_cfg.dynamic.upceil_per_ip = g_tc_conf.new_cfg.dynamic.up_per_ip;
        }

        if (0 == g_tc_conf.new_cfg.dynamic.dnceil_per_ip) {
            g_tc_conf.new_cfg.dynamic.dnceil_per_ip = g_tc_conf.new_cfg.dynamic.dn_per_ip;
        }
        break;
    }

    default:
        break;
    }

    fclose(fp);

    return 0;
}

/**************************************************************************//**
* function: clean_last_tc
* @brief  清除之前的配置
* @param  struct tc_config *cfg,
* @return
* @retval void
*
* @note history:
*     @note    date:      2015年01月23日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
void clean_last_tc(struct tc_config *cfg)
{
    int i = 0;
    int ip_first = 0;
    int ip_last = 0;
    char cmd_str[MAX_STR_LEN] = {0};

    if (NULL == cfg) {
        return;
    }
    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc del dev %s root 1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc del dev %s root 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    switch(cfg->tc_type) {
    case TC_TYPE_FIXED:
    {
        for (i = 0; i < MAX_TC_INFO; i++) {
            if (0 == cfg->fixed[i].dn_begin_ip)
                continue;
            /* 为避免iptables规则重复， 这里先做一下删除操作 */
            ip_first = htonl(cfg->fixed[i].dn_begin_ip);
            ip_last = htonl(cfg->fixed[i].dn_end_ip);
            if (0 == ip_last) {
                ip_last = ip_first;
            }
            for (; ip_first <= ip_last; ++ip_first) {
                snprintf(cmd_str, sizeof(cmd_str), "iptables -t mangle -D POSTROUTING -d %d.%d.%d.%d -j MARK --set-mark %d",
                        INT_VAL_BYTE_FIRST(ip_first), INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), i+1);
                system(cmd_str);
                debug(LOG_ERR, cmd_str);
            }
        }
        break;
    }
    case TC_TYPE_DYNAMIC:
    {
        if (0 == cfg->dynamic.begin_ip)
            break;
        /* 为避免iptables规则重复， 这里先做一下删除操作 */
        ip_first = htonl(cfg->dynamic.begin_ip);
        ip_last = htonl(cfg->dynamic.end_ip);
        if (0 == ip_last) {
            ip_last = ip_first;
        }
        for (; ip_first <= ip_last; ++ip_first) {
            snprintf(cmd_str, sizeof(cmd_str), "iptables -t mangle -D POSTROUTING -d %d.%d.%d.%d -j MARK --set-mark %d",
                    INT_VAL_BYTE_FIRST(ip_first), INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), INT_VAL_BYTE_FOURTH(ip_first));
            system(cmd_str);
            debug(LOG_ERR, cmd_str);
        }
        break;
    }
    default:
        break;
    }
    return;
}

/**************************************************************************//**
* function: fixed_tc_apply
* @brief  固定ip限速
* @param  struct tc_config_info *config,
* @return
* @retval void
*
* @note history:
*     @note    date:      2015年01月26日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
void fixed_tc_apply(struct tc_config_info *config)
{
    int ip_last_val = 1;
    int ip_first = 0;
    int ip_last = 0;
    char cmd_str[MAX_STR_LEN] = {0};

    if (NULL == config) {
        return;
    }
    /* 上行 */
    /* 主队列主类 */
    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s handle ffff:0 ingress 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN);
    system(cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc filter add dev %s parent ffff:0 protocol ip u32 match u32 0 0 "
           "action mirred egress redirect dev %s 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN, CMD_REDIRECT_VIRTUAL_ETH);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s root handle 1:0 htb default 255  1>/dev/null 2>&1",
           CMD_REDIRECT_VIRTUAL_ETH);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:0 classid 1:1 htb rate %dmbit ceil %dmbit quantum 10000 "
           "1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH, CMD_MAX_RATE_IN_MBIT, CMD_MAX_RATE_IN_MBIT);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    /* 子队列 */
    for (ip_last_val = 1; ip_last_val <= MAX_TC_INFO; ++ip_last_val) {
        if ((0 != config->new_cfg.fixed[ip_last_val - 1].up_value) && (0 != config->new_cfg.fixed[ip_last_val - 1].up_begin_ip)) {
            snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:1 classid 1:1%d htb rate %dkbit ceil %dkbit prio 1 "
                    "1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH, ip_last_val, config->new_cfg.fixed[ip_last_val - 1].up_value, config->new_cfg.fixed[ip_last_val - 1].up_value);
            system(cmd_str);
            debug(LOG_ERR, cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s parent 1:1%d handle 201:%d sfq perturb 10 1>/dev/null 2>&1",
                    CMD_REDIRECT_VIRTUAL_ETH, ip_last_val, ip_last_val);
            system(cmd_str);
            debug(LOG_ERR, cmd_str);
            ip_first = htonl(config->new_cfg.fixed[ip_last_val - 1].up_begin_ip);
            if (0 == config->new_cfg.fixed[ip_last_val - 1].up_end_ip) {
                ip_last = ip_first;
            } else {
                ip_last = htonl(config->new_cfg.fixed[ip_last_val - 1].up_end_ip);
            }
            for (; ip_first <= ip_last; ++ip_first) {
                snprintf(cmd_str, sizeof(cmd_str), "tc filter add dev %s parent 1:0  protocol ip prio %d u32 match ip src %d.%d.%d.%d/32 classid 1:1%d "
                        "1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH, ip_last_val, INT_VAL_BYTE_FIRST(ip_first),
                        INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), ip_last_val);
                system(cmd_str);
                debug(LOG_ERR, cmd_str);
            }
        }
    }

    /* 下行 */
    /* ##2.1 主队列及主类 */
    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s root handle 1:0 htb default 255 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN);
    system(cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:0 classid 1:1 htb rate %dmbit "
            "ceil %dmbit quantum 10000 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN, CMD_MAX_RATE_IN_MBIT, CMD_MAX_RATE_IN_MBIT);
    system(cmd_str);

    /* 子队列 */
    for (ip_last_val = 1; ip_last_val <= MAX_TC_INFO; ++ip_last_val) {
        if ((0 != config->new_cfg.fixed[ip_last_val - 1].dn_value) && (0 != config->new_cfg.fixed[ip_last_val - 1].dn_begin_ip)) {
            /* sta */
            snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:1 classid 1:1%d htb rate %dkbit ceil %dkbit prio 1 1>/dev/null 2>&1",
                    CMD_REDIRECT_BRLAN, ip_last_val, config->new_cfg.fixed[ip_last_val - 1].dn_value, config->new_cfg.fixed[ip_last_val - 1].dn_value);
            system(cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s parent 1:1%d handle 201:%d sfq perturb 10 1>/dev/null 2>&1",
                    CMD_REDIRECT_BRLAN, ip_last_val, ip_last_val);
            system(cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc filter add dev %s parent 1:0 protocol ip  prio 100 handle %d fw classid 1:1%d 1>/dev/null 2>&1",
                    CMD_REDIRECT_BRLAN, ip_last_val, ip_last_val);
            system(cmd_str);
            /* 为避免iptables规则重复， 这里先做一下删除操作 */
            ip_first = htonl(config->new_cfg.fixed[ip_last_val - 1].dn_begin_ip);
            if (0 == config->new_cfg.fixed[ip_last_val - 1].dn_end_ip) {
                ip_last = ip_first;
            } else {
                ip_last = htonl(config->new_cfg.fixed[ip_last_val - 1].dn_end_ip);
            }
            for (; ip_first <= ip_last; ++ip_first) {
                snprintf(cmd_str, sizeof(cmd_str), "iptables -t mangle -D POSTROUTING -d %d.%d.%d.%d -j MARK --set-mark %d",
                        INT_VAL_BYTE_FIRST(ip_first), INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), ip_last_val);
                system(cmd_str);

                snprintf(cmd_str, sizeof(cmd_str), "iptables -t mangle -A POSTROUTING -d %d.%d.%d.%d -j MARK --set-mark %d",
                        INT_VAL_BYTE_FIRST(ip_first), INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), ip_last_val);
                system(cmd_str);
            }
        }
    }

    return;
}

/**************************************************************************//**
* function: voiddynamic_tc_apply
* @brief  动态带宽调整
* @param  struct tc_config_info *config,
* @return
* @retval
*
* @note history:
*     @note    date:      2015年01月26日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
void
dynamic_tc_apply(struct tc_config_info *config)
{
    int ip_last_val = 1;
    int ip_first = 0;
    int ip_last = 0;
    char cmd_str[MAX_STR_LEN] = {0};

    if (NULL == config) {
        return;
    }

    /* 上行 */
    /* 主队列主类 */
    snprintf(cmd_str, sizeof(cmd_str), "tc qdiscL add dev %s handle ffff:0 ingress 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN);
    system(cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc filter add dev %s parent ffff:0 protocol ip u32 match u32 0 0 "
           "action mirred egress redirect dev %s 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN, CMD_REDIRECT_VIRTUAL_ETH);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s root handle 1:0 htb default 255  1>/dev/null 2>&1",
           CMD_REDIRECT_VIRTUAL_ETH);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:0 classid 1:1 htb rate %dmbit ceil %dmbit quantum 10000 "
           "1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH, config->new_cfg.dynamic.up_max, config->new_cfg.dynamic.up_max);
    system(cmd_str);
    debug(LOG_ERR, cmd_str);

    /* 子队列 */
    if ((0 != config->new_cfg.dynamic.end_ip) && (0 != config->new_cfg.dynamic.begin_ip)) {
        ip_first = htonl(config->new_cfg.dynamic.begin_ip);
        if (0 == config->new_cfg.dynamic.end_ip) {
            ip_last = ip_first;
        } else {
            ip_last = htonl(config->new_cfg.dynamic.end_ip);
        }

        for (; ip_first <= ip_last; ++ip_first) {
            ip_last_val = INT_VAL_BYTE_FOURTH(ip_first);
            snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:1 classid 1:1%d htb rate %dkbit ceil %dkbit prio 1 "
                    "1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH, ip_last_val, config->new_cfg.dynamic.up_per_ip, config->new_cfg.dynamic.upceil_per_ip);
            system(cmd_str);
            debug(LOG_ERR, cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s parent 1:1%d handle 201:%d sfq perturb 10 1>/dev/null 2>&1",
                    CMD_REDIRECT_VIRTUAL_ETH, ip_last_val, ip_last_val);
            system(cmd_str);
            debug(LOG_ERR, cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc filter add dev %s parent 1:0  protocol ip prio %d u32 match ip src %d.%d.%d.%d/32 classid 1:1%d "
                    "1>/dev/null 2>&1", CMD_REDIRECT_VIRTUAL_ETH, ip_last_val, INT_VAL_BYTE_FIRST(ip_first),
                    INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), ip_last_val);
            system(cmd_str);
            debug(LOG_ERR, cmd_str);
        }
    }

    /* 下行 */
    /* ##2.1 主队列及主类 */
    snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s root handle 1:0 htb default 255 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN);
    system(cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:0 classid 1:1 htb rate %dmbit "
            "ceil %dmbit quantum 10000 1>/dev/null 2>&1", CMD_REDIRECT_BRLAN, config->new_cfg.dynamic.dn_max, config->new_cfg.dynamic.dn_max);
    system(cmd_str);

    /* 子队列 */
    if ((0 != config->new_cfg.dynamic.end_ip) && (0 != config->new_cfg.dynamic.begin_ip)) {

        /* 为避免iptables规则重复， 这里先做一下删除操作 */
        ip_first = htonl(config->new_cfg.dynamic.begin_ip);
        if (0 == config->new_cfg.dynamic.end_ip) {
            ip_last = ip_first;
        } else {
            ip_last = htonl(config->new_cfg.dynamic.end_ip);
        }

        for (; ip_first <= ip_last; ++ip_first) {
            ip_last_val = INT_VAL_BYTE_FOURTH(ip_first);
            snprintf(cmd_str, sizeof(cmd_str), "tc class add dev %s parent 1:1 classid 1:1%d htb rate %dkbit ceil %dkbit prio 1 1>/dev/null 2>&1",
                    CMD_REDIRECT_BRLAN, ip_last_val, config->new_cfg.dynamic.dn_per_ip, config->new_cfg.dynamic.dnceil_per_ip);
            system(cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc qdisc add dev %s parent 1:1%d handle 201:%d sfq perturb 10 1>/dev/null 2>&1",
                    CMD_REDIRECT_BRLAN, ip_last_val, ip_last_val);
            system(cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "tc filter add dev %s parent 1:0 protocol ip  prio 100 handle %d fw classid 1:1%d 1>/dev/null 2>&1",
                    CMD_REDIRECT_BRLAN, ip_last_val, ip_last_val);
            system(cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "iptables -t mangle -D POSTROUTING -d %d.%d.%d.%d -j MARK --set-mark %d",
                    INT_VAL_BYTE_FIRST(ip_first), INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), ip_last_val);
            system(cmd_str);

            snprintf(cmd_str, sizeof(cmd_str), "iptables -t mangle -A POSTROUTING -d %d.%d.%d.%d -j MARK --set-mark %d",
                    INT_VAL_BYTE_FIRST(ip_first), INT_VAL_BYTE_SECOND(ip_first), INT_VAL_BYTE_THIRD(ip_first), INT_VAL_BYTE_FOURTH(ip_first), ip_last_val);
            system(cmd_str);
        }
    }

    return;
}

/**************************************************************************//**
* function: voidtc_apply
* @brief  流控生效处理流程
* @param  struct tc_config_info *config,
* @return
* @retval
*
* @note history:
*     @note    date:      2015年01月26日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
void
tc_apply(struct tc_config_info *config)
{
    if (NULL == config) {
        return;
    }
    clean_last_tc(&(config->old_cfg));

    switch (config->new_cfg.tc_type) {
    case TC_TYPE_FIXED:
        fixed_tc_apply(config);
        break;

    case TC_TYPE_DYNAMIC:
        dynamic_tc_apply(config);
        break;

    default:
        debug(LOG_ERR, "error tc type : %d\n", config->new_cfg.tc_type);
        break;
    }

    return;
}


/**************************************************************************//**
* function: voidthread_tc
* @brief  流控处理线程入口
* @param  void *arg,
* @return
* @retval
*
* @note history:
*     @note    date:      2015年01月26日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
void
thread_tc(void *arg)
{
    int fd = 0;
    char cmd_str[MAX_STR_LEN] = {0};

    debug(LOG_DEBUG, "Running tc()");

    /* 启用一个虚拟网卡，用作数据重定向进行流控 */
    snprintf(cmd_str, sizeof(cmd_str), "modprobe ifb 1>/dev/null 2>&1");
    system(cmd_str);

    snprintf(cmd_str, sizeof(cmd_str), "ip link set ifb0 up 1>/dev/null 2>&1");
    system(cmd_str);

    while (1) {
        if (config_has_modified(TC_CONFIG_PATH)) {
            update_tc_conf_from_file(TC_CONFIG_PATH);
            show_config();
            tc_apply(&g_tc_conf);
        } else {
            sleep(3);
        }
    }
}


/**************************************************************************//**
* function: show_config
* @brief  打印配置
* @return
* @retval void
*
* @note history:
*     @note    date:      2015年01月26日
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/
void show_config()
{
    int i = 0;
    switch (g_tc_conf.new_cfg.tc_type) {
    case TC_TYPE_FIXED:
    {
        debug(LOG_ERR, "fixed:\n");
        for (i = 0; i < MAX_TC_INFO; i++) {
            if ((0 == g_tc_conf.new_cfg.fixed[i].up_value) && (0 == g_tc_conf.new_cfg.fixed[i].dn_value)) {
                continue;
            }

            debug(LOG_ERR, "NEWUPLOAD:\n");
            debug(LOG_ERR, "value:%d\n", g_tc_conf.new_cfg.fixed[i].up_value);
            debug(LOG_ERR, "beginip:%d\n", g_tc_conf.new_cfg.fixed[i].up_begin_ip);
            debug(LOG_ERR, "endip:%d\n", g_tc_conf.new_cfg.fixed[i].up_end_ip);

            debug(LOG_ERR, "NEWDNLOAD:\n");
            debug(LOG_ERR, "value:%d\n", g_tc_conf.new_cfg.fixed[i].dn_value);
            debug(LOG_ERR, "beginip:%d\n", g_tc_conf.new_cfg.fixed[i].dn_begin_ip);
            debug(LOG_ERR, "endip:%d\n", g_tc_conf.new_cfg.fixed[i].dn_end_ip);
        }
        break;
    }

    case TC_TYPE_DYNAMIC:
    {
        debug(LOG_ERR, "dynamic:\n");
        debug(LOG_ERR, "up max:%dmbit\n", g_tc_conf.new_cfg.dynamic.up_max);
        debug(LOG_ERR, "endip:%dmbit\n", g_tc_conf.new_cfg.dynamic.dn_max);
        debug(LOG_ERR, "up per ip:%dkbit\n", g_tc_conf.new_cfg.dynamic.up_per_ip);
        debug(LOG_ERR, "dn per ip:%dkbit\n", g_tc_conf.new_cfg.dynamic.dn_per_ip);
        debug(LOG_ERR, "up ceil max:%dkbit\n", g_tc_conf.new_cfg.dynamic.upceil_per_ip);
        debug(LOG_ERR, "dn ceil:%dkbit\n", g_tc_conf.new_cfg.dynamic.dnceil_per_ip);
        debug(LOG_ERR, "beginip:%d\n", g_tc_conf.new_cfg.dynamic.begin_ip);
        debug(LOG_ERR, "endip:%d\n", g_tc_conf.new_cfg.dynamic.end_ip);
        break;
    }

    default:
    {
        debug(LOG_ERR, "error tc type:%d\n", g_tc_conf.new_cfg.tc_type);
        break;
    }
    }
    return;
}


