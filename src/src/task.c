#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <string.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "task.h"
#include "cJSON.h"
#include "centralserver.h"
#include "fw_iptables.h"

pthread_mutex_t task_list_mutex = PTHREAD_MUTEX_INITIALIZER;

t_task         *firsttask = NULL;

t_task * task_get_first_task(void)
{
    return firsttask;
}

void task_list_init(void)
{
    firsttask = NULL;
}

t_task * task_list_append(const char *id, const int code, const char *params)
{
    t_task         *cur, *prev;

    prev = NULL;
    cur = firsttask;

    while (cur != NULL) {
        prev = cur;
        cur = cur->next;
    }

    cur = safe_malloc(sizeof(t_task));
    memset(cur, 0, sizeof(t_task));

    cur->task_id = safe_strdup(id);
    cur->task_code = code;
    cur->task_params = safe_strdup(params);
    cur->task_status = TASK_APPENDING;

    if (prev == NULL) {
        firsttask = cur;
    } else {
        prev->next = cur;
    }

    debug(LOG_INFO, "Added a new task to linked list: id: %s code: %d params:[%s]",
          id, code, params);

    return cur;
}

void _task_list_free_node(t_task * task)
{

    if (task->task_id != NULL)
        free(task->task_id);

    if (task->task_params != NULL)
        free(task->task_params);

    free(task);
}

void task_list_delete(t_task * task)
{
    t_task        *ptr;

    ptr = firsttask;

    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == task) {
        firsttask = ptr->next;
        _task_list_free_node(task);
    } else {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != task) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        /* Free element. */
        } else {
            ptr->next = task->next;
            _task_list_free_node(task);
        }
    }
}

int task_response_parse(const char *buf)
{
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *obj = NULL;

    char *id = NULL;
    int code = 0;
    char *params = NULL;

    if(NULL == (root = cJSON_Parse(buf))) {
        return -1;
    }
    if(NULL == (item = cJSON_GetObjectItem(root, "result"))) {
        cJSON_Delete(root);
        return -1;
    }
    if(0 != strcmp(item->valuestring, "OK")) {
        cJSON_Delete(root);
        return -1;
    }
    if(NULL == (obj = cJSON_GetObjectItem(root, "task"))) {
        cJSON_Delete(root);
        return -1;
    }

    if(NULL != (item = cJSON_GetObjectItem(obj, "task_id"))) {
        id = safe_strdup(item->valuestring);

        if(NULL != (item = cJSON_GetObjectItem(obj, "task_code"))) {
            code = item->valueint;

            if(NULL != (item = cJSON_GetObjectItem(obj, "task_params"))) {
                params = cJSON_Print(item);
            }

            task_list_append(id, code, params);

            if(id)
                free(id);
            if(params)
                free(params);
            cJSON_Delete(root);
            return 0;
        }
    }

    if(id)
        free(id);
    if(params)
        free(params);
    cJSON_Delete(root);
    return -1;
}

int task_execute_reboot(t_task *task)
{
    debug(LOG_DEBUG, "Task executing: reboot");
    system("reboot");
    return 0;
}

int task_execute_portalrestart(t_task *task)
{
    debug(LOG_DEBUG, "Task executing: portal restart");
    system("wdctl reset all");
    return 0;
}

int task_execute_setbaseinfo(t_task *task)
{
    cJSON *root = NULL;
    cJSON *item = NULL;
    char *hostname = NULL;
    char *ssid = NULL;
    char cmd[128] = {0};

    if(NULL == task->task_params)
        return -1;

    if(NULL == (root = cJSON_Parse(task->task_params))) {
        debug(LOG_ERR, "Parse json fail.");
        return -1;
    }
    if(NULL == (item = cJSON_GetObjectItem(root, "hostname"))) {
        debug(LOG_ERR, "setbaseinfo: no hostname in params");
    } else {
        hostname = safe_strdup(item->valuestring);

        snprintf(cmd, sizeof(cmd), "uci set system.@system[0].hostname=%s", hostname); system(cmd);
        debug(LOG_DEBUG, "exec: %s", cmd);
        system("uci commit");

        //snprintf(cmd, sizeof(cmd), "/etc/init.d/boot restart"); system(cmd);
        snprintf(cmd, sizeof(cmd), "echo \"%s\" > /proc/sys/kernel/hostname", hostname); system(cmd);
        debug(LOG_DEBUG, "exec: %s", cmd);

        free(hostname);
    }
    if(NULL == (item = cJSON_GetObjectItem(root, "ssid"))) {
        debug(LOG_ERR, "setbaseinfo: no ssid in params");
    } else {
        ssid = safe_strdup(item->valuestring);

        snprintf(cmd, sizeof(cmd), "uci set wireless.@wifi-iface[0].ssid=%s", ssid); system(cmd);
        snprintf(cmd, sizeof(cmd), "uci set wireless.@wifi-iface[1].ssid=%s", ssid); system(cmd);
        debug(LOG_DEBUG, "exec: %s", cmd);
        system("uci commit");
        snprintf(cmd, sizeof(cmd), "iwpriv ra0 set SSID=%s", ssid); system(cmd);
        snprintf(cmd, sizeof(cmd), "iwpriv rai0 set SSID=%s", ssid); system(cmd);
        debug(LOG_DEBUG, "exec: %s", cmd);

        free(ssid);
    }
    cJSON_Delete(root);

    return 0;
}

int task_execute_sysupgrade(t_task *task)
{
    char *file = NULL;
    cJSON *root = NULL;
    cJSON *item = NULL;
    char cmd[1024] = {0};

    if(task->task_params == NULL)
        return -1;

    if(NULL == (root = cJSON_Parse(task->task_params))) {
        debug(LOG_ERR, "Parse json fail.");
        return -1;
    }
    if(NULL == (item = cJSON_GetObjectItem(root, "file"))) {
        debug(LOG_ERR, "sysupgrade: no file in params");
        cJSON_Delete(root);
        return -1;
    } else {
        file = safe_strdup(item->valuestring);
        snprintf(cmd, sizeof(cmd), "sysupgrade -c %s", file); 
        if(system(cmd) != 0) {
            debug(LOG_ERR, "cmd fail: %s", cmd);
            cJSON_Delete(root);
            free(file);
            return -1;
        }
        free(file);
    }
    cJSON_Delete(root);
    return 0;
}

int task_execute_white_list(t_task *task)
{
    iptables_fw_clear_trustedmacs();
    iptables_fw_set_trustedmacs(task->task_params);
    return 0;
}

void thread_task(void *arg)
{
    int ret = -1;

    s_config *config = config_get_config();
    t_task *p1, *p2;
    char *task_id = NULL;
    int task_code = 0;
    char *task_params = NULL;
    int task_status;

    t_authresponse auth_response;
    
    while(1) {
        LOCK_TASK_LIST();
        for(p1 = p2 = task_get_first_task(); NULL != p1; p1 = p2) {
            p2 = p1->next;

            task_status = p1->task_status;
            task_id = safe_strdup(p1->task_id);
            task_code = p1->task_code;

            if(task_status == TASK_APPENDING) {

                debug(LOG_DEBUG, "Executing task[%s:%d]", task_id, task_code);
                switch(task_code) {
                case SMARTWIFI_TASK_REBOOT:
                    ret = task_execute_reboot(p1);
                    break;
                case SMARTWIFI_TASK_PORTALRESTART:
                    ret = task_execute_portalrestart(p1);
                    break;
                case SMARTWIFI_TASK_WHITE_LIST:
                    ret = task_execute_white_list(p1);
                    break;
                case SMARTWIFI_TASK_SETBASEINFO:
                    ret = task_execute_setbaseinfo(p1);
                    break;
                case SMARTWIFI_TASK_SYSUPGRADE:
                    ret = task_execute_sysupgrade(p1);
                    break;
                default:
                    debug(LOG_ERR, "unknown task_code: %d", task_code);
                    ret = -1;
                    break;
                }

                if(ret == 0)
                    p1->task_status = TASK_SUCCED;
                else 
                    p1->task_status = TASK_FAILED;
            }

            if(p1->task_status == TASK_SUCCED || p1->task_status == TASK_FAILED) {

                UNLOCK_TASK_LIST();
                auth_server_taskresult(&auth_response, config->device_id, task_id, p1->task_status==TASK_SUCCED?"OK":"FAIL", "taskfinished");
                LOCK_TASK_LIST();

                if(auth_response.authcode == AUTH_ALLOWED) {
                    task_list_delete(p1);
                }
            }
            free(task_id);
        }
        UNLOCK_TASK_LIST();
        sleep(5);
    }
}
