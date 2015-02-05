#ifndef _TASK_H_
#define _TASK_H_

#define SMARTWIFI_TASK_REBOOT          1000
#define SMARTWIFI_TASK_PORTALSTART     2000
#define SMARTWIFI_TASK_PORTALSTOP      2001
#define SMARTWIFI_TASK_PORTALRESTART   2002
#define SMARTWIFI_TASK_SETBASEINFO     2003
#define SMARTWIFI_TASK_SYSUPGRADE      3000
#define SMARTWIFI_TASK_WHITE_LIST      4002
#define SMARTWIFI_TASK_FLOW_CONTROL    5001

#define TASK_APPENDING     1
#define TASK_EXECUTING     2
#define TASK_SUCCED        3
#define TASK_FAILED        4

typedef struct	_t_task {
  struct	_t_task *next;        /**< @brief Pointer to the next task */
  char *task_id;
  int   task_code;
  char *task_params;              /* json format string */
  int   task_status;
} t_task;

t_task * task_get_first_task(void);
void task_list_init(void);
t_task *task_list_append(const char *id, const int code, const char *params);
void task_list_delete(t_task *task);
int task_response_parse(const char *buf);
void thread_task(void *arg);

#define LOCK_TASK_LIST() do { \
	debug(LOG_DEBUG, "Locking task list"); \
	pthread_mutex_lock(&task_list_mutex); \
	debug(LOG_DEBUG, "Task list locked"); \
} while (0)

#define UNLOCK_TASK_LIST() do { \
	debug(LOG_DEBUG, "Unlocking task list"); \
	pthread_mutex_unlock(&task_list_mutex); \
	debug(LOG_DEBUG, "Task list unlocked"); \
} while (0)

#endif
