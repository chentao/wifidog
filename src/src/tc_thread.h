/**************************************************************************//**
*
*                  版权所有 (C), 1999-2013, 中太数据通信公司
*
* @file tc_thread.h
* @brief
* @version 初稿
* @author luosy
* @date 2015年01月23日 
* @note history: 
*     @note    date:      2015年01月23日 
*     @note    author:    luosy
*     @note    content:   新生成函数
******************************************************************************/

#ifndef __TC_THREAD_H__
#define __TC_THREAD_H__


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/*
 * 包含头文件
 */

/*
 * 宏定义
 */
#define INT_VAL_BYTE_FIRST(val)     (((val) >> 24) & 0XFF)
#define INT_VAL_BYTE_SECOND(val)    (((val) >> 16) & 0XFF)
#define INT_VAL_BYTE_THIRD(val)     (((val) >> 8) & 0XFF)
#define INT_VAL_BYTE_FOURTH(val)    (((val) >> 0) & 0XFF)

#define MAX_TC_INFO     (50)

/*
 * 外部变量说明
 */

/*
 * 外部函数原型说明
 */

/*
 * 全局变量
 */

/*
 * 模块级变量
 */

/*
 * 接口声明
 */


enum tc_type {
    TC_TYPE_FIXED = 1,      /* 固定ip限速 */
    TC_TYPE_DYNAMIC = 2,    /* 带宽动态调整 */
    TC_TYPE_MAX
};

/* IP固定限速 */
struct tc_fixed_cfg {
    int up_begin_ip;
    int up_end_ip;
    int up_value;       /*kbit*/
    int dn_begin_ip;
    int dn_end_ip;
    int dn_value;       /*kbit*/
};

/* IP动态限速 */
struct tc_dynamic_cfg {
    int up_max;         /*mbit*/
    int dn_max;         /*mbit*/
    int up_per_ip;      /*kbit*/
    int dn_per_ip;      /*kbit*/
    int upceil_per_ip;  /*kbit*/
    int dnceil_per_ip;  /*kbit*/
    int begin_ip;
    int end_ip;
};

struct tc_config {
    int tc_type;
    struct tc_dynamic_cfg dynamic;
    struct tc_fixed_cfg fixed[MAX_TC_INFO];
};


struct tc_config_info {
    time_t last_modify_time;
    struct tc_config new_cfg;
    struct tc_config old_cfg;
};


extern void thread_tc(void *arg);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __TC_THREAD_H__ */
