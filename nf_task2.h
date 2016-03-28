/*
 * =====================================================================================
 *
 *       Filename:  task2.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  03/10/2016 12:36:59 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef NF_TASK2_H
#define NF_TASK2_H

#include <linux/types.h>

struct filter {
    struct list_head list;
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  proto;
    uint16_t sport;
    uint16_t dport;
    uint8_t  saddr_active:1,
             daddr_active:1,
             proto_active:1,
             sport_active:1,
             dport_active:1
             ;
};

#endif // NF_TASK2_H

