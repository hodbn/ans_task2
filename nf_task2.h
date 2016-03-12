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
static struct nf_hook_ops ipv4_defrag_ops[] = {
    {
        .hook           = ipv4_conntrack_defrag,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_PRE_ROUTING,
        .priority       = NF_IP_PRI_CONNTRACK_DEFRAG,
    },
    {
        .hook           = ipv4_conntrack_defrag,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_LOCAL_OUT,
        .priority       = NF_IP_PRI_CONNTRACK_DEFRAG,
    },

};
