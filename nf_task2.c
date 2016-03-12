/*
 * =====================================================================================
 *
 *       Filename:  nf_task2.c
 *
 *    Description:  A sample firewall using Netfilter
 *
 *        Version:  1.0
 *        Created:  03/10/2016 12:21:48 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Hod Bin Noon, Dolev Sigron
 *   Organization:  BIU
 *
 * =====================================================================================
 */
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip.h>

static uint32_t DROP_IN_SADDR      = 0x01010101;
static uint16_t DROP_IN_DPORT      = 80;
static uint8_t  DROP_IN_PROTO      = 0x33;
static uint32_t DROP_OUT_DADDR     = 0x02020202;
static uint16_t DROP_OUT_DPORT     = 80;

static unsigned int drop_incoming_hook(const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *)) {
    const struct iphdr *iph = NULL;
    const struct tcphdr *tcph = NULL;
	uint32_t ip_saddr = 0;
	uint8_t ip_proto = 0;
	uint16_t tcp_dport = 0;

    if (!skb) {
        return NF_ACCEPT;
    }
    iph = (struct iphdr *)skb_network_header(skb);
    if (!iph) {
        return NF_ACCEPT;
    }
	ip_saddr = ntohl(iph->saddr);
    if (ip_saddr == DROP_IN_SADDR) {
        printk(KERN_INFO "Dropping incoming packet from %pI4\n", &ip_saddr);
        return NF_DROP;
    }
	ip_proto = iph->protocol;
    if (ip_proto == DROP_IN_PROTO) {
        printk(KERN_INFO "Dropping incoming 0x%02X packet\n",
                (uint32_t)ip_proto);
        return NF_DROP;
    }
    if (ip_is_fragment(iph)) {
        return NF_ACCEPT;
    }
    if (ip_proto != IPPROTO_TCP) {
        return NF_ACCEPT;
    }
    tcph = (struct tcphdr *)skb_transport_header(skb);
    if (!tcph) {
        return NF_ACCEPT;
    }
	tcp_dport = ntohs(tcph->dest);
    if (tcp_dport == DROP_IN_DPORT) {
        printk(KERN_INFO "Dropping incoming tcp packet to port %u\n",
                (uint32_t)tcp_dport);
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static unsigned int drop_outgoing_hook(const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *)) {
    const struct iphdr *iph = NULL;
    const struct tcphdr *tcph = NULL;
	uint32_t ip_daddr = 0;
	uint16_t tcp_dport = 0;

    if (!skb) {
        return NF_ACCEPT;
    }
    iph = (struct iphdr *)skb_network_header(skb);
    if (!iph) {
        return NF_ACCEPT;
    }
	ip_daddr = ntohl(iph->daddr);
    if (ip_daddr == DROP_OUT_DADDR) {
        printk(KERN_INFO "Dropping outgoing packet to %pI4\n", &ip_daddr);
        return NF_DROP;
    }
    if (ip_is_fragment(iph)) {
        return NF_ACCEPT;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }
    tcph = (struct tcphdr *)skb_transport_header(skb);
    if (!tcph) {
        return NF_ACCEPT;
    }
	tcp_dport = ntohs(tcph->dest);
    if (tcp_dport == DROP_OUT_DPORT) {
        printk(KERN_INFO "Dropping outgoing tcp packet to port %u\n",
                (uint32_t)tcp_dport);
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops task2_ops[] = {
    {
        .hook           = drop_incoming_hook,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_PRE_ROUTING,
        .priority       = NF_IP_PRI_FIRST,
    },
    {
        .hook           = drop_outgoing_hook,
        .owner          = THIS_MODULE,
        .pf             = NFPROTO_IPV4,
        .hooknum        = NF_INET_POST_ROUTING,
        .priority       = NF_IP_PRI_LAST,
    },
};

static int __init nf_task2_init(void) {
    int err = 0;
    printk(KERN_INFO "Task2 loaded!\n");
    err = nf_register_hooks(task2_ops, ARRAY_SIZE(task2_ops));
    return err;

}

static void __exit nf_task2_fini(void) {
    nf_unregister_hooks(task2_ops, ARRAY_SIZE(task2_ops));
    printk(KERN_INFO "Task2 unloaded!\n");
}

module_init(nf_task2_init);
module_exit(nf_task2_fini);

MODULE_DESCRIPTION("A sample firewall using Netfilter");
MODULE_AUTHOR("Hod Bin Noon and Dolev Sigron");
MODULE_LICENSE("GPL");

