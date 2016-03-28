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
#include "nf_task2.h"

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip.h>

static LIST_HEAD(g_in_fils);
static LIST_HEAD(g_out_fils);

static bool is_iph_matches_filter(const struct iphdr *iph,
                                  const struct filter *fil) {
    uint32_t saddr, daddr;
    uint8_t  proto;

    if (!iph) {
        return false;
    }
    saddr = ntohl(iph->saddr);
    if (fil->saddr_active && saddr == fil->saddr) {
        return true;
    }
    daddr = ntohl(iph->daddr);
    if (fil->daddr_active && daddr == fil->daddr) {
        return true;
    }
    proto = iph->protocol;
    if (fil->proto_active && proto == fil->proto) {
        return true;
    }
    return false;
}

static bool is_tcph_matches_filter(const struct tcphdr *tcph,
                                   const struct filter *fil) {
    uint16_t sport, dport;

    if (!tcph) {
        return false;
    }
    sport = ntohs(tcph->source);
    if (fil->sport_active && sport == fil->sport) {
        return true;
    }
    dport = ntohs(tcph->dest);
    if (fil->dport_active && dport == fil->dport) {
        return true;
    }
    return false;
}

static bool is_packet_matches_filter(const struct sk_buff *skb,
                                     const struct filter *fil) {
    const struct iphdr *iph = NULL;
    const struct tcphdr *tcph = NULL;

    if (!skb) {
        return false;
    }
    iph = (const struct iphdr *)skb_network_header(skb);
    if (iph) {
        if (is_iph_matches_filter(iph, fil)) {
            return true;
        }
        if (!ip_is_fragment(iph) && iph->protocol == IPPROTO_TCP) {
            tcph = (const struct tcphdr *)skb_transport_header(skb);
            if (tcph && is_tcph_matches_filter(tcph, fil)) {
                return true;
            }
        }
    }
    return false;

}
static bool is_packet_matches_filters(const struct sk_buff *skb,
                                      const struct list_head *fils_list) {
    const struct filter *fil = NULL;

    list_for_each_entry(fil, fils_list, list) {
        if (is_packet_matches_filter(skb, fil)) {
            return true;
        }
    }
    return false;
}

static int format_skb(char *buf, size_t buflen, const struct sk_buff *skb) {
    int ret = 0;
    const struct iphdr *iph = NULL;
    const struct tcphdr *tcph = NULL;
    uint16_t sport, dport;

    if (skb) {
        iph = (const struct iphdr *)skb_network_header(skb);
        if (iph) {
            tcph = NULL;
            ret += snprintf(buf + ret, buflen - ret,
                    "IP(src=%pI4, dst=%pI4, proto=0x%02X)", &iph->saddr, &iph->daddr,
                    iph->protocol);
            tcph = (const struct tcphdr *)skb_transport_header(skb);
            if (tcph) {
                sport = ntohs(tcph->source);
                dport = ntohs(tcph->dest);
                ret += snprintf(buf + ret, buflen - ret,
                        "TCP(sport=%u, dport=%u)", (uint32_t)sport,
                        (uint32_t)dport);
            }
        }
    }
    return ret;
}

static unsigned int drop_incoming_hook(const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *)) {
    char packet[256] = { 0 };
    if (is_packet_matches_filters(skb, &g_in_fils)) {
        if (format_skb(packet, sizeof(packet), skb)) {
            printk(KERN_INFO "Dropping %s\n", packet);
        } else {
            printk(KERN_WARNING "Dropping unknown packet\n");
        }
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static unsigned int drop_outgoing_hook(const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *)) {
    char packet[256] = { 0 };
    if (is_packet_matches_filters(skb, &g_out_fils)) {
        if (format_skb(packet, sizeof(packet), skb)) {
            printk(KERN_INFO "Dropping %s\n", packet);
        } else {
            printk(KERN_WARNING "Dropping unknown packet\n");
        }
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static int filters_init(void) {
    int err = 0;
    struct filter *in_fil0  = vmalloc(sizeof(*in_fil0)),
                  *in_fil1  = vmalloc(sizeof(*in_fil1)),
                  *in_fil2  = vmalloc(sizeof(*in_fil2)),
                  *out_fil0 = vmalloc(sizeof(*out_fil0)),
                  *out_fil1 = vmalloc(sizeof(*out_fil1));

    if (!in_fil0 || !in_fil1 || !in_fil2 || !out_fil0 || !out_fil1) {
        err = -ENOMEM;
        goto cleanup;
    }
    memset(in_fil0,  0, sizeof(*in_fil0));
    memset(in_fil1,  0, sizeof(*in_fil1));
    memset(in_fil2,  0, sizeof(*in_fil2));
    memset(out_fil0, 0, sizeof(*out_fil0));
    memset(out_fil1, 0, sizeof(*out_fil1));
    in_fil0->saddr = 0x01010101;
    in_fil0->saddr_active = 1;
    list_add_tail(&in_fil0->list, &g_in_fils);
    in_fil1->dport = 80;
    in_fil1->dport_active = 1;
    list_add_tail(&in_fil1->list, &g_in_fils);
    in_fil2->proto = 0x33;
    in_fil2->proto_active = 1;
    list_add_tail(&in_fil2->list, &g_in_fils);
    out_fil0->daddr = 0x2e783045;
    out_fil0->daddr_active = 1;
    list_add_tail(&out_fil0->list, &g_out_fils);
    out_fil1->dport = 80;
    out_fil1->dport_active = 1;
    list_add_tail(&out_fil1->list, &g_out_fils);

cleanup:
    if (err) {
        vfree(out_fil1);
        vfree(out_fil0);
        vfree(in_fil2);
        vfree(in_fil1);
        vfree(in_fil0);
    }
    return err;
}

static void filters_fini(void) {
    struct filter *fil, *n;
    list_for_each_entry_safe_reverse(fil, n, &g_out_fils, list) {
        vfree(fil);
    }
    list_for_each_entry_safe_reverse(fil, n, &g_in_fils, list) {
        vfree(fil);
    }
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
    err = filters_init();
    if (err) {
        goto cleanup;
    }
    err = nf_register_hooks(task2_ops, ARRAY_SIZE(task2_ops));
cleanup:
    return err;

}

static void __exit nf_task2_fini(void) {
    nf_unregister_hooks(task2_ops, ARRAY_SIZE(task2_ops));
    filters_fini();
    printk(KERN_INFO "Task2 unloaded!\n");
}

module_init(nf_task2_init);
module_exit(nf_task2_fini);

MODULE_DESCRIPTION("A sample firewall using Netfilter");
MODULE_AUTHOR("Hod Bin Noon and Dolev Sigron");
MODULE_LICENSE("GPL");

