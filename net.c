#include "packet.h"
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <linux/udp.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KaitoHH");

static struct nf_hook_ops ip_ops;
static struct nf_hook_ops ipv6_ops;
static struct timer_list my_timer;

struct sock *nl_sk = NULL;
static int activate = 0;

static struct net_packet *buffer;
static __u32 head = 0, tail = 0;
static __u32 max_size = 10000;
static int interval = 1000;
static const size_t NET_PACKET_SIZE = sizeof(struct net_packet);

module_param(max_size, int, 0);
MODULE_PARM_DESC(max_size, "max packet number in the buffer");
module_param(interval, int, 0);
MODULE_PARM_DESC(interval, "time interval of sending packets (ms)");

static void copy_buffer(__u8 *mbuffer, __u32 lhead, __u32 ltail)
{
    __u32 size;
    __u8 *phead = mbuffer;
    mbuffer += sizeof(__u32);
    if (lhead >= ltail) {
        size = lhead - ltail;
        memcpy(mbuffer, buffer + ltail, size * NET_PACKET_SIZE);
    } else {
        size = max_size - ltail + lhead;
        memcpy(mbuffer, buffer + ltail, (max_size - ltail) * NET_PACKET_SIZE);
        mbuffer += (max_size - ltail) * NET_PACKET_SIZE;
        memcpy(mbuffer, buffer, lhead * NET_PACKET_SIZE);
    }
    *(__u32 *)phead = size;
}

static int send_msg(const char *msg, __u32 pid, int unicast)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb;
    size_t msg_size;
    int res;
    int lhead, ltail;

    if (unicast) {
        msg_size = strlen(msg) + 1;
    } else {
        lhead = *(__u32 *)msg;
        ltail = tail;
        if (lhead >= ltail) {
            msg_size = (lhead - ltail) * NET_PACKET_SIZE;
        } else {
            msg_size = (max_size - ltail + lhead) * NET_PACKET_SIZE;
        }
    }

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (skb == NULL) {
        printk(KERN_ERR "Failed to allocate skb\n");
        return -1;
    }

    nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size, 0);
    if (unicast) {
        strncpy(nlmsg_data(nlh), msg, msg_size);
    } else {
        copy_buffer(nlmsg_data(nlh), lhead, ltail);
    }

    if (unicast) {
        res = nlmsg_unicast(nl_sk, skb, pid);
    } else {
        res = nlmsg_multicast(nl_sk, skb, 0, NETLINK_GROUP, GFP_KERNEL);
    }
    if (res < 0) {
        // printk(KERN_ERR "Failed to send messages (%d)\n", res);
        return -2;
    }
    return 0;
}

static const char *recv_msg(struct sk_buff *skb, __u32 *pid)
{
    struct nlmsghdr *nlh;
    nlh = (struct nlmsghdr *)skb->data;
    *pid = nlh->nlmsg_pid;
    return nlmsg_data(nlh);
}

static void send_packet_timer_callback(struct timer_list *timer)
{
    int cur_head = head;
    int ret = send_msg((void *)&cur_head, -1, 0);
    tail = cur_head;
    if (ret == 0) {
        mod_timer(&my_timer, jiffies + msecs_to_jiffies(interval));
    } else {
        activate = 0;
        printk(KERN_INFO "stopped capturing.\n");
    }
}

static void begin_capture(struct sk_buff *skb)
{
    __u32 pid;
    const char *in = recv_msg(skb, &pid);
    if (!strcmp(in, "ACK")) {
        send_msg("ACK", pid, 1);
        if (!activate) {
            activate = 1;
            printk(KERN_INFO "begin capturing...\n");
            mod_timer(&my_timer, jiffies + msecs_to_jiffies(interval));
        }
    }
}

static void insert_packet(struct net_packet packet)
{
    __u32 next = (head + 1) % max_size;
    if (next == tail) {
        printk(KERN_WARNING "message buffer overflow. Consider increasing max_size or decreasing time interval.");
    } else {
        buffer[head] = packet;
        head = next;
    }
}

static void get_port_from_transport(struct sk_buff *skb, __u8 protocol,
                                    __u16 *src, __u16 *dest)
{
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    if (protocol == TCP_PROTOCOL) {
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        *src = tcp_header->source;
        *dest = tcp_header->dest;
    } else if (protocol == UDP_PROTOCOL) {
        udp_header = (struct udphdr *)skb_transport_header(skb);
        *src = udp_header->source;
        *dest = udp_header->dest;
    }
}

static unsigned int nf_ip_hook(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct net_packet cur_packet;
    cur_packet.ip6 = 0;

    if (!activate)
        return NF_ACCEPT;
    ip_header = (struct iphdr *)skb_network_header(skb);

    cur_packet.protocol = ip_header->protocol;
    cur_packet.saddr.ip = ip_header->saddr;
    cur_packet.daddr.ip = ip_header->daddr;
    get_port_from_transport(skb, cur_packet.protocol, &cur_packet.sport,
                            &cur_packet.dport);
    insert_packet(cur_packet);
    return NF_ACCEPT;
}

static unsigned int nf_ip6_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6_header;
    struct net_packet cur_packet;
    cur_packet.ip6 = 1;

    if (!activate)
        return NF_ACCEPT;
    ip6_header = ipv6_hdr(skb);

    cur_packet.protocol = ip6_header->nexthdr;
    cur_packet.saddr.ip6 = ip6_header->saddr;
    cur_packet.daddr.ip6 = ip6_header->daddr;
    get_port_from_transport(skb, cur_packet.protocol, &cur_packet.sport,
                            &cur_packet.dport);
    insert_packet(cur_packet);
    return NF_ACCEPT;
}

static int __init register_hook(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = begin_capture,
    };
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -2;
    }

    ip_ops.hook = nf_ip_hook;
    ip_ops.hooknum = NF_INET_PRE_ROUTING;
    ip_ops.pf = NFPROTO_IPV4;
    ip_ops.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &ip_ops);

    ipv6_ops.hook = nf_ip6_hook;
    ipv6_ops.hooknum = NF_INET_PRE_ROUTING;
    ipv6_ops.pf = NFPROTO_IPV6;
    ipv6_ops.priority = NF_IP6_PRI_FIRST;
    nf_register_net_hook(&init_net, &ipv6_ops);

    timer_setup(&my_timer, send_packet_timer_callback, 0);

    buffer =
        (struct net_packet *)kmalloc(max_size * NET_PACKET_SIZE, GFP_KERNEL);
    return 0;
}

static void __exit cleanup_hook(void)
{
    nf_unregister_net_hook(&init_net, &ip_ops);
    nf_unregister_net_hook(&init_net, &ipv6_ops);
    netlink_kernel_release(nl_sk);
    del_timer(&my_timer);
    kfree(buffer);
}

module_init(register_hook);
module_exit(cleanup_hook);
