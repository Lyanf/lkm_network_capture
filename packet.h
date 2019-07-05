#ifndef PACKET_H
#define PACKET_H

#include <linux/ipv6.h>
#include <linux/types.h>

#define NETLINK_GROUP 1
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

struct net_packet {
    __u8 ip6;
    __u8 protocol;
    __u16 sport;
    __u16 dport;
    union {
        __u32 ip;
        struct in6_addr ip6;
    } saddr;
    union {
        __u32 ip;
        struct in6_addr ip6;
    } daddr;
};

struct dlist {
    __u32 size;
    struct net_packet data[0];
};

#endif
