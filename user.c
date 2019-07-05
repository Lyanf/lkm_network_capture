#include "packet.h"
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SEND_BUFFER_SIZE 1000
#define RECV_BUFFER_SIZE 10000 * sizeof(struct net_packet)

int done, sock_fd;

void init_sendmsg(struct msghdr *msg_hdr)
{
    struct sockaddr_nl *addr;
    int nlh_length;
    struct nlmsghdr *nlh;
    struct iovec *iov;

    addr = (struct sockaddr_nl *)malloc(sizeof(struct sockaddr_nl));
    memset(addr, 0, sizeof(*addr));
    addr->nl_family = AF_NETLINK;
    addr->nl_pid = 0; // send to kernel

    nlh_length = NLMSG_SPACE(SEND_BUFFER_SIZE);
    nlh = (struct nlmsghdr *)malloc(nlh_length);

    memset(nlh, 0, nlh_length);
    nlh->nlmsg_len = nlh_length;
    nlh->nlmsg_pid = getpid();

    iov = (struct iovec *)malloc(sizeof(struct iovec));
    iov->iov_len = nlh_length;
    iov->iov_base = nlh;

    memset(msg_hdr, 0, sizeof(*msg_hdr));
    msg_hdr->msg_name = addr;
    msg_hdr->msg_namelen = sizeof(*addr);
    msg_hdr->msg_iov = iov;
    msg_hdr->msg_iovlen = 1;
}

void send_msg(int sock_fd, const char *msg, struct msghdr *msg_hdr)
{
    size_t msg_size = strlen(msg);
    strncpy(NLMSG_DATA(msg_hdr->msg_iov->iov_base), msg, msg_size);
    sendmsg(sock_fd, msg_hdr, 0);
}

void init_recvmsg(struct sockaddr_nl *addr, struct msghdr *msg_hdr)
{
    struct iovec *iov;
    struct nlmsghdr *nlh;
    int nlh_length;

    addr = (struct sockaddr_nl *)malloc(sizeof(struct sockaddr_nl));
    memset(addr, 0, sizeof(*addr));
    addr->nl_family = AF_NETLINK;
    addr->nl_pid = getpid();

    nlh_length = NLMSG_SPACE(RECV_BUFFER_SIZE);
    nlh = (struct nlmsghdr *)malloc(nlh_length);

    iov = (struct iovec *)malloc(sizeof(struct iovec));
    iov->iov_base = nlh;
    iov->iov_len = nlh_length;

    memset(msg_hdr, 0, sizeof(*msg_hdr));
    msg_hdr->msg_name = addr;
    msg_hdr->msg_namelen = sizeof(*addr);
    msg_hdr->msg_iov = iov;
    msg_hdr->msg_iovlen = 1;
}

const char *recv_msg(int sock_fd, struct msghdr *msg_hdr)
{
    recvmsg(sock_fd, msg_hdr, 0);
    return NLMSG_DATA(msg_hdr->msg_iov->iov_base);
}

void cleanup(int signum)
{
    done = 0;
}

int main(int argc, char *argv[])
{
    int ret, opt;
    struct sockaddr_nl src_addr;
    struct msghdr sendmsg_hdr, recvmsg_hdr;
    struct sigaction action;
    const char *msg;
    FILE *fp = NULL;
    char ip_src[INET6_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];
    char *ipv[] = {"ipv4", "ipv6"};

    while ((opt = getopt(argc, argv, "nf:")) != -1) {
        switch (opt) {
        case 'n':
            break;
        case 'f':
            fp = fopen(optarg, "a");
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-t nsecs] [-n] name\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd < 0) {
        fprintf(stderr, "Create socket failed.(%d)\n", sock_fd);
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_pad = 0;
    src_addr.nl_groups = NETLINK_GROUP;

    ret = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (ret != 0) {
        fprintf(stderr,
                "Bind error (%d)! Make sure you have sudo premission.\n", ret);
        return -1;
    }

    init_sendmsg(&sendmsg_hdr);
    init_recvmsg(&src_addr, &recvmsg_hdr);

    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = cleanup;
    sigaction(SIGINT, &action, NULL);

    send_msg(sock_fd, "ACK", &sendmsg_hdr);

    printf("Press ctrl + c at any time to stop capturing...\n");
    msg = recv_msg(sock_fd, &recvmsg_hdr); // try conecting

    if (strlen(msg)) {
        printf("Begin to capture packets...");
        fflush(stdout);
        done = 1;
        while (done) {
            struct dlist *mlist =
                (struct dlist *)recv_msg(sock_fd, &recvmsg_hdr);
            struct net_packet *d = mlist->data;
            for (int i = 0; i < mlist->size; i++) {
                if (!d[i].ip6) {
                    inet_ntop(AF_INET, &d[i].saddr.ip, ip_src, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &d[i].daddr.ip, ip_dst, INET_ADDRSTRLEN);

                } else {
                    inet_ntop(AF_INET6, &d[i].saddr.ip6, ip_src,
                              INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &d[i].daddr.ip6, ip_dst,
                              INET6_ADDRSTRLEN);
                }
                if (d[i].protocol == UDP_PROTOCOL ||
                    d[i].protocol == TCP_PROTOCOL) {
                    fprintf(fp, "%s/%d %s:%u -> %s:%u\n", ipv[d[i].ip6],
                            d[i].protocol, ip_src, d[i].sport, ip_dst,
                            d[i].dport);
                } else {
                    fprintf(fp, "%s/%d %s -> %s\n", ipv[d[i].ip6],
                            d[i].protocol, ip_src, ip_dst);
                }
            }
        }
    } else {
        printf("No response. Please make sure LKM has been loaded.");
    }

    printf("\nCleaning up...\n");
    close(sock_fd);
    return 0;
}
