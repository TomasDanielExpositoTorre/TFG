#ifndef SPC_NETWORK_HEADERS_H
#define SPC_NETWORK_HEADERS_H

#include "headers.h"

/* =====================      Ethernet  Headers      ===================== */

struct eth_header
{
    unsigned char dst[ETH_ALEN], src[ETH_ALEN];
    unsigned short ether_type;
};

/* =====================         IP  Headers         ===================== */

struct ip_header
{
    unsigned char vhl;
    unsigned char tos;
    unsigned short len;
    unsigned short id;
    unsigned short offset;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1FFF
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr src, dst;
};

#define IP_HL(ip) ((ip->vhl) & 0x0F) * 4
#define IP_V(ip) ((ip->vhl) >> 4)

/* =====================         TCP Headers         ===================== */

struct tcp_header
{
    unsigned short srcport, dstport;
    unsigned short seq, ack;
    unsigned char offset;
#define TCP_OFFSET(tcp) ((tcp->offset & 0xF0) >> 4)
    unsigned char flags;
#define TCP_FIN 0x1
#define TCP_SYN 0x2
#define TCP_RST 0x4
#define TCP_PUSH 0x8
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN | TCP_SYN | TCP_RST | TCP_PUSH | TCP_ACK | TCP_URG | TCP_ECE | TCP_CWR)
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent;
};

/* Extra Values */
#define VLAN_HLEN 4
#define UDP_LEN 8

#endif