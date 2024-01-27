#ifndef __TYPES_H__
#define __TYPES_H__

/* Compatibility stuff */
#define _XOPEN_SOURCE 700 /* Required for signal handling */
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
/* ------------------- */

#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

/* Ethernet Header Values */

typedef struct
{
    unsigned char dst[ETH_ALEN], src[ETH_ALEN];
    unsigned short ether_type;
} ETHeader;

/* IP Header Values */
typedef struct
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
} IPHeader;

#define IP_HL(ip) ((ip->vhl) & 0x0F) * 4
#define IP_V(ip) ((ip->vhl) >> 4)

/* TCP Header Values */
typedef struct
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
} TCPHeader;

/* Selective Capping Values */
#define CAPSIZE 65535
#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E

typedef struct
{
    uint8_t percentage, threshold;
    char *interface;
    // TODO add a way to save the captured packets
} HandlerArgs;

#endif