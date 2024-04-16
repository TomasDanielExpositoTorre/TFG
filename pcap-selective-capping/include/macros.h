#ifndef SPC_UTILS_H
#define SPC_UTILS_H

/* =====================  Compatibility Definitions  ===================== */

#define _XOPEN_SOURCE 700
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;

/* =====================     Capping Definitions     ===================== */
#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E
#define NO_CAPPING 0
#define ERR_UNSUPPORTED -1
#define ERR_ILLFORMED -2

#define TO_MS_VAL 0
#define SNAPLEN_SIZE 65535

/* =====================      Extra Definitions      ===================== */
#define false 0
#define true 1
#define PCAP_USEC 0xA1B2C3D4
#define PCAP_NSEC 0xA1B23C4D
#define KILOBIT 1024
#define MEGABIT (KILOBIT * 1024)
#define GIGABIT (MEGABIT * 1024)

#define UDP_HLEN 8
#define IP_HMINLEN 20
#define IP_HMAXLEN 60
#define TCP_HMINLEN 20
#define TCP_HMAXLEN 60

/** Minimum length of supported packet header, assuming 4 bytes for VLAN */
#define MIN_HLEN (ETH_HLEN + VLAN_HLEN + IP_HMINLEN + UDP_HLEN)

/** Maximum length of supported packet header, assuming 4 bytes for VLAN */
#define MAX_HLEN (ETH_HLEN + VLAN_HLEN + IP_HMAXLEN + TCP_HMAXLEN)

/* =====================       Function Macros       ===================== */

#define psem_init(x) pthread_mutex_init(&(x), NULL)
#define psem_destroy(x) pthread_mutex_destroy(&(x))
#define psem_down(x) pthread_mutex_lock(&(x))
#define psem_up(x) pthread_mutex_unlock(&(x))

#endif