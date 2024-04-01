#ifndef SPC_MACROS_H
#define SPC_MACROS_H

#include "headers.h"

/* =====================  Macro  Functions  ===================== */

/* Macro wrapper for condition checking on rte functions */
#define try(cond) if ((ret = cond) != 0)

/* Macro wrapper for exiting a program with a message */
#define fail(...) rte_exit(EXIT_FAILURE, __VA_ARGS__)

/* Returns ceil(X/Y) */
#define ceil(X, Y) (X + Y - 1) / Y

/**
 * Macro handler for waiting for launched worker threads.
 */
#define RTE_WAIT_WORKERS(id, ret)                             \
    for (int id = rte_get_next_lcore(-1, 1, 0);               \
         id < RTE_MAX_LCORE && ret >= 0;                      \
         id = rte_get_next_lcore(id, 1, 0))                   \
    {                                                         \
        ret = rte_eal_wait_lcore(id);                         \
        if (rte_eal_wait_lcore(id) < 0)                       \
            fprintf(stderr, "bad exit for coreid: %d\n", id); \
    }

/* ===================== Macro  Definitions ===================== */

/** Minimum printable ascii character */
#define MIN_ASCII 0x20
/** Maximum printable ascii character */
#define MAX_ASCII 0x7E

/* Lnkytype Ethernet */
#define DLT_EN10MB 1

#define UDP_HLEN 8
#define IP_HMINLEN 20
#define IP_HMAXLEN 60
#define TCP_HMINLEN 20
#define TCP_HMAXLEN 60

/** Minimum length of supported packet header, assuming 4 bytes for VLAN */
#define MIN_HLEN (RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + IP_HMINLEN + UDP_HLEN)

/** Maximum length of supported packet header, assuming 4 bytes for VLAN */
#define MAX_HLEN (RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + IP_HMAXLEN + TCP_HMAXLEN)

#define PCAP_USEC 0xA1B2C3D4
#define PCAP_NSEC 0xA1B23C4D
/* =====================  Temporal  Macros  ===================== */

#define NIC_PORT 0
#define GPU_ID 0

#define RTE_PKTBUF_DATAROOM 2048U
#define GPU_PAGE 65536U
#define RTE_RXBURST_ALIGNSIZE 8
#define MAX_BURSTSIZE 4096
#endif