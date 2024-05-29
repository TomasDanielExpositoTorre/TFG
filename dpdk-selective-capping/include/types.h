#ifndef __TYPES__H__
#define __TYPES__H__

#include "headers.h"

/* =========================== Macro Definitions =========================== */

#define MIN_ASCII 0x20
#define MAX_ASCII 0x7D

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

#define RTE_RXBURST_ALIGNSIZE 8
#define MAX_BURSTSIZE 1024
#define KILOBIT 1000
#define MEGABIT (KILOBIT * 1000)
#define GIGABIT (MEGABIT * 1000)

/* ===========================  Temporal Macros  =========================== */

#define NIC_PORT 0
#define GPU_ID 0

#define RTE_PKTBUF_DATAROOM 2048U
#define GPU_PAGE 65536U

/* ===========================  Macro Functions  =========================== */

/* Macro wrapper for condition checking on rte functions */
#define try(cond) if ((ret = cond) != 0)

/* Macro wrapper for exiting a program with a message */
#define fail(...) rte_exit(EXIT_FAILURE, __VA_ARGS__)

/* Returns ceil(X/Y) */
#define ceil(X, Y) (X + Y - 1) / Y

#define speed_format(data, units)                                                    \
    units = (data > GIGABIT) ? 'G' : (data > MEGABIT) ? 'M'                          \
                                                      : 'K';                         \
    data = (data > GIGABIT) ? (data / GIGABIT) : (data > MEGABIT) ? (data / MEGABIT) \
                                                                  : (data / KILOBIT)

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
/* ========================== Struct  Definitions ========================== */

struct pcap_file_header
{
#ifdef PCAP_NANOSECONDS
    const uint32_t magic_number = PCAP_NSEC;
#else
    const uint32_t magic_number = PCAP_USEC;
#endif
    const uint16_t version_major = 2;
    const uint16_t version_minor = 4;
    const uint32_t thiszone = 0;
    const uint32_t sigfigs = 0;
    const uint32_t snaplen = 65535;
    const uint32_t network = DLT_EN10MB;
};

/** Header for a pcap formatted packet */
struct pcap_packet_header
{
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen; /* Captured length of packet in bytes */
    uint32_t len;    /* Original length of packet in bytes */
};

struct queue_stats
{
    unsigned long int packets;
    unsigned long int total_bytes;
    unsigned long int stored_bytes;
};

enum burst_state
{
    BURST_FREE = 0,
    BURST_PROCESSING = 1,
    BURST_DONE = 2, 
    RX_DONE = 3,
};

/* User arguments inserted at the beginning of the program */
struct arguments
{
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    unsigned short kernel;
    unsigned short queues;
    unsigned short threads;
    unsigned int burst_size;
    unsigned int ring_size;
    bool gpu_workload;
    FILE *output;
};

#endif