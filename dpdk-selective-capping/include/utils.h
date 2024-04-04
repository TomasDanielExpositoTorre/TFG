#ifndef SPC_PARSER_H
#define SPC_PARSER_H

#include "headers.h"

/* =====================     PCAP Saver     ===================== */

/** Header for a pcap formatted file*/
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
    uint32_t ts_nsec;
    uint32_t caplen; /* Captured length of packet in bytes */
    uint32_t len;    /* Original length of packet in bytes */
};

/* =====================    RX/TX  Cores    ===================== */

/**
 * Handler function for a reception thread. This function receives
 * packets in bursts from a defined reception queue, and populates
 * a communication list for GPU processing.
 *
 * Reception threads should also store statistics relative to the
 * received data: received packets, bytes...
 *
 * @param args: Arguments required to manipulate a communication ring.
 */
int gpu_rxcore(void *args);

/**
 * Handler function for a dumping thread. This function retrieves
 * packets from a processed burst list, and writes relevant data
 * to disk.
 *
 * @param args: Arguments required to manipulate a communication ring.
 */
int gpu_dxcore(void *args);

int cpu_rxcore(void *args);
int cpu_dxcore(void *args);
int cpu_pxcore(void *args);

/* =====================  Other  Functions  ===================== */

/* User arguments inserted at the beginning of the program */
struct arguments
{
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    unsigned short kernel;
    unsigned short queues;
    unsigned int burst_size;
    unsigned int ring_size;
    bool gpu_workload;
    FILE *output;
};

/**
 * Parsing function for received user arguments.
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

/**
 * TODO document.
 */
int print_stats(void *args);

#endif