#ifndef SPC_PARSER_H
#define SPC_PARSER_H

#include "headers.h"

/* =====================     PCAP Saver     ===================== */

/** Header for a pcap formatted file*/
struct pcap_file_header
{
    const uint32_t magic_number = 0xA1B2C3D4;
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
int rx_core(void *args);

/**
 * Handler function for a dumping thread. This function retrieves
 * packets from a processed burst list, and writes relevant data
 * to disk.
 *
 * @param args: Arguments required to manipulate a communication ring.
 */
int dx_core(void *args);

/* =====================  Other  Functions  ===================== */

/* User arguments inserted at the beginning of the program */
struct arguments
{
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    unsigned short kernel;
    unsigned short queues;
    unsigned int elements;
    unsigned int bsize;
    unsigned int rsize;
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