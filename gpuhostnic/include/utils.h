#ifndef SPC_PARSER_H
#define SPC_PARSER_H

#include "headers.h"
/* =====================     PCAP Saver     ===================== */
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

struct pcap_packet_header
{
    uint32_t ts_sec;
    uint32_t ts_usec; 
    uint32_t caplen;   /* Captured length of packet in bytes */
    uint32_t len;      /* Original length of packet in bytes */
};

/* =====================    RX/TX  Cores    ===================== */

/**
 * TODO document this function
 */
int rx_core(void *args);

/**
 * TODO document this function
 */
int tx_core(void *args);

/* =====================  Other  Functions  ===================== */

struct arguments
{
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    unsigned short kernel;
    char* output;
};

/**
 * TODO document this function
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

#endif