#ifndef __SELCAP_H
#define __SELCAP_H

#include "network_headers.h"
#include <pthread.h>

#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E
#define NO_CAPPING 0
#define ERR_UNSUPPORTED -1
#define ERR_ILL_FORMED -2
#define NTHREADS 8

typedef struct
{
    uint8_t percentage, threshold;
    char *interface;
    pcap_dumper_t *file;
} HandlerArgs;

typedef struct
{
    HandlerArgs h_args;
    pcap_t *handle;
    pthread_mutex_t m_read;
    pthread_mutex_t m_write;
    short signaled;
} ThreadArgs;

/**
 * Applies the vanilla selective capping algorithm over the received packet.
 * This function is used as a callback by pcap_loop, so it has no return value.
 *
 * @param args Additional arguments to be sent by the user.
 * @param header Generic per-packet information, as supplied by libpcap.
 * @param packet Packet to process.
 */
void selective_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * Applies an optimized version of the selective capping algorithm over the
 * received packet. This function is used as a callback by pcap_loop, so it has
 * no return value.
 *
 * @param args Additional arguments to be sent by the user.
 * @param header Generic per-packet information, as supplied by libpcap.
 * @param packet Packet to process.
 */
void optimized_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

void *selective_capping_thread(void *args);
void *optimized_capping_thread(void *args);
#endif