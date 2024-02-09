#ifndef __SELCAP_H
#define __SELCAP_H

#include "network_headers.h"
#include <pthread.h>
#include <unistd.h>

#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E
#define NO_CAPPING 0
#define ERR_UNSUPPORTED -1
#define ERR_ILL_FORMED -2
#define NTHREADS 8
typedef struct __LoggingInfo__
{
    pthread_mutex_t log_mutex;
    int captured_bytes;
    int total_bytes;
    int packets;
    int elapsed_time;
} LoggingInfo;

typedef struct __Arguments__
{
    LoggingInfo log;
    uint8_t percentage, threshold;
    char *interface;
    pcap_dumper_t *file;
} Arguments;

typedef struct __ThreadArguments__
{
    Arguments args;
    pcap_t *handle;
    pthread_mutex_t read_mutex;
    pthread_mutex_t write_mutex;
    short signaled;
} ThreadArguments;

void capping_log(void *args);

/**
 * Applies the vanilla selective capping algorithm over the received packet.
 * This function is used as a callback by pcap_loop, so it has no return value.
 *
 * @param args Additional arguments to be sent by the user.
 * @param header Generic per-packet information, as supplied by libpcap.
 * @param packet Packet to process.
 */
void selective_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

void *selective_capping_thread(void *args);
#endif