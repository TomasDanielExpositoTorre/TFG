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
#define TO_MS_VAL 10
#define PCAP_BUFSIZE 8192

typedef struct __LoggingInfo__
{
    pthread_mutex_t log_mutex;
    int stored_bytes;
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

#define log_write(log, stored, capped, total)   \
    pthread_mutex_lock(&(log->log_mutex));      \
    log->packets++;                             \
    log->stored_bytes += stored;                \
    log->captured_bytes += capped;              \
    log->total_bytes += total;                  \
    pthread_mutex_unlock(&(log->log_mutex))

#define log_init(log)        \
    log->packets = 0;        \
    log->captured_bytes = 0;    \
    log->stored_bytes = 0; \
    log->elapsed_time = 0

#define args_init(args, p, th) \
    args->percentage = p;      \
    args->threshold = th;      \
    args->interface = NULL

#define psem_init(x) pthread_mutex_init(&(x), NULL)
#define psem_destroy(x) pthread_mutex_destroy(&(x))
#define psem_down(x) pthread_mutex_lock(&(x))
#define psem_up(x) pthread_mutex_unlock(&(x))

/**
 * Prints average capture statistics through standard output.
 *
 * @param log Logging information.
 */
void capping_log(LoggingInfo *log);

/**
 * Callback function for pcap_loop. Applies selective capping over the received
 * packet.
 *
 * @details define __OPTIMIZED to use the optimized version of the algorithm.
 * @details define __SIMSTORAGE to skip packet dumping process.
 *
 * @param args Additional arguments to be sent by the user.
 * @param header Generic per-packet information, as supplied by libpcap.
 * @param packet Packet to process.
 */
void selective_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * Thread start routine for packet capture with libpcap. Applies selective
 * capping over the received packet.
 *
 * @param args ThreadArguments*.
 */
void *selective_capping_thread(void *args);
#endif