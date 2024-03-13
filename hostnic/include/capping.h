#ifndef SPC_CAPPING_H
#define SPC_CAPPING_H

#include "headers.h"

/* =====================       Logging  Struct       ===================== */

struct logging_info
{
    pthread_mutex_t log_mutex;
    unsigned int stored_bytes;
    unsigned int captured_bytes;
    unsigned int total_bytes;
    unsigned int packets;
    unsigned int elapsed_time;
};

#define log_update(log, stored, capped, total) \
    pthread_mutex_lock(&(log->log_mutex));     \
    log->packets++;                            \
    log->stored_bytes += stored;               \
    log->captured_bytes += capped;             \
    log->total_bytes += total;                 \
    pthread_mutex_unlock(&(log->log_mutex))

#define log_init(log)        \
    log->packets = 0;        \
    log->captured_bytes = 0; \
    log->stored_bytes = 0;   \
    log->elapsed_time = 0

/* =====================      Arguments  Struct      ===================== */

struct arguments
{
    struct logging_info log;
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    char *interface;
    char *output;
    pcap_dumper_t *file;
};

#define args_init(args, p, rl)  \
    args->ascii_percentage = p; \
    args->ascii_runlen = rl;    \
    args->interface = NULL;     \
    args->output = NULL

/* =====================       Threads  Struct       ===================== */

struct thread_arguments
{
    struct arguments args;
    pcap_t *handle;
    pthread_mutex_t read_mutex;
    pthread_mutex_t write_mutex;
    short signaled;
};

/* =====================    Function  Definitions    ===================== */

/**
 * Prints average capture statistics through standard output.
 *
 * @param log Logging information.
 */
void write_log(struct logging_info *log);

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
void spc_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * Thread start routine for packet capture with libpcap. Applies selective
 * capping over the received packet.
 *
 * @param args ThreadArguments*.
 */
void *spct_handler(void *args);

#endif