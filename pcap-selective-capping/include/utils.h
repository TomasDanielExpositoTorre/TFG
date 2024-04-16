#ifndef SPC_CAPPING_H
#define SPC_CAPPING_H

#include "headers.h"

/* =====================     Struct  Definitions     ===================== */
struct logging_info
{
    pthread_mutex_t log_mutex;
    long unsigned int stored_bytes;
    long unsigned int captured_bytes;
    long unsigned int total_bytes;
    long unsigned int packets;
    unsigned int elapsed_time;
};

struct arguments
{
    struct logging_info log;
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    char *interface;
    char *output;
    char *input;
    FILE *file;
};

struct thread_arguments
{
    struct arguments args;
    pcap_t *handle;
    pthread_mutex_t read_mutex;
    pthread_mutex_t write_mutex;
    short signaled;
};


#define log_update(log, stored, capped, total) \
    pthread_mutex_lock(&(log->log_mutex));     \
    log->packets++;                            \
    log->stored_bytes += stored;               \
    log->captured_bytes += capped;             \
    log->total_bytes += total;                 \
    pthread_mutex_unlock(&(log->log_mutex))

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