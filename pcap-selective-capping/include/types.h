#ifndef __TYPES__H__
#define __TYPES__H__

#include "headers.h"

/* =====================  Compatibility Definitions  ===================== */

#define _XOPEN_SOURCE 700
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;

/* =====================        Value  Macros        ===================== */
#define MIN_ASCII 0x20
#define MAX_ASCII 0x7D

#define TO_MS_VAL 0
#define SNAPLEN_SIZE 65535

#define false 0
#define true 1
#define PCAP_USEC 0xA1B2C3D4
#define PCAP_NSEC 0xA1B23C4D
#define KILOBIT 1024
#define MEGABIT (KILOBIT * 1024)
#define GIGABIT (MEGABIT * 1024)

#define VLAN_HLEN 4
#define UDP_HLEN 8
#define IP_HMINLEN 20
#define IP_HMAXLEN 60
#define TCP_HMINLEN 20
#define TCP_HMAXLEN 60

/** Minimum length of supported packet header, assuming 4 bytes for VLAN */
#define MIN_HLEN (ETH_HLEN + VLAN_HLEN + IP_HMINLEN + UDP_HLEN)

/** Maximum length of supported packet header, assuming 4 bytes for VLAN */
#define MAX_HLEN (ETH_HLEN + VLAN_HLEN + IP_HMAXLEN + TCP_HMAXLEN)

/* =====================       Function Macros       ===================== */

#define psem_init(x) pthread_mutex_init(&(x), NULL)
#define psem_destroy(x) pthread_mutex_destroy(&(x))
#define psem_down(x) pthread_mutex_lock(&(x))
#define psem_up(x) pthread_mutex_unlock(&(x))

#define speed_format(data, units)                                                    \
    units = (data > GIGABIT) ? 'G' : (data > MEGABIT) ? 'M'                          \
                                                      : 'K';                         \
    data = (data > GIGABIT) ? (data / GIGABIT) : (data > MEGABIT) ? (data / MEGABIT) \
                                                                  : (data / KILOBIT)
/**
 * @brief Set signal SIG_NO as the only element of the mask SIGMASK.
 */
#define set_mask(sigmask, sig_no) \
    sigemptyset(&sigmask);        \
    sigaddset(&sigmask, sig_no)

#define log_update(log, stored, capped, total) \
    pthread_mutex_lock(&(log->log_mutex));     \
    log->packets++;                            \
    log->stored_bytes += stored;               \
    log->captured_bytes += capped;             \
    log->total_bytes += total;                 \
    pthread_mutex_unlock(&(log->log_mutex))

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
#endif