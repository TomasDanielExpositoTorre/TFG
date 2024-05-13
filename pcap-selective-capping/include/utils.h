#ifndef __UTILS__H__
#define __UTILS__H__

#include "headers.h"

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
void callback(unsigned char *uargs, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif