#ifndef __SELCAP_H__
#define __SELCAP_H__

#include "types.h"
#include <string.h>

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
void selective_capping_optimized(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif