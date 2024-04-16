#ifndef SPC_PARSER_H
#define SPC_PARSER_H

#include "headers.h"


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
int rxcore(void *args);

/**
 * Handler function for a dumping thread. This function retrieves
 * packets from a processed burst list, and writes relevant data
 * to disk.
 *
 * @param args: Arguments required to manipulate a communication ring.
 */
int dxcore(void *args);

int pxcore(void *args);

/* =====================  Other  Functions  ===================== */


/**
 * Parsing function for received user arguments.
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

void mastercore_workload(std::vector<CommunicationRing*>& shmem, struct arguments args);

#endif