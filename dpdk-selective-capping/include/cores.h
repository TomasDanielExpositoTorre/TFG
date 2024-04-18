#ifndef __UTILS__H__
#define __UTILS__H__

#include "headers.h"

/* =====================    RPDX  Cores    ===================== */

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
int pxcore(void *args);

int opxcore(void *args);

/**
 * Handler function for a dumping thread. This function retrieves
 * packets from a processed burst list, and writes relevant data
 * to disk.
 *
 * @param args: Arguments required to manipulate a communication ring.
 */
int srxcore(void *args);

int spxcore(void *args);
int sopxcore(void *args);

int sdxcore(void *args);

void mastercore(std::vector<CommunicationRing *> &shmem, struct arguments args);

/* =====================  Other  Functions  ===================== */

/**
 * Parsing function for received user arguments.
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

#endif