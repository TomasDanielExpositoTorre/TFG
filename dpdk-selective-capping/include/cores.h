#ifndef __CORES__H__
#define __CORES__H__

#include "headers.h"

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
 * Handler function for a processing thread. This function receives
 * packets in bursts from a defined reception queue, and populates
 * a communication list for GPU processing.
 *
 * Reception threads should also store statistics relative to the
 * received data: received packets, bytes...
 *
 * @param args: Arguments required to manipulate a communication ring.
 */
int pxcore(void *args);

/**
 * TODO COMPLETE
 */
int opxcore(void *args);

/**
 * TODO COMPLETE
 */
int srxcore(void *args);

/**
 * TODO COMPLETE
 */
int spxcore(void *args);

/**
 * TODO COMPLETE
 */
int sopxcore(void *args);

/**
 * TODO COMPLETE
 */
int sdxcore(void *args);

#endif