#ifndef __CORES__H__
#define __CORES__H__

#include "headers.h"

// /**
//  * Handler function for a reception thread. This function receives
//  * and populates packets in bursts from a defined rx queue.
//  *
//  * @param args: Linear Communication Ring.
//  */
// int rxcore(void *args);


// /**
//  * Handler function for a processing thread. This function applies the
//  * selective capping algorithm over populated bursts.
//  *
//  * @param args: Linear Communication Ring.
//  */
// int pxcore(void *args);

// /**
//  * Handler function for a processing thread. This function applies the
//  * optimized capping algorithm over populated bursts.
//  *
//  * @param args: Linear Communication Ring.
//  */
// int opxcore(void *args);

// /**
//  * Handler function for a dumping thread. This function retrieves
//  * packets from a processed burst list, and writes relevant data
//  * to disk.
//  *
//  * @param args: Linear Communication Ring.
//  */
// int dxcore(void *args);

// /**
//  * Handler function for a reception thread. This function receives
//  * and populates packets in bursts from a defined rx queue.
//  * 
//  * @param args: Scheduled Communication Ring (SPU).
//  */
// int srxcore(void *args);

// /**
//  * Handler function for a processing thread. This function applies the
//  * selective capping algorithm over populated bursts.
//  *
//  * @param args: Scheduled Communication Ring (SPU).
//  */
// int spxcore(void *args);

// /**
//  * Handler function for a processing thread. This function applies the
//  * optimized capping algorithm over populated bursts.
//  *
//  * @param args: Scheduled Communication Ring (SPU).
//  */
// int sopxcore(void *args);

// /**
//  * Handler function for a dumping thread. This function retrieves
//  * packets from a processed burst list, and writes relevant data
//  * to disk.
//  *
//  * @param args: Scheduled Communication Ring (SPU).
//  */
// int sdxcore(void *args);

int cpu_rx(void *args);
int cpu_px(void *args);
int cpu_opx(void *args);
int cpu_dx(void *args);

int spu_rx(void *args);
int spu_px(void *args);
int spu_opx(void *args);
int spu_dx(void *args);

int gpu_rx(void *args);
int gpu_px(void *args);
int gpu_opx(void *args);
int gpu_dx(void *args);

#endif