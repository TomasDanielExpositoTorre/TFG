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

/**
 * CPU reception lcore handler.
 * 
 * @param args: Communication Ring.
 */
int cpu_rx(void *args);

/**
 * CPU processing lcore handler. Applies vanilla capping over mbufs.
 * 
 * @param args: Communication Ring.
 */
int cpu_px(void *args);

/**
 * CPU processing lcore handler. Applies optimized capping over mbufs.
 * 
 * @param args: Communication Ring.
 */
int cpu_opx(void *args);

/**
 * CPU dumping lcore handler. 
 * 
 * @warning One core should be called for each open queue.
 * 
 * @param args: Communication Ring.
 */
int cpu_dx(void *args);

/**
 * CPU dumping lcore handler.
 * 
 * @warning Only one core should be called.
 * 
 * @param args: Communication Ring Vector.
 */
int cpu_ndx(void *args);

/**
 * SPU reception lcore handler.
 * 
 * @param args: Communication Ring.
 */
int spu_rx(void *args);

/**
 * SPU processing lcore handler. Applies vanilla capping over mbufs.
 * 
 * @param args: Communication Ring.
 */
int spu_px(void *args);

/**
 * SPU processing lcore handler. Applies optimized capping over mbufs.
 * 
 * @param args: Communication Ring.
 */
int spu_opx(void *args);

/**
 * SPU dumping lcore handler. 
 * 
 * @warning One core should be called for each open queue.
 * 
 * @param args: Communication Ring.
 */
int spu_dx(void *args);

/**
 * GPU reception lcore handler.
 * 
 * @param args: Communication Ring.
 */
int gpu_rx(void *args);

/**
 * GPU processing lcore handler. Applies vanilla capping over mbufs.
 * 
 * @param args: Communication Ring.
 */
int gpu_px(void *args);

/**
 * GPU processing lcore handler. Applies optimized capping over mbufs.
 * 
 * @param args: Communication Ring.
 */
int gpu_opx(void *args);

/**
 * GPU dumping lcore handler. 
 * 
 * @warning One core should be called for each open queue.
 * 
 * @param args: Communication Ring.
 */
int gpu_dx(void *args);

#endif