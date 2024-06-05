#ifndef __CORES__H__
#define __CORES__H__

#include "headers.h"

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