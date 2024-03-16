#ifndef SPC_CUDA_H
#define SPC_CUDA_H

#include "headers.h"

/**
 * TODO document
 */
enum kernel_type
{
    VANILLA_CAPPING_THREAD = 0,   /* Vanilla algorithm */
    OPTIMIZED_CAPPING_THREAD = 1, /* Optimized algorithm */
    NAIVE_CAPPING_WARP = 2,       /* Divides packet payload equally */
    INVASIVE_CAPPING_WARP = 3,    /* Extra runlen-1 bytes per naive thread */
    COERCIVE_CAPPING_WARP = 4     /* Simulates invasive threads with shared mem */
};

/**
 * TODO document
 */
struct kernel_arguments
{
    unsigned short ascii_percentage;
    unsigned short ascii_runlen;
    unsigned short kernel;
};

/**
 * TODO document
 */
void launch_kernel(struct rte_gpu_comm_list *comm_list, int blocks, int threads, cudaStream_t stream, struct kernel_arguments kargs);
#endif