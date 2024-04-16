#ifndef SPC_CUDA_H
#define SPC_CUDA_H

#include "headers.h"

/**
 * Different kinds of kernels that can be called for packet processing.
 */
enum kernel_type
{
    VANILLA_CAPPING_THREAD = 0,   /* Vanilla algorithm */
    OPTIMIZED_CAPPING_THREAD = 1, /* Optimized algorithm */
    NAIVE_CAPPING_WARP = 2,       /* Divides packet payload equally */
    INVASIVE_CAPPING_WARP = 3,    /* Extra runlen-1 bytes per naive thread */
    COERCIVE_CAPPING_WARP = 4     /* Simulates invasive threads with shmem */
};

/**
 * Launches a kernel to process an incoming packet burst from the received communication list.
 *
 * @param comm_list: Communication list containing the packet burst.
 * @param blocks: Number of blocks to launch in the kernel.
 * @param threads: Number of threads to launch per block.
 * @param stream: CUDA stream for concurrent kernel calls.
 * @param kargs: arguments sent to the kernel by value.
 */
void launch_kernel(struct rte_gpu_comm_list *comm_list, int blocks, int threads,
                   cudaStream_t stream, struct arguments args,
                   struct pcap_packet_header *headers);
#endif