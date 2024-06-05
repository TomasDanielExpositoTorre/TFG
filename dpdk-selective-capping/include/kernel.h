#ifndef __KERNEL__H__
#define __KERNEL__H__

#include "headers.h"

/**
 * Different kinds of kernels that can be called for packet processing.
 */
enum kernel_type
{
    SELECTIVE_CAPPING = 0,  
    OPTIMIZED_CAPPING = 1,
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
                   cudaStream_t stream, int ascii_runlen, int ascii_percentage, int kernel,
                   struct pcap_packet_header *headers);
#endif