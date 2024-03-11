#include "headers.h"

/**
 * About capping...
 * Who should do it, the kernel (VERY divergent) or the transmission core?
 * Can we tell TX up to how many bytes we want to write?
 *  e.g. : 0 for not yet read, header_len for cap, -1 for whole packet on extmem
 *
 *
 * About filtering...
 * Who should handle it, the GPU or CPU?
 * Can we write a dpdk filter beforehand?
 */

__global__ void vanilla_capping_thread(struct rte_gpu_comm_list * comm_list, kernel_args args)
{
    printf("Hello Kernel!\n");
    /**
     * TODO
     *
     * for each packet in burst do
     *  i = header_len(packet)
     *  if i is unsupported do not write packet
     *  for byte in payload do
     *      if byte[i] is printable run++ total++
     *          if run == runlen DO NOT CAP
     *      else run = 0
     *
     *  if total >= percentage DO NOT CAP
     *  else CAP
     */
}

__global__ void optimized_capping_thread(struct rte_gpu_comm_list * comm_list, kernel_args args)
{
    printf("Hello Kernel!\n");
    /**
     * TODO
     *
     * for each packet in burst do
     *  i = header_len(packet)
     *  if i is unsupported do not write packet
     *  for byte in payload do
     *      if byte[i] is printable run++ total++
     *          if run == runlen DO NOT CAP
     *      else run = 0, i += runlen
     *
     *  if total >= percentage DO NOT CAP
     *  else CAP
     */
}

__global__ void naive_capping_warp(struct rte_gpu_comm_list * comm_list, kernel_args args)
{
    printf("Hello Kernel!\n");
}

__global__ void invasive_capping_warp(struct rte_gpu_comm_list * comm_list, kernel_args args)
{
    printf("Hello Kernel!\n");
}

__global__ void coercive_capping_warp(struct rte_gpu_comm_list * comm_list, kernel_args args)
{
    printf("Hello Kernel!\n");
}

void launch_kernel(struct rte_gpu_comm_list * comm_list, int blocks, int threads, cudaStream_t stream, kernel_args args)
{
    
    if (args.kernel == VANILLA_CAPPING_THREAD)
    {
        vanilla_capping_thread<<<blocks, threads, 0, stream>>>(comm_list, args);
    }
    else if (args.kernel == OPTIMIZED_CAPPING_THREAD)
    {
        optimized_capping_thread<<<blocks, threads, 0, stream>>>(comm_list, args);
        // opt_pkthread_kernel<<<1,1>>>();
    }
    else if (args.kernel == NAIVE_CAPPING_WARP)
    {
        naive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
        // naive_pktwarp_kernel<<<1,1>>>();
    }
    else if (args.kernel == INVASIVE_CAPPING_WARP)
    {
        invasive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
        // invasive_pktwarp_kernel<<<1,1>>>();
    }
    else
    {
        coercive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
        // coercive_pktwarp_kernel<<<1,1>>>();
    }
}