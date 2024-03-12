#include "headers.h"

#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E

__global__ void vanilla_capping_thread(struct rte_gpu_comm_list *comm_list, kernel_args args)
{
    /**
     * Caculate header len,
     * Or assume ~80 bytes,
     * Or use a magic dpdk function to do it for me
     */
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    int consecutive = 0, total = 0, headerlen = 0;
    char *packet;

    if (i < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[i].addr);
        for (int j = headerlen; j < comm_list->pkt_list[i].size; j++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                consecutive++;
                total += 100;
                if (consecutive == args.ascii_runlen)
                    return; /* Do not cap */
            }
            else
                consecutive = 0;
        }

        if (total >= (args.ascii_percentage * comm_list->pkt_list[i].size))
            return; /* Do not cap */

        comm_list->pkt_list[i].size = headerlen; /* Cap when writing to CPU */
    }
}

__global__ void optimized_capping_thread(struct rte_gpu_comm_list *comm_list, kernel_args args)
{
    /**
     * Caculate header len,
     * Or assume ~80 bytes,
     * Or use a magic dpdk function to do it for me
     */
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    int consecutive = 0, total = 0, headerlen = 0, seen = 0;
    char *packet;

    if (i < comm_list->num_pkts)
    {
        /* Cap if payload is less than runlen */
        if (headerlen + args.ascii_runlen - 1 > comm_list->pkt_list[i].size)
        {
            comm_list->pkt_list[i].size = headerlen;
            return;
        }

        packet = (char *)(comm_list->pkt_list[i].addr);
        for (int j = headerlen + args.ascii_runlen - 1; j >= headerlen && j < comm_list->pkt_list[i].size; j--, seen++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                consecutive++;
                total += 100;
                if (consecutive == args.ascii_runlen)
                    return; /* Do not cap */
            }
            else
            {
                consecutive = 0;
                j += args.ascii_runlen + 1;
            }
        }

        if (total >= (args.ascii_percentage * seen))
            return; /* Do not cap */

        comm_list->pkt_list[i].size = headerlen; /* Cap when writing to CPU */
    }
}

__global__ void naive_capping_warp(struct rte_gpu_comm_list *comm_list, kernel_args args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    printf("%d\n", i);
}

__global__ void invasive_capping_warp(struct rte_gpu_comm_list *comm_list, kernel_args args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    printf("%d\n", i);
}

__global__ void coercive_capping_warp(struct rte_gpu_comm_list *comm_list, kernel_args args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    printf("%d\n", i);
}

void launch_kernel(struct rte_gpu_comm_list *comm_list, int blocks, int threads, cudaStream_t stream, kernel_args args)
{

    if (args.kernel == VANILLA_CAPPING_THREAD)
        vanilla_capping_thread<<<blocks, threads, 0, stream>>>(comm_list, args);
    else if (args.kernel == OPTIMIZED_CAPPING_THREAD)
        optimized_capping_thread<<<blocks, threads, 0, stream>>>(comm_list, args);
    else if (args.kernel == NAIVE_CAPPING_WARP)
        naive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
    else if (args.kernel == INVASIVE_CAPPING_WARP)
        invasive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
    else
        coercive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
}